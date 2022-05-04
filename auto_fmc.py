from copy import deepcopy
from datetime import datetime
from ipaddress import IPv4Network, ip_network
from random import randint
from re import search, sub
import json
from logging_fmc import LogCollector
import pandas as pd
from fireREST import FMC
from netmiko import ConnectHandler
from tqdm import tqdm
from utilites import create_file_path,deprecated
from time import sleep

pd.options.display.max_columns = None
pd.options.display.max_rows = None
pd.options.mode.chained_assignment = None


class AugmentedWorker:

    def __init__(self, cred_file: str = None, fmc_host='', ftd_host='', domain='Global',
            ppsm_location='ppsm_test_file.csv', access_policy='test_acp', zbr_bypass: dict = None,rule_prepend_name='firewall',zone_of_last_resort='outside',same_cred=True):
        """
        @param cred_file: JSON file hosting user/pass information DEPRECATED
        @param fmc_host: FMC domain or IP address
        @param ftd_host: FTD domain or IP address
        @param domain: used to select the tenant in FMC
        @param ppsm_location: location of rules to stage on FMC
        @param access_policy: which ACP to stage the rules onto
        @param zbr_bypass: (experimental) if you want to manually assign the security zone to rules instead of doing the zone to IP lookup make sure the zone and rules rows match exactly!
        @param rule_prepend_name: an additive on what to call the staged rule. ie a rule will look like facetime_rule_allow_facetime_5324
        where facetime_rule is the prepend var, allow_facetime is the comment and number is unique set of characters to distinguish the rule
        @@param zone_of_last_resort: this is needed when we dont know where a route lives relative to their Zone ie we know that a IP is northbound of our gateway or outside interface.
        @@param same_cred: whether all creds to login devices use the same user and password combination
        """
        creds = self.get_device_creds(cred_file=cred_file,same_cred=same_cred)
        # Sec-lint #1
        for v in list(creds.values()):
            if not isinstance(v,(str,int,float)):
                raise ValueError(f'Cred file has a value that is not allowed for this script. returned value of {type(v)}')
        self.fmc_host = fmc_host
        self.ftd_host = ftd_host
        self.fmc_username = creds['fmc_username']
        self.fmc_password = creds['fmc_password']
        self.ftd_username = creds['ftd_username']
        self.ftd_password = creds['ftd_password']
        self.domain = domain
        # this is just a check the file MUST be the folder
        self.ppsm_location = create_file_path('ingestion',ppsm_location)
        self.access_policy = access_policy
        self.zbr_bypass = zbr_bypass
        self.rule_prepend_name = rule_prepend_name
        self.zone_of_last_resort = zone_of_last_resort
        self.logfmc = LogCollector()

    def _creation_check(self,response, new_obj, output=True):
        if response.status_code != 201:
            raise Exception(f'received back status code:{response.status_code}')
        else:
            if output:
                self.logfmc.logger.warning(f'new obj {new_obj} created ')

    def rest_connection(self,reset=False):
        if reset:
            self.fmc.conn.refresh()
        else:
            self.fmc = FMC(hostname=self.fmc_host, username=self.fmc_username, password=self.fmc_password, domain=self.domain)

    def fmc_net_port_info(self):
        net_objects = self.fmc.object.network.get()
        host_objects = self.fmc.object.host.get()
        port_objects = self.fmc.object.port.get()
        net_group_object = self.fmc.object.networkgroup.get()
        port_group_object = self.fmc.object.portobjectgroup.get()

        def get_name_from_group_object(object_name:list,obj_type='net'):
            if isinstance(object_name,list):
                if obj_type == 'net':
                    return [i['name'] for i in object_name]
                else:
                    return [[str(i.get('name')), str(i.get('protocol')), str(i.get('port'))] for i in object_name]
            # if a single is returned
            return x['name']

        self.net_group_object = []
        for x in net_group_object:
            try:
                self.net_group_object.append(tuple([str(x['name']), get_name_from_group_object(x.get('objects')),str(x['id'])]))
            except:
                self.net_group_object.append(tuple([str(x['name']), get_name_from_group_object(x.get('literals')),str(x['id'])]))

        self.net_data = [tuple([str(x['name']), str(x['value']),str(x['id'])]) for x in net_objects] + [tuple([str(x['name']), str(x['value']),str(x['id'])]) for x in host_objects]
        self.port_data = [tuple([str(x.get('name')), str(x.get('protocol')), str(x.get('port')),str(x['id']), str(x['type'])]) for x in port_objects]
        self.port_group_object = [tuple([str(x['name']), get_name_from_group_object(x.get('objects'),obj_type='port'),str(x['id'])]) for x in port_group_object]

    @staticmethod
    def _ip_address_check(x):
        # check if user entered a hot bits in thier subnet mask
        x = x.strip()
        try:
            if not 'any' in x:
                # has to strick check so we can properly identifty if its a subnet or mistyped single IP.
                return str(ip_network(x))
            else:
                return x
        except:
            return x.split('/')[0]

    def retrieve_ppsm(self):
        ppsm = pd.read_csv(self.ppsm_location)
        ppsm = ppsm.astype(str)
        ppsm = ppsm[ppsm['source'] != 'nan']
        for origin in ['source', 'destination']:
            # check if user entered a hot bits in thier subnet mask
            ppsm[origin] = ppsm[origin].apply(lambda x: str(self._ip_address_check(x)))
            # fix so we dont have to refactor a bullion lines
            ppsm[origin] = ppsm[origin].apply(lambda x: (x.split('/')[0]).strip() if '/32' in x else x.strip())
        # strip extra spaces in cols
        for col in ppsm.columns:
            ppsm[col] = ppsm[col].apply(lambda x: x.strip())
        # check if we have acceptable protocol for the API
        na_protos = ppsm[~ppsm['protocol'].str.contains('TCP|UDP',regex=True)]
        dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d%H%M%S")
        fpath = create_file_path('CNI',f'non_applicable_protocols_{dt_now}.csv')
        if not na_protos.empty:
            self.logfmc.logger.warning(f'found protocols that cannot be used with this script\n Please enter them manually\n file location: {fpath}')
            # make sure the user sees the msg with no input.
            sleep(2)
            na_protos.to_csv(fpath,index=False)
        ppsm = ppsm[ppsm['protocol'].str.contains('TCP|UDP',regex=True)]
        # remove non-alphanumeric chars from str if protocol take udp or tcp from str
        for col in ['service','protocol']:
            ppsm[col] = ppsm[col].apply(lambda x: sub('[^0-9a-zA-Z]+', '_', x))
            if col == 'protocol':
                ppsm[col] = ppsm[col].apply(lambda x: [i.split()[0] for i in x.split('_') if i == 'TCP' or i == 'UDP'][0])
        return ppsm

    def create_fmc_object_names(self, keep_old_name=True):
        # drop trailing decimal point from str conversion
        self.ppsm['port_1'] = self.ppsm['port_1'].apply(lambda x: x.split('.')[0])
        self.ppsm['port_2'] = self.ppsm['port_2'].apply(lambda x: x.split('.')[0])
        # take care range ports
        self.ppsm['port'] = 0

        for i in self.ppsm.index:
            # catch any any clause
            if self.ppsm['port_1'][i] in ['nan', '0', '65535', 'any'] and self.ppsm['port_2'][i] in ['nan', '0', '65535', 'any']:
                self.ppsm['port_2'][i] = self.ppsm['port_1'][i] = 'any'
            elif self.ppsm['port_2'][i] in ['nan', '0', '65535', 'any'] and self.ppsm['port_1'][i] in ['nan', '0', '65535', 'any']:
                self.ppsm['port_2'][i] = self.ppsm['port_1'][i] = self.ppsm['port_2'][i] = 'any'
            # if the rows has nothing in the adjacent col copy from the other row. (this avoids nan bug)
            if self.ppsm['port_2'][i] in ['nan']:
                self.ppsm['port_2'][i] = self.ppsm['port_1'][i]
            elif self.ppsm['port_1'][i] in ['nan']:
                self.ppsm['port_1'][i] = self.ppsm['port_2'][i]
            # if port is a range append range symbol
            if self.ppsm['port_1'][i] != self.ppsm['port_2'][i]:
                self.ppsm['port'].loc[i] = self.ppsm['port_1'][i] + '-' + self.ppsm['port_2'][i]
            else:
                self.ppsm['port'].loc[i] = self.ppsm['port_1'][i]
        # take care of the random chars in protocol col ( we can only use TCP/UDP for its endpoint soo..
        self.ppsm['protocol'] = self.ppsm['protocol'].astype(str).apply(lambda x: x.strip()[:3])
        self.ppsm.drop(columns=['port_1', 'port_2'], inplace=True)

        for type_ in tqdm(['source', 'destination', 'port'], desc=f'creating new objects or checking if it exist.', total=3, colour='MAGENTA'):
            # whether we need to create an obj placeholder
            self.ppsm[f'fmc_name_{type_}_install'] = True
            self.ppsm[f'fmc_name_{type_}'] = 'None'
            if type_ != 'port':
                for name_ip in self.net_data:
                    # if ip is found in FMC store that info in a df
                    if not self.ppsm[self.ppsm[type_] == name_ip[1]].empty:
                        self.ppsm[f'fmc_name_{type_}'].loc[self.ppsm[type_] == name_ip[1]] = name_ip[0]
                        self.ppsm[f'fmc_name_{type_}_install'].loc[self.ppsm[type_] == name_ip[1]] = False
            else:
                # check if port data already exist on fmc
                for port_info in self.port_data:
                    port_protco = self.ppsm[(self.ppsm[type_] == port_info[2]) & (self.ppsm['protocol'] == port_info[1])]
                    if not port_protco.empty:
                        self.ppsm[f'fmc_name_{type_}'].loc[(self.ppsm[type_] == port_info[2]) & (self.ppsm['protocol'] == port_info[1])] = port_info[0]
                        self.ppsm[f'fmc_name_{type_}_install'].loc[(self.ppsm[type_] == port_info[2]) & (self.ppsm['protocol'] == port_info[1])] = False

            # group the common IPs and ports into unique and push all objects in bulk
            install_pd = self.ppsm[self.ppsm[f'fmc_name_{type_}_install'] == True]
            install_pd = install_pd[install_pd[type_] != 'any']
            if type_ in ['source','destination']:
                self.fmc_net_port_info()
                install_pd[f'fmc_name_{type_}'] = install_pd[type_].apply(lambda net: f'{net.split("/")[0]}_{net.split("/")[1]}' if '/' in net else net)
                if not self.ppsm[type_][(self.ppsm[f'fmc_name_{type_}_install'] == True) & (self.ppsm[type_] != 'any')].empty:
                    self.ppsm[f'fmc_name_{type_}'] = self.ppsm[type_][(self.ppsm[f'fmc_name_{type_}_install'] == True) & (self.ppsm[type_] != 'any')].apply(lambda net: f'{net.split("/")[0]}_{net.split("/")[1]}' if '/' in net else net)
                net_data = [nd[0] for nd in self.net_data]
                net_list = list(set([net for net in install_pd[f'fmc_name_{type_}'] if '_' in net]))
                net_list = [{'name': net, 'value': net.replace('_','/')} for net in net_list if net not in net_data]

                host_list = list(set([host for host in install_pd[f'fmc_name_{type_}'] if not '_' in host]))
                host_list = [{'name': host, 'value': host} for host in host_list if host not in net_data]
                try:
                    self.fmc.object.network.create(data=net_list)
                except Exception as error:
                    self.logfmc.logger.debug(error)

                try:
                    self.fmc.object.host.create(data=host_list)
                except Exception as error:
                    self.logfmc.logger.debug(error)
            else:
                if not install_pd.empty:
                    group_port = install_pd.groupby(['port','protocol'])
                    gpl = group_port.size()[group_port.size() > 0].index.values.tolist()
                    for i in gpl:
                        i = group_port.get_group(i)
                        i = i.iloc[0]
                        ipd = install_pd['service'][(install_pd['port'] == i['port']) & (install_pd['protocol'] == i['protocol'])]
                        spipd = self.ppsm['service'][(self.ppsm['port'] == i['port']) & (self.ppsm['protocol'] == i['protocol'])]
                        install_pd[f'fmc_name_{type_}'][ipd.index.tolist()] = ipd.iloc[0]
                        self.ppsm[f'fmc_name_{type_}'][spipd.index.tolist()] = spipd.iloc[0]

                    port_data = [po[0] for po in self.port_data]
                    install_pd[f'fmc_name_{type_}'] = install_pd[f'fmc_name_{type_}'].apply(lambda port: port.replace(" ","-"))
                    self.ppsm[f'fmc_name_{type_}'] = self.ppsm[f'fmc_name_{type_}'].apply(lambda port: port.replace(" ","-"))

                    port_list = list(set([port for port in install_pd[f'fmc_name_{type_}'] if port not in port_data]))
                    port_list = [{'name': port, "protocol": install_pd['protocol'][install_pd[f'fmc_name_{type_}'] == port].iloc[0], 'port': install_pd['port'][install_pd[f'fmc_name_{type_}'] == port].iloc[0]} for port in port_list]
                    try:
                        self.fmc.object.protocolportobject.create(data=port_list)
                    except Exception as error:
                        self.logfmc.logger.debug(error)

    def zone_to_ip_information(self):
        route_zone_info = []
        ipv4_re = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        ftd_info = {
            'device_type': 'cisco_ftd_ssh', 'host': self.ftd_host,
            'username': self.ftd_username, 'password': self.ftd_password
        }

        command = "show asp table routing input"
        command_2 = 'show running-config | include nameif'
        with ConnectHandler(**ftd_info) as net_connect:
            asp_output = net_connect.send_command(command)

        with ConnectHandler(**ftd_info) as net_connect:
            nameif_output = net_connect.send_command(command_2)

        nameif_output = [zone_name.strip().replace('nameif', '').strip() for zone_name in nameif_output.split('\n') if zone_name.startswith(' nameif')]

        asp_output = [route_zone[3:].split() for route_zone in asp_output.split('\n') if route_zone.startswith('in')]
        for fix_pos in asp_output:
            if len(fix_pos) >= 3:
                zone_info = [i for i in nameif_output if i in fix_pos]
                if len(zone_info) >= 1:
                    route_zone_info.append(fix_pos[0:2] + zone_info)

        route_zone_info = pd.DataFrame(route_zone_info, columns=['IP', 'MASK', 'ZONE'])
        route_zone_info = route_zone_info[~route_zone_info['ZONE'].str.contains('nlp.*tap')]
        route_zone_info['CIDR'] = route_zone_info['MASK'].apply(lambda ip: IPv4Network(f'0.0.0.0/{ip}').prefixlen if search(ipv4_re, ip) else ip)
        route_zone_info = route_zone_info[route_zone_info['CIDR'].astype(str).str.isdigit()]
        route_zone_info = route_zone_info[route_zone_info['ZONE'].astype(str) != 'identity']
        return route_zone_info

    def find_nested_group_objects(self, object_item):
        try:
            object_item = object_item.get('objects')
            if not isinstance(object_item, list):
                return object_item
            item_holder = []
            for obj_info in object_item:
                if 'group' not in obj_info.get('type').lower():
                    item_holder.append(obj_info.get('name'))
                elif 'group' in obj_info.get('type').lower():
                    if 'port' not in obj_info.get('type').lower():
                        for i in self.net_group_object:
                            if i[0] == obj_info['name']:
                                for v in i[1]:
                                    for ip in self.net_data:
                                        if v == ip[0]:
                                            item_holder.append(ip[0])
                    else:
                        for i in self.port_group_object:
                            if obj_info.get('name') == i[0]:
                                for v in i[1]:
                                    for ports in self.port_data:
                                        if v[0] == ports[0]:
                                            item_holder.append(ports[0])
            if len(item_holder) == 1:
                return item_holder[0]
            sorted(item_holder)
            return item_holder
        except Exception as error:
            self.logfmc.logger.debug(error)
            return None

    def find_dup_policies(self, ruleset, acp_set):
        def flatten(d):
            out = {}
            for key, val in d.items():
                if isinstance(val, dict):
                    val = [val]
                if isinstance(val, list):
                    for subdict in val:
                        deeper = flatten(subdict).items()
                        out.update({key + '_' + key2: val2 for key2, val2 in deeper})
                else:
                    out[key] = val
            return out

        def fdp_grouper(p,type_):
            if type_ == 'ip':
                if not isinstance(p, list):
                    for ipx in self.net_data:
                        if p == ipx[0]:
                            return ipx[1]
                else:
                    return sorted(list(set(ipx[1] for ruleip in p for ipx in self.net_data if ruleip == ipx[0])))
            if type_ == 'port':
                if not isinstance(p, list):
                    for px in self.port_data:
                        if p == px[0]:
                            return f"{px[1]}:{px[2]}"
                else:
                    return sorted(list(set(f"{px[1]}:{px[2]}" for rulep in p for px in self.port_data if rulep == px[0])))

        # find existing policy in fmc
        current_ruleset = self.fmc.policy.accesspolicy.accessrule.get(container_uuid=acp_set['id'])
        changed_ruleset = []
        for i in current_ruleset:
            subset_rule = {}
            subset_rule['src_z'] = self.find_nested_group_objects(i.get('sourceZones'))
            subset_rule['dst_z'] = self.find_nested_group_objects(i.get('destinationZones'))
            subset_rule['source'] = self.find_nested_group_objects(i.get('sourceNetworks'))
            subset_rule['destination'] = self.find_nested_group_objects(i.get('destinationNetworks'))
            subset_rule['port'] = self.find_nested_group_objects(i.get('destinationPorts'))
            changed_ruleset.append(subset_rule)
        current_ruleset = changed_ruleset
        current_ruleset = pd.DataFrame(current_ruleset)
        if len(current_ruleset) < 1:
            self.logfmc.logger.error('nothing in current ruleset')
            return ruleset

        self.logfmc.logger.warning("getting real IPs from named network objects")
        for ip in ['source', 'destination']:
            current_ruleset[f'real_{ip}'] = current_ruleset[ip].apply(lambda p: fdp_grouper(p, 'ip'))
            ruleset[f'real_{ip}'] = ruleset[f'{ip}_network'].apply(lambda p: fdp_grouper(p, 'ip'))

        self.logfmc.logger.warning("getting real ports-protocols from named port objects")
        current_ruleset['real_port'] = current_ruleset['port'].apply(lambda p: fdp_grouper(p,'port'))
        ruleset['real_port'] = ruleset['port'].apply(lambda p: fdp_grouper(p,'port'))

        # remove nan values with any
        current_ruleset.fillna(value='any',inplace=True)
        ruleset.fillna(value='any',inplace=True)
        current_ruleset.replace({'None':'any'},inplace=True)

        # make sure we are matching by list type and sorting correctly even if its a list object
        for col in ruleset.columns:
            ruleset[col] = ruleset[col].apply(lambda x: sorted(list(v for v in x)) if isinstance(x, (tuple,list)) else x)
        for col in current_ruleset.columns:
            current_ruleset[col] = current_ruleset[col].apply(lambda x: sorted(list(v for v in x)) if isinstance(x, (tuple,list)) else x)

        # remove rules that are dups
        idx_collector = []
        for i in tqdm(current_ruleset.index, desc='Comparing old ruleset objects to new ones', total=len(current_ruleset.index), colour='yellow'):
            for idx in ruleset.index:
                # bug fix for None(any) zone values slipping matching
                cur_src_z = current_ruleset['src_z'][i] if current_ruleset['src_z'][i] != 'None' else 'any'
                cur_dst_z = current_ruleset['dst_z'][i] if current_ruleset['dst_z'][i] != 'None' else 'any'

                cur_src_z = cur_src_z.split('|') if '|' in cur_src_z else cur_src_z
                cur_dst_z = cur_dst_z.split('|') if '|' in cur_dst_z else cur_dst_z

                # get nested objects
                cur_real_dst_ip = current_ruleset['real_destination'][i].split('|') if '|' in current_ruleset['real_destination'][i] else current_ruleset['real_destination'][i]
                cur_real_src_ip = current_ruleset['real_source'][i].split('|') if '|' in current_ruleset['real_source'][i] else current_ruleset['real_source'][i]
                cur_real_port_ip = current_ruleset['real_port'][i].split('|') if '|' in current_ruleset['real_port'][i] else current_ruleset['real_port'][i]

                rs_real_dst_ip = ruleset['real_destination'][idx].split('|') if '|' in ruleset['real_destination'][idx] else ruleset['real_destination'][idx]
                rs_real_src_ip = ruleset['real_source'][idx].split('|') if '|' in ruleset['real_source'][idx] else ruleset['real_source'][idx]
                rs_real_port_ip = ruleset['real_port'][idx].split('|') if '|' in ruleset['real_port'][idx] else ruleset['real_port'][idx]
                # counter if rule exist
                quondam = 0
                # ip dest
                if isinstance(cur_real_dst_ip, list):
                    sorted(cur_real_dst_ip)
                    if isinstance(rs_real_dst_ip, list):
                        sorted(rs_real_dst_ip)
                        if cur_real_dst_ip == rs_real_dst_ip:
                            quondam += 1
                    elif rs_real_dst_ip in cur_real_dst_ip:
                        quondam += 1
                elif rs_real_dst_ip == cur_real_dst_ip:
                    quondam += 1
                # ip src
                if isinstance(cur_real_src_ip, list):
                    sorted(cur_real_dst_ip)
                    if isinstance(rs_real_src_ip, list):
                        sorted(rs_real_src_ip)
                        if cur_real_src_ip == rs_real_src_ip:
                            quondam += 1
                    elif rs_real_src_ip in cur_real_src_ip:
                        quondam += 1
                elif rs_real_src_ip == cur_real_src_ip:
                    quondam += 1
                # port
                if isinstance(cur_real_port_ip, list):
                    sorted(cur_real_port_ip)
                    if isinstance(rs_real_port_ip, list):
                        sorted(rs_real_port_ip)
                        if cur_real_port_ip == rs_real_port_ip:
                            quondam += 1
                    elif rs_real_port_ip in cur_real_port_ip:
                        quondam += 1
                elif rs_real_port_ip == cur_real_port_ip:
                    quondam += 1
                # zone
                if ruleset['source_zone'][idx] == cur_src_z and ruleset['destination_zone'][idx] == cur_dst_z:
                    quondam += 1

                if quondam >= 4:
                    idx_collector.append(idx)

        idx_collector = list(set(idx_collector))
        try:
            ruleset.drop(idx_collector, inplace=True)
            ruleset.reset_index(inplace=True,drop=True)
            self.logfmc.logger.warning(f"{'#' * 3}DROP {len(idx_collector)} DUP RULES{'#' * 3}")
        except:
            # no dups to drop
            pass
        return ruleset

    def _get_sn_match(self, type_, i):
        if self.ppsm[type_][i] == 'any':
            return {f"{type_}_zone": 'any', f'{type_}_network': 'any'}
        elif self.zbr_bypass is not None:
            # index of bypass MUST match ppsm index
            return {f"{type_}_zone": str(self.zbr_bypass[type_][i]), f'{type_}_network': self.ppsm[f'fmc_name_{type_}'][i]}

        ppsm_subnet = ip_network(self.ppsm[type_][i])
        # if we need to find where a host address lives exactly
        if '/' not in self.ppsm[type_][i] or '/32' in self.ppsm[type_][i]:
            for p in self.zone_ip_info.index:
                asp_subnet = self.zone_ip_info['ip_cidr'][p]
                if ppsm_subnet.subnet_of(ip_network(asp_subnet)):
                    return {f"{type_}_zone": self.zone_ip_info['ZONE'][p], f'{type_}_network': self.ppsm[f'fmc_name_{type_}'][i]}
        # if we need to find all zones a subnet might reside
        elif '/' in self.ppsm[type_][i]:
            zone_group = tuple(list(set([self.zone_ip_info['ZONE'][p] for p in self.zone_ip_info.index if ip_network(self.zone_ip_info['ip_cidr'][p]).subnet_of(ppsm_subnet)])))
            if len(zone_group) != 0:
                zone_group = zone_group if len(zone_group) > 1 else zone_group[0]
                return {f"{type_}_zone": zone_group, f'{type_}_network': self.ppsm[f'fmc_name_{type_}'][i]}
        # if we dont know where this zone is coming it must be from external
        return {f"{type_}_zone": self.zone_of_last_resort, f'{type_}_network': self.ppsm[f'fmc_name_{type_}'][i]}

    def del_fmc_objects(self,obj_tup,type_,obj_type):
        try:
            if type_ == 'network':
                if obj_type == 'net':
                    if '/' in obj_tup[1]:
                        self.fmc.object.network.delete(obj_tup[2])
                    else:
                        self.fmc.object.host.delete(obj_tup[2])
                elif obj_type == 'net_group':
                    self.fmc.object.networkgroup.delete(obj_tup[-1])
            elif type_ == 'port':
                if obj_type == 'port':
                    self.fmc.object.protocolportobject.delete(obj_tup[3])
                elif obj_type == 'port_group':
                    self.fmc.object.portobjectgroup.delete(obj_tup[-1])
        except Exception as error:
            self.logfmc.logger.error(f'Cannot delete {obj_tup} of {type_} \n received code: {error}')

    def create_acp_rule(self):
        ruleset = []

        def fix_object(x):
            try:
                x = x[0]
            except:
                x = x
            return [{'name': x['name'], 'id': x['id'], 'type': x['type']}]

        if self.zbr_bypass is None:
            self.zone_ip_info['ip_cidr'] = self.zone_ip_info['IP'].astype(str) + '/' + self.zone_ip_info['CIDR'].astype(str)
            # sort df by subnet size to find the closet match first
            self.zone_ip_info.sort_values(by='ip_cidr', key=lambda x: x.apply(lambda y: ip_network(y)), ascending=False, inplace=True)
        else:
            # if we are not doing zone-ip lookup based rule creation then the zone must be loaded from init
            if not isinstance(self.zbr_bypass, dict):
                raise TypeError(f'zbr_bypass is a {type(self.zbr_bypass)} object not dict')

        # sort rules in a pretty format
        for i in self.ppsm.index:
            rule_flow = {}
            src_flow = self._get_sn_match('source', i)
            dst_flow = self._get_sn_match('destination', i)
            # block double zone
            if src_flow["source_zone"] == dst_flow["destination_zone"]:
                continue
            rule_flow.update(src_flow)
            rule_flow.update(dst_flow)
            rule_flow.update({'port': self.ppsm['fmc_name_port'][i] if self.ppsm['port'][i] != 'any' else 'any'})
            rule_flow.update({'comment': self.ppsm['ticket_id'][i]})
            ruleset.append(rule_flow)

        ruleset = pd.DataFrame(ruleset)
        # if there all the same zone then we got nothing to find dups of
        if ruleset.empty:
            raise Exception('NOTHING IN RULESET THEY MIGHT ALL BE THE SAME ZONE')
        acp_set = self.fmc.policy.accesspolicy.get(name=self.access_policy)
        ruleset = self.find_dup_policies(ruleset, acp_set)

        # if we removed all the dups and we have no new rules or for some reason we dont have rules to deploy raise to stop the program
        try:
            for col in ruleset.columns:
                ruleset[col] = ruleset[col].apply(lambda x: tuple(v for v in x) if isinstance(x, list) else x)
            ruleset.drop_duplicates(ignore_index=True, inplace=True)
            if ruleset.empty:
                raise Exception('NO RULES TO DEPLOY')
        except Exception as error:
            raise Exception(error)

        # group by most distinct features
        case1 = ruleset.groupby(['source_network', 'port'])
        case2 = ruleset.groupby(['destination_network', 'port'])
        case3 = ruleset.groupby(['destination_zone','source_zone','port'])

        ruleset_holder = []
        dup_holder = []
        for grouped_df, type_net in zip([case1, case2, case3], ['source', 'destination','zone']):
            group_listing = grouped_df.size()[grouped_df.size() > 1].index.values.tolist()
            for gl in group_listing:
                concat_cols_type = 'destination' if type_net == 'source' else 'source'
                concat_cols_type = 'port' if type_net == 'port' else concat_cols_type
                group = grouped_df.get_group(gl)
                # get idx dups of the main ruleset to remove
                dup_holder += group.index.to_list()
                if type_net == 'source' or type_net == 'destination':
                    cct_net = f'{concat_cols_type}_network'
                    cct_zone = f'{concat_cols_type}_zone'
                    cct_net_data = list(set(group[cct_net].to_list()))
                    cct_zone_data = list(set(group[cct_zone].to_list()))
                    group = group.iloc[0]
                    if len(cct_net_data) == 1:
                        group[cct_net] = cct_net_data[0]
                    else:
                        group[cct_net] = sorted(cct_net_data)
                    if len(cct_zone_data) == 1:
                        group[cct_zone] = cct_zone_data[0]
                    else:
                        try:
                            group[cct_zone] = sorted(cct_zone_data)
                        except:
                            # needed due to [(many zones),zone,zone] problem
                            all_zones = []
                            for pull_all in cct_zone_data:
                                if isinstance(pull_all,tuple):
                                    for i in pull_all:
                                        all_zones.append(i)
                                else:
                                    all_zones.append(pull_all)
                            group[cct_zone] = sorted(all_zones)

                elif type_net == 'zone':
                    agg_src_net = sorted(list(set(group['source_network'].tolist())))
                    agg_dst_net = sorted(list(set(group['destination_network'].tolist())))
                    # fit the agg lists into one cell since we captured the all the other info
                    group = group.iloc[0]
                    # dont take list items if the list only has 1 element
                    group['source_network'] = agg_src_net if len(agg_src_net) > 1 else agg_src_net[0]
                    group['destination_network'] = agg_dst_net if len(agg_dst_net) > 1 else agg_dst_net[0]
                # dup policy check
                dup_seen = False
                for rule_group in ruleset_holder:
                    if group.to_dict() == rule_group:
                        dup_seen = True
                        break
                if not dup_seen:
                    ruleset_holder.append(group.to_dict())

        ruleset.drop(ruleset.index[dup_holder], inplace=True)
        ruleset = pd.concat([pd.DataFrame(ruleset_holder), ruleset], ignore_index=True)
        ruleset.reset_index(inplace=True, drop=True)

        # convert to tup for search
        for col in ruleset.columns:
            ruleset[col] = ruleset[col].apply(lambda x: tuple(v for v in x) if isinstance(x, list) else x)

        # group ports separately
        ruleset_holder = []
        dup_holder = []
        case4 = ruleset.groupby(['destination_network', 'source_network'])
        c4_listing = case4.size()[case4.size() > 1].index.values.tolist()
        for gl in c4_listing:
            group = case4.get_group(gl)
            # get idx dups of the main ruleset to remove
            dup_holder += group.index.to_list()
            cct_port_data = list(set(group['port'].to_list()))
            group = group.iloc[0]
            if len(cct_port_data) == 1:
                group['port'] = cct_port_data[0]
            else:
                group['port'] = sorted(cct_port_data)
                # dup policy check
            dup_seen = False
            for rule_group in ruleset_holder:
                if group.to_dict() == rule_group:
                    dup_seen = True
                    break
            if not dup_seen:
                ruleset_holder.append(group.to_dict())
        ruleset.drop(ruleset.index[dup_holder], inplace=True)
        ruleset = pd.concat([pd.DataFrame(ruleset_holder), ruleset], ignore_index=True)
        ruleset.reset_index(inplace=True, drop=True)

        # remove tuples from multi-zoned rows
        for col in ruleset.columns:
            ruleset[col] = ruleset[col].apply(lambda x: list(v for v in x) if isinstance(x, tuple) else x)

        # since we grouped policy find the dups again and get rid of em
        ruleset = self.find_dup_policies(ruleset, acp_set)
        if ruleset.empty:
            raise Exception('NO RULES TO DEPLOY')

        # real cols are for function lookup use
        ruleset = ruleset.loc[:, ~ruleset.columns.str.startswith('real')]

        dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d%H%M%S")
        ruleset_loc = create_file_path('predeploy_rules', f"fmc_ruleset_preload_configs_{dt_now}.csv", )
        ruleset.to_csv(ruleset_loc, index=False)
        warn_msg = f'REVIEW PREDEPLOY RULESET FILE located at {ruleset_loc}. ENTER "c" TO CONTINUE'
        while True:
            self.logfmc.logger.warning(warn_msg)
            user_input = input()
            if user_input.lower() == 'c':
                break

        temp_form = {"action": "ALLOW", "enabled": 'true', "type": "AccessRule",
            "name": "Rule2", "sendEventsToFMC": 'true', "enableSyslog": 'true',
            "logFiles": 'false', "logBegin": 'false', "logEnd": 'true'}

        # get all zone info
        all_zones = {fix_object(i)[0]['name']:fix_object(i)[0] for i in self.fmc.object.securityzone.get()}
        # create a bulk policy push operation
        charity_policy = []
        for i in tqdm(ruleset.index, desc='Loading bulk rule collection artifacts', total=len(ruleset.index), colour='green'):
            rule = ruleset.loc[i].to_dict()
            dh = {}
            for k,v in rule.items():
                if isinstance(v,str):
                    # everything was converted to str for comparison in dup func so convert list obj back
                    if '[' in v:
                        v = json.loads(v.replace("'", '"'))
                if isinstance(v,list):
                    # dont need create objs for zones or any ips,zone
                    if 'zone' in k or 'any' in v:
                        if 'any' in v:
                            # any is coming as list so lets strip it just in case this is due to how the policy lookup occurred
                            v = 'any'
                    else:
                        sleep(5)
                        # get new port/net info per iteration so we dont create dup objects that have the same child IDs on creation if needed
                        self.fmc_net_port_info()
                        # the inner break controls the for-loop and need a mechanism to break IF we matched on already created group
                        matched = False
                        while not matched:
                            if 'destination' in k or 'source' in k:
                                # if this object exists already use it
                                for ip_lists in self.net_group_object:
                                    if sorted(ip_lists[1]) == sorted(v):
                                        v = ip_lists[0]
                                        matched = True
                                        break
                                if not matched:
                                    # create group net or port objs by IDs since fmc cant create rules with more than 50 objects
                                    create_group_obj = {'objects': [{'type': name_ip_id[1], 'id': name_ip_id[2]} for ip in v for name_ip_id in self.net_data if ip == name_ip_id[0]], 'name': f"{self.rule_prepend_name}_net_group_{randint(1, 100)}"}
                                    try:
                                        if len(create_group_obj['objects']) > 1:
                                            response = self.fmc.object.networkgroup.create(create_group_obj)
                                            if 'already exists' not in str(response):
                                                self._creation_check(response, create_group_obj['name'], output=False)
                                        matched = True
                                        v = create_group_obj['name']
                                    except Exception as error:
                                        self.logfmc.logger.error(error)

                            elif 'port' in k:
                                # if this object exist already use it
                                for port_lists in self.port_group_object:
                                    port_list_name = [p_name[0] for p_name in port_lists[1]]
                                    if sorted(port_list_name) == sorted(v):
                                        v = port_lists[0]
                                        matched = True
                                        break
                                if not matched:
                                    create_group_obj = {'objects': [{'type': name_port_id[4], 'id': name_port_id[3]} for port in v for name_port_id in self.port_data if port == name_port_id[0]], 'name': f"{self.rule_prepend_name}_port_group_{randint(1, 100)}"}
                                    try:
                                        if len(create_group_obj['objects']) > 1:
                                            response = self.fmc.object.portobjectgroup.create(create_group_obj)
                                            if 'already exists' not in str(response):
                                                self._creation_check(response, create_group_obj['name'], output=False)
                                        matched = True
                                        v = create_group_obj['name']
                                    except Exception as error:
                                        self.logfmc.logger.error(error)
                dh[k] = v
            rule = dh
            rule_form = deepcopy(temp_form)
            rule_form['name'] = f"{self.rule_prepend_name}_{rule['comment']}_{randint(1, 1000000)}"

            for srcdest_net in ['source','destination']:
                if 'any' != rule[f'{srcdest_net}_network']:
                    if 'group' in rule[f'{srcdest_net}_network']:
                        # update npi if we created a grouped policy
                        self.fmc_net_port_info()
                        rule_form[f'{srcdest_net}Networks'] = {'objects': fix_object(self.fmc.object.networkgroup.get(name=rule[f'{srcdest_net}_network']))}
                    else:
                        rule_form[f'{srcdest_net}Networks'] = {'objects': [{'name': i[0], 'id': i[2], 'type': 'Host' if '/' not in i[1] else 'Network'} for i in self.net_data if i[0] == rule[f'{srcdest_net}_network']]}

            for srcdest_z in ['source', 'destination']:
                if all(['any' != rule[f'{srcdest_z}_zone'],'any' not in rule[f'{srcdest_z}_zone']]):
                    if isinstance(rule[f'{srcdest_z}_zone'],list):
                        add_to_object = []
                        for i in rule[f'{srcdest_z}_zone']:
                            add_to_object.append(all_zones[i])
                        rule_form[f'{srcdest_z}Zones'] = {'objects':add_to_object}
                    else:
                        rule_form[f'{srcdest_z}Zones'] = {'objects': [all_zones[rule[f'{srcdest_z}_zone']]]}

            if 'any' != rule['port']:
                if 'group' in rule['port']:
                    # update npi if we created a grouped policy
                    self.fmc_net_port_info()
                    rule_form['destinationPorts'] = {'objects': fix_object(self.fmc.object.portobjectgroup.get(name=rule['port']))}
                else:
                    rule_form['destinationPorts'] = {'objects': [{'name': i[0], 'id': i[3], 'type': i[4]} for i in self.port_data if i[0] == rule['port']]}

            rule_form['newComments'] = [rule['comment']]
            charity_policy.append(rule_form)

        try:
            res = self.fmc.policy.accesspolicy.accessrule.create(data=charity_policy, container_uuid=acp_set['id'], category='automation_engine', )
            self._creation_check(res, charity_policy)
            self.logfmc.logger.warning(f'{"#" * 5}RULES PUSHED SUCCESSFULLY{"#" * 5}')
        except Exception as error:
            self.logfmc.logger.error(error)

    def driver(self):
        # login FMC
        self.rest_connection()
        # Get zone info first via ClI
        self.zone_ip_info = self.zone_to_ip_information()
        # test
        # self.zone_ip_info = pd.read_csv('temp_zii.csv')
        # get network and port information via rest
        self.fmc_net_port_info()
        # pull information from PPSM
        self.ppsm = self.retrieve_ppsm()
        # create FMC objects
        self.create_fmc_object_names()
        # restart conn??
        self.rest_connection(reset=True)
        # create FMC rules
        self.create_acp_rule()

    @staticmethod
    @deprecated
    def _get_device_creds(cred_file):
        cred_file = create_file_path('safe',cred_file)
        with open(cred_file,'r') as cf:
            return json.load(cf) \


    def get_device_creds(self, cred_file=None,same_cred=True):
        if cred_file is not None:
            return self._get_device_creds(cred_file)
        ftd_u = None
        ftd_p = None

        fmc_u = input("FMC USERNAME:")
        fmc_p = input("FMC PASSWORD:")
        if not same_cred:
            ftd_u = input("FTD USERNAME:")
            ftd_p = input("FTD PASSWORD:")
        ftd_u = ftd_u if ftd_u is not None else fmc_u
        ftd_p = ftd_p if ftd_p is not None else fmc_p

        cdict = {"fmc_username": fmc_u, "fmc_password": fmc_p, "ftd_username": ftd_u, "ftd_password": ftd_p}
        return cdict

if __name__ == "__main__":
    augWork = AugmentedWorker(ppsm_location='gfrs.csv',access_policy='test12',ftd_host='10.11.6.191',fmc_host='10.11.6.60',rule_prepend_name='test_st_beta_1',zone_of_last_resort='outside_zone',same_cred=False,cred_file='cF.json')
    augWork.driver()
    # augWork.rest_connection()
    # augWork.fmc_net_port_info()
    # gps = augWork.net_data
    # mms = augWork.net_group_object
    # mmp = augWork.port_data
    # pop = augWork.port_group_object
    # for item in tqdm(mms,total=len(mms)):
    #     augWork.del_fmc_objects(obj_tup=item, type_='network', obj_type='net_group')
    # for item in tqdm(gps,total=len(gps)):
    #     augWork.del_fmc_objects(obj_tup=item, type_='network', obj_type='net')
    # for item in tqdm(pop,total=len(pop)):
    #     augWork.del_fmc_objects(obj_tup=item, type_='port', obj_type='port_group')
    # for item in tqdm(mmp,total=len(mmp)):
    #     augWork.del_fmc_objects(obj_tup=item, type_='port', obj_type='port')
    # augWork.driver()



