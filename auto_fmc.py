from copy import deepcopy
from datetime import datetime
from ipaddress import IPv4Network, ip_network
from random import randint
from re import search
import json
from logging_fmc import LogCollector
import pandas as pd
from fireREST import FMC
from netmiko import ConnectHandler
from tqdm import tqdm
from utilites import create_file_path
from time import sleep

pd.options.display.max_columns = None
pd.options.display.max_rows = None
pd.options.mode.chained_assignment = None


class AugmentedWorker:

    def __init__(self, cred_file: str = 'cF.json', fmc_host='', ftd_host='', domain='Global',
            ppsm_location='ppsm_test_file.csv', access_policy='test_acp', zbr_bypass: dict = None,rule_prepend_name='firewall',zone_of_last_resort='outside'):
        """
        @param cred_file: JSON file hosting user/pass information
        @param fmc_host: FMC domain or IP address
        @param ftd_host: FTD domain or IP address
        @param domain: used to select the tenant in FMC
        @param ppsm_location: location of rules to stage on FMC
        @param access_policy: which ACP to stage the rules onto
        @param zbr_bypass: (experimental) if you want to manually assign the security zone to rules instead of doing the zone to IP lookup make sure the zone and rules rows match exactly!
        @param rule_prepend_name: an additive on what to call the staged rule. ie a rule will look like facetime_rule_allow_facetime_5324
        where facetime_rule is the prepend var, allow_facetime is the comment and number is unique set of characters to distinguish the rule
        @@param zone_of_last_resort: this is needed when we dont know where a route lives relative to their Zone ie we know that a IP is northbound of our gateway or outside interface.
        """
        creds = self.get_device_creds(cred_file)
        # Sec-lint #1
        for v in list(creds.values()):
            if not isinstance(v,(str,int,float)):
                raise ValueError(f'Cred file has a value that is not allowed for this program. returned value of {type(v)}')
        self.fmc_host = fmc_host
        self.ftd_host = ftd_host
        self.fmc_username = creds['fmc_username']
        self.fmc_password = creds['fmc_password']
        self.ftd_username = creds.get('ftd_username') if creds.get('ftd_username') is not None else creds['fmc_username']
        self.ftd_password = creds.get('ftd_password') if creds.get('ftd_password') is not None else creds['fmc_password']
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
        return ppsm

    def create_fmc_object_names(self, keep_old_name=True):
        def new_name():
            if type_ in ['source', 'destination']:
                net = self.ppsm[type_][x]
                if '/' in net:
                    return f'{net.split("/")[0]}_{net.split("/")[1]}'
                else:
                    return net
            else:
                # if the service is not type-of-port format; make it so
                return (self.ppsm['service'][x]).replace(" ","-")

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

        for type_ in ['source', 'destination', 'port']:
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

            # fix the object naming if we are creating a new name so FMC will accept it and create obj
            for x in tqdm(self.ppsm.index, desc=f'creating new {type_} object or checking if it exist.', total=len(self.ppsm.index), colour='MAGENTA'):
                old_fire_name = self.ppsm[f'fmc_name_{type_}'][x]
                if old_fire_name == 'None':
                    # net object is any ip obj
                    if self.ppsm[type_][x].lower() == 'any':
                        # DNC = Do not create object for this entry
                        self.ppsm[f'fmc_name_{type_}'].loc[x] = 'DNC'
                if self.ppsm[f'fmc_name_{type_}'][x] == 'DNC':
                    continue
                elif not self.ppsm[f'fmc_name_{type_}_install'][x]:
                    continue
                else:
                    fix_obj_naming = new_name()
                    self.ppsm[f'fmc_name_{type_}'].loc[x] = fix_obj_naming

                    if type_ != 'port':
                        new_obj = {'name': fix_obj_naming, 'value': self.ppsm[type_][x]}
                        counter = 0
                        while True:
                            try:
                                if '/' in self.ppsm[type_][x]:
                                    response = self.fmc.object.network.create(data=new_obj)
                                else:
                                    response = self.fmc.object.host.create(data=new_obj)
                                self._creation_check(response, new_obj, output=False)
                                break
                            except Exception as error:
                                self.logfmc.logger.error(f'{error} related to {self.ppsm[type_][x]}')
                                # if we run into issues where this somehow already exist then append a num to end of it
                                counter += 1
                                if 'already exists' in str(error):
                                    self.logfmc.logger.info(error)
                                    if not keep_old_name:
                                        new_obj['name'] = f'{fix_obj_naming}_{counter}'
                                        self.ppsm[f'fmc_name_{type_}'].loc[x] = f'{fix_obj_naming}_{counter}'
                                        self.logfmc.logger.warning(f'creating new object: {new_obj["name"]} and trying again.. ')
                                        return
                                    else:
                                        break

                    else:
                        new_obj = {'name': fix_obj_naming, "protocol": self.ppsm['protocol'][x], 'port': self.ppsm[type_][x]}
                        counter = 0
                        while True:
                            try:
                                response = self.fmc.object.protocolportobject.create(data=new_obj)
                                self._creation_check(response, new_obj, output=False)
                                break
                            except Exception as error:
                                counter += 1
                                if 'already exists' in str(error):
                                    self.logfmc.logger.info(error)
                                    if not keep_old_name:
                                        new_obj['name'] = f'{fix_obj_naming}_{counter}'
                                        self.ppsm[f'fmc_name_{type_}'].loc[x] = f'{fix_obj_naming}_{counter}'
                                        self.logfmc.logger.warning(f'creating new object: {new_obj["name"]} and trying again.. ')
                                        return
                                    else:
                                        break

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
                                try:
                                    item_holder.append(v.get('name'))
                                except:
                                    item_holder.append(v)
                else:
                    for i in self.port_group_object:
                        if obj_info.get('name') == i[0]:
                            for v in i[1]:
                                try:
                                    item_holder.append(v.get('name'))
                                except:
                                    item_holder.append(v)

        if len(item_holder) == 1:
            return item_holder[0]
        sorted(item_holder)
        return item_holder

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

        # find existing policy in fmc
        current_ruleset = self.fmc.policy.accesspolicy.accessrule.get(container_uuid=acp_set['id'])
        changed_ruleset = []
        for i in current_ruleset:
            subset_rule = {}
            try:
                subset_rule['src_z'] = self.find_nested_group_objects(i.get('sourceZones').get('objects'))
            except:
                subset_rule['src_z'] = None
            try:
                subset_rule['dst_z'] = self.find_nested_group_objects(i.get('destinationZones').get('objects'))
            except:
                subset_rule['dst_z'] = None
            try:
                subset_rule['source'] = self.find_nested_group_objects(i.get('sourceNetworks').get('objects'))
            except:
                subset_rule['source'] = None
            try:
                subset_rule['destination'] = self.find_nested_group_objects(i.get('destinationNetworks').get('objects'))
            except:
                subset_rule['destination'] = None
            try:
                subset_rule['port'] = self.find_nested_group_objects(i.get('destinationPorts').get('objects'))
            except:
                subset_rule['port'] = None
            changed_ruleset.append(subset_rule)
        current_ruleset = changed_ruleset
        current_ruleset = pd.DataFrame(current_ruleset)
        if len(current_ruleset) < 1:
            self.logfmc.logger.error('nothing in current ruleset')
            return ruleset

        # get group objects directly added to current rule
        for ip in ['source', 'destination', 'port']:
            grouped_idx = current_ruleset[current_ruleset[ip].apply(lambda x: True if isinstance(x, list) else False)].index.to_list()
            if len(grouped_idx) > 0:
                for gidx in grouped_idx:
                    real_grouped_ip = []
                    for cri in current_ruleset[ip][gidx]:
                        dat_list = self.net_data if ip != 'port' else self.port_data
                        for snd in dat_list:
                            if cri == snd[0]:
                                real_dat = snd[1] if ip != 'port' else f'{snd[1]}:{snd[2]}'
                                real_grouped_ip.append(real_dat)
                    current_ruleset.loc[current_ruleset[ip].index == gidx, f'real_{ip}'] = '|'.join(real_grouped_ip)

        # transformed named objs to real
        combined_net_objs = self.net_data + self.net_group_object
        combined_port_objs = self.port_data + self.port_group_object

        for i in tqdm(combined_net_objs, desc="getting real IPs from named network objects", total=len(combined_net_objs), colour='red'):
            for ip in ['source', 'destination']:
                current_ruleset.loc[current_ruleset[ip].astype(str) == str(i[1]), f'real_{ip}'] = i[1] if not isinstance(i[1],list) else '|'.join(i[1])
                ruleset.loc[ruleset[f'{ip}_network'].astype(str) == str(i[1]), f'real_{ip}'] = i[1] if not isinstance(i[1],list) else '|'.join(i[1])
        for i in tqdm(combined_port_objs, desc="getting real ports-protocols from named port objects", total=len(combined_port_objs), colour='green'):
            current_ruleset.loc[current_ruleset['port'] == i[0], 'real_port'] = i[1] if not isinstance(i[1],list) else '|'.join([pi[0] for pi in i[1]])
            ruleset.loc[ruleset['port'] == i[0], 'real_port'] = i[1] if not isinstance(i[1],list) else '|'.join([pi[0] for pi in i[1]])

        # remove nan values with any
        current_ruleset.fillna(value='any',inplace=True)
        ruleset.fillna(value='any',inplace=True)
        current_ruleset.replace({'None':'any'},inplace=True)
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
            ruleset.reset_index(inplace=True)
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

    def del_fmc_objects(self,obj_id,type_,obj_type):
        try:
            if type_ == 'network':
                if obj_type == 'net':
                    try:
                        self.fmc.object.host.delete(obj_id)
                    except:
                        self.fmc.object.network.delete(obj_id)
                elif obj_type == 'net_group':
                    self.fmc.object.networkgroup.delete(obj_id)
            elif type_ == 'port':
                if obj_type == 'port':
                    self.fmc.object.port.delete(obj_id)
                elif obj_type == 'port_group':
                    self.fmc.object.portobjectgroup.delete(obj_id)
        except Exception as error:
            self.logfmc.logger.error(f'Cannot delete {obj_id} of {type_} \n received code: {error}')

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
            ruleset.drop_duplicates(ignore_index=True, inplace=True)
            if ruleset.empty:
                raise Exception('NO RULES TO DEPLOY')
        except Exception as error:
            raise Exception(error)

        # group by most distinct features
        case1 = ruleset.groupby(['source_network', 'port'])
        case2 = ruleset.groupby(['destination_network', 'port'])
        case3 = ruleset.groupby(['destination_zone','source_zone','port'])
        case4 = ruleset.groupby(['destination_network', 'source_network'])

        ruleset_holder = []
        dup_holder = []
        for grouped_df, type_net in zip([case1, case2, case3, case4], ['source', 'destination','zone','port']):
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
                else:
                    cct_port = 'port'
                    cct_port_data = list(set(group[cct_port].to_list()))
                    group = group.iloc[0]
                    if len(cct_port_data) == 1:
                        group[cct_port] = cct_port_data[0]
                    else:
                        group[cct_port] = sorted(cct_port_data)

                ruleset_holder.append(group.to_dict())

        ruleset.drop(ruleset.index[dup_holder], inplace=True)
        ruleset = pd.concat([pd.DataFrame(ruleset_holder), ruleset], ignore_index=True)
        ruleset.reset_index(inplace=True, drop=True)
        # remove tuples from multi-zoned rows
        for z_name in ['source','destination']:
            ruleset[f'{z_name}_zone'] = ruleset[f'{z_name}_zone'].apply(lambda x: [v for v in x ] if isinstance(x,tuple) else x)
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
                    if 'zone' in k or 'any' == v[0]:
                        if 'any' == v[0]:
                            # any is coming as list so lets strip it just in case this is due to how the policy lookup occurred
                            v = v[0]
                    else:
                        # get new port/net info per iteration so we dont create dup objects that have the same child IDs on creation if needed
                        self.fmc_net_port_info()
                        # the inner break controls the for-loop and need a mechism to break IF we matched on already created group
                        matched = False
                        while True:
                            try:
                                # if this object exist already use it
                                for ip_lists in self.net_group_object:
                                    if sorted(ip_lists[1]) == sorted(v):
                                        v = ip_lists[0]
                                        matched = True
                                        break
                                if matched:
                                    break
                                # create group net or port objs by IDs since fmc cant create rules with more than 50 objects
                                create_group_obj = {'objects': [{'type': name_ip_id[1], 'id': name_ip_id[2]} for ip in v for name_ip_id in self.net_data if ip == name_ip_id[0]], 'name': f"{self.rule_prepend_name}_net_group_{randint(1, 100)}"}
                                response = self.fmc.object.networkgroup.create(create_group_obj)
                                if 'already exists' not in str(response):
                                    self._creation_check(response, create_group_obj['name'], output=False)
                            except:
                                # if this object exist already use it
                                for port_lists in self.port_group_object:
                                    if sorted(port_lists[1]) == sorted(v):
                                        v = port_lists[0]
                                        matched = True
                                        break
                                if matched:
                                    break
                                create_group_obj = {'objects': [{'type': name_port_id[4], 'id': name_port_id[3]} for port in v for name_port_id in self.port_data if port == name_port_id[0]], 'name': f"{self.rule_prepend_name}_port_group_{randint(1, 100)}"}
                                response = self.fmc.object.portobjectgroup.create(create_group_obj)
                                if 'already exists' not in str(response):
                                    self._creation_check(response, create_group_obj['name'], output=False)

                            v = create_group_obj['name']
                            break
                dh[k] = v
            rule = dh

            rule_form = deepcopy(temp_form)
            rule_form['name'] = f"{self.rule_prepend_name}_{rule['comment']}_{randint(1, 1000000)}"

            if any(['any' != rule['source_zone'],'any' not in rule['source_zone']]):
                if isinstance(rule['source_zone'],list):
                    add_to_object = []
                    for i in rule['source_zone']:
                        add_to_object.append(fix_object(self.fmc.object.securityzone.get(name=i))[0])
                    rule_form['sourceZones'] = {'objects':add_to_object}
                else:
                    rule_form['sourceZones'] = {'objects': fix_object(self.fmc.object.securityzone.get(name=rule['source_zone']))}

            if any(['any' != rule['source_network'],'any' not in rule['source_network']]):
                if isinstance(rule['source_network'],list):
                    add_to_object = []
                    for i in rule['source_network']:
                        try:
                            add_to_object.append(fix_object(self.fmc.object.network.get(name=i))[0])
                        except:
                            add_to_object.append(fix_object(self.fmc.object.host.get(name=i))[0])
                    rule_form['sourceNetworks'] = {'objects':add_to_object}
                else:
                    try:
                        rule_form['sourceNetworks'] = {'objects': fix_object(self.fmc.object.network.get(name=rule['source_network']))}
                    except:
                        try:
                            rule_form['sourceNetworks'] = {'objects': fix_object(self.fmc.object.host.get(name=rule['source_network']))}
                        except:
                            rule_form['sourceNetworks'] = {'objects': fix_object(self.fmc.object.networkgroup.get(name=rule['source_network']))}

            if any(['any' != rule['destination_network'],'any' not in rule['destination_network']]):
                if isinstance(rule['destination_network'],list):
                    add_to_object = []
                    for i in rule['destination_network']:
                        try:
                            add_to_object.append(fix_object(self.fmc.object.network.get(name=i))[0])
                        except:
                            add_to_object.append(fix_object(self.fmc.object.host.get(name=i))[0])
                    rule_form['destinationNetworks'] = {'objects':add_to_object}
                else:
                    try:
                        rule_form['destinationNetworks'] = {'objects': fix_object(self.fmc.object.network.get(name=rule['destination_network']))}
                    except:
                        try:
                            rule_form['destinationNetworks'] = {'objects': fix_object(self.fmc.object.host.get(name=rule['destination_network']))}
                        except:
                            rule_form['destinationNetworks'] = {'objects': fix_object(self.fmc.object.networkgroup.get(name=rule['destination_network']))}

            if all(['any' != rule['destination_zone'],'any' not in rule['destination_zone']]):
                if isinstance(rule['destination_zone'],list):
                    add_to_object = []
                    for i in rule['destination_zone']:
                        add_to_object.append(fix_object(self.fmc.object.securityzone.get(name=i))[0])
                    rule_form['destinationZones'] = {'objects':add_to_object}
                else:
                    rule_form['destinationZones'] = {'objects': fix_object(self.fmc.object.securityzone.get(name=rule['destination_zone']))}

            if any(['any' != rule['port'], 'any' not in rule['port']]):
                try:
                    rule_form['destinationPorts'] = {'objects': fix_object(self.fmc.object.protocolportobject.get(name=rule['port']))}
                except:
                    rule_form['destinationPorts'] = {'objects': fix_object(self.fmc.object.portobjectgroup.get(name=rule['port']))}

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
    def get_device_creds(cred_file):
        cred_file = create_file_path('safe',cred_file)
        with open(cred_file,'r') as cf:
            return json.load(cf)


if __name__ == "__main__":
    augWork = AugmentedWorker(cred_file='cF.json', ppsm_location='gfrs.csv',access_policy='test09',ftd_host='10.11.6.191',fmc_host='10.11.6.60',rule_prepend_name='test_st_beta_1',zone_of_last_resort='outside_zone')
    augWork.driver()
    # augWork.rest_connection()
    # augWork.fmc_net_port_info()
    # gps = augWork.net_data
    # for item in tqdm(gps,total=len(gps)):
    #     augWork.del_fmc_objects(obj_id=item[-1],type_='network',obj_type='net')

