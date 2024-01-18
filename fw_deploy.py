import json
from copy import deepcopy
from datetime import datetime
from ipaddress import IPv4Network, ip_network
from re import search, sub, match
from time import sleep
from socket import gethostbyaddr

import pandas as pd
from fireREST import FMC
from netmiko import ConnectHandler
from tqdm import tqdm

from fw_test import FireCheck
from utilites import Util, deprecated, log_collector

pd.options.display.max_columns = None
pd.options.display.max_rows = None
pd.options.mode.chained_assignment = None


class FireStick:

    def __init__(self, configuration_data: dict, cred_file=None):
        self.utils = Util()
        creds = self.get_device_creds(cred_file=cred_file, same_cred=configuration_data.get('same_creds'))

        for v in list(creds.values()):
            if not isinstance(v, (str, int, float)):
                raise ValueError(f'Cred file has a value that is not allowed for this script. returned value of {type(v)}')
        self.management_center = configuration_data.get('management_center')
        self.firewall_sensor = configuration_data.get('firewall_sensor')
        self.fmc_username = creds['fmc_username']
        self.fmc_password = creds['fmc_password']
        self.ftd_username = creds['ftd_username']
        self.ftd_password = creds['ftd_password']
        self.domain = configuration_data.get('domain')
        # some calls might not need a ippp file
        if configuration_data.get('ippp_location'):
            # this is just a check the file MUST be the folder
            self.ippp_location = self.utils.create_file_path('ingestion', configuration_data.get('ippp_location'))
        self.access_policy = configuration_data.get('access_policy')
        self.zbr_bypass = configuration_data.get('zbr_bypass')
        self.rule_prepend_name = configuration_data.get('rule_prepend_name')
        self.zone_of_last_resort = configuration_data.get('zone_of_last_resort')
        self.ruleset_type = configuration_data.get('ruleset_type').upper()
        self.rule_section = configuration_data.get('rule_section')
        self.logfmc = log_collector()
        # optional passing commands
        self.config_data = configuration_data

    def _creation_check(self, response, new_obj, output=True):
        if response.status_code != 201:
            raise Exception(f'received back status code:{response.status_code}')
        else:
            if output:
                self.logfmc.warning(f'new obj {new_obj} created ')

    def rest_connection(self, reset=False):
        if reset:
            self.fmc.conn.refresh()
        else:
            self.fmc = FMC(hostname=self.management_center, username=self.fmc_username, password=self.fmc_password, domain=self.domain)

    def fmc_net_port_info(self):
        net_objects = self.fmc.object.network.get()
        host_objects = self.fmc.object.host.get()
        port_objects = self.fmc.object.port.get()
        net_group_object = self.fmc.object.networkgroup.get()
        port_group_object = self.fmc.object.portobjectgroup.get()

        def _get_name_from_group_object(object_name: list, obj_type='net'):
            if isinstance(object_name, list):
                if obj_type == 'net':
                    return [i['name'] for i in object_name]
                else:
                    return [[str(i.get('name')), str(i.get('protocol')), str(i.get('port'))] for i in object_name]
            # if a single is returned
            return x['name']

        self.net_group_object = []
        for x in net_group_object:
            try:
                self.net_group_object.append(tuple([str(x['name']), _get_name_from_group_object(x.get('objects')), str(x['id'])]))
            except:
                self.net_group_object.append(tuple([str(x['name']), _get_name_from_group_object(x.get('literals')), str(x['id'])]))

        self.net_data = [tuple([str(x['name']), str(x['value']), str(x['id'])]) for x in net_objects] + [tuple([str(x['name']), str(x['value']), str(x['id'])]) for x in host_objects]
        self.port_data = [tuple([str(x.get('name')), str(x.get('protocol')), str(x.get('port')), str(x['id']), str(x['type'])]) for x in port_objects]
        self.port_group_object = [tuple([str(x['name']), _get_name_from_group_object(x.get('objects'), obj_type='port'), str(x['id'])]) for x in port_group_object]

    def retrieve_rule_objects(self,get_diff_access_pol=False):
        if get_diff_access_pol:
            pol_to_use = get_diff_access_pol
        else:
            pol_to_use = self.access_policy

        acp_id = self.fmc.policy.accesspolicy.get(name=pol_to_use)
        acp_id = acp_id['id']
        acp_rules = self.fmc.policy.accesspolicy.accessrule.get(container_uuid=acp_id)
        return acp_id, acp_rules

    def transform_rulesets(self, proposed_rules=None, save_current_ruleset=False):
        if save_current_ruleset:
            self.rest_connection()
            self.fmc_net_port_info()

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
        acp_id, current_ruleset = self.retrieve_rule_objects()
        current_ruleset = self.transform_acp(current_ruleset)
        if len(current_ruleset) < 1:
            self.logfmc.error('nothing in current ruleset')
            return proposed_rules, None, acp_id

        self.logfmc.warning("getting real IPs from named network objects")
        for ip in ['source', 'destination']:
            current_ruleset[f'real_{ip}'] = current_ruleset[ip].apply(lambda p: self.fdp_grouper(p, 'ip'))
            if proposed_rules is not None:
                proposed_rules[f'real_{ip}'] = proposed_rules[f'{ip}_network'].apply(lambda p: self.fdp_grouper(p, 'ip'))

        self.logfmc.warning("getting real ports-protocols from named port objects")
        current_ruleset['real_port'] = current_ruleset['port'].apply(lambda p: self.fdp_grouper(p, 'port'))
        if proposed_rules is not None:
            proposed_rules['real_port'] = proposed_rules['port'].apply(lambda p: self.fdp_grouper(p, 'port'))

        # remove nan values with any
        current_ruleset.fillna(value='any', inplace=True)
        current_ruleset.replace({'None': 'any'}, inplace=True)

        # make sure we are matching by list type and sorting correctly even if its a list object
        if proposed_rules is not None:
            for col in proposed_rules.columns:
                proposed_rules[col] = proposed_rules[col].apply(lambda x: sorted(list(v for v in x)) if isinstance(x, (tuple, list)) else x)
        for col in current_ruleset.columns:
            current_ruleset[col] = current_ruleset[col].apply(lambda x: sorted(list(v for v in x)) if isinstance(x, (tuple, list)) else x)

        # save rules
        if save_current_ruleset:
            return current_ruleset

        # pipeline rules
        if proposed_rules is not None:
            proposed_rules.fillna(value='any', inplace=True)
            return proposed_rules, current_ruleset, acp_id

    def ip_address_check(self,x):
        # check if user entered a hot bits in their subnet mask
        x = x.strip()
        try:
            if 'any' not in x:
                # has to strict check so we can properly identify if its a subnet or mistyped single IP.
                return str(ip_network(x))
            else:
                return x
        except ValueError as verror:
            self.logfmc.debug(verror)
            return x.split('/')[0]

    def prepare_ippp(self, ippp):
        ippp = ippp.astype(str)
        ippp = ippp[ippp['source'] != 'nan']
        for origin in ['source', 'destination']:
            # check if user entered a hot bits in their subnet mask
            ippp[origin] = ippp[origin].apply(lambda x: str(self.ip_address_check(x)))
            # fix so we dont have to refactor a bullion lines
            ippp[origin] = ippp[origin].apply(lambda x: (x.split('/')[0]).strip() if '/32' in x else x.strip())
        # strip extra spaces in cols
        for col in ippp.columns:
            ippp[col] = ippp[col].apply(lambda x: x.strip())
        # check if we have acceptable protocol for the API
        ippp['protocol'] = ippp['protocol'].apply(lambda x: str(x).upper())
        na_protos = ippp[~ippp['protocol'].str.contains('TCP|UDP|ANY', regex=True)]
        dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d%H%M%S")
        fpath = self.utils.create_file_path('CNI', f'{self.rule_prepend_name}_non_applicable_protocols_{dt_now}.csv')
        if not na_protos.empty:
            self.logfmc.warning(self.utils.highlight_important_message('found protocols that cannot be used with this script. Please enter them manually'))
            self.logfmc.warning(f'PROTOCOLS NOT IMPLEMENTED LOCATED AT FILE LOCATION: {fpath}')
            # make sure the user sees the msg with no input.
            sleep(2)
            na_protos.to_csv(fpath, index=False)
        ippp = ippp[ippp['protocol'].str.contains('TCP|UDP|ANY', regex=True)]
        # remove non-alphanumeric chars from str if protocol take udp or tcp from str
        for col in ['service', 'protocol', 'port_range_low', 'port_range_high']:
            if col in ['service', 'protocol']:
                ippp[col] = ippp[col].apply(lambda x: sub('[^0-9a-zA-Z]+', '_', x))
                if col == 'protocol':
                    ippp[col] = ippp[col].apply(lambda x: next(i.split()[0] for i in x.split('_')) if match('TCP|UDP', x) else x)
            # remove trailing zero from float -> str convert
            elif col in ['port_range_low', 'port_range_high']:
                ippp[col] = ippp[col].apply(lambda x: x.split('.0')[0] if x != 'nan' else x)
        return ippp

    def find_dup_services(self):
        fixing_holder = []
        should_preproc = self.config_data.get('preprocess_csv')
        service_grouping = self.ippp.groupby(['service'])
        sg_listing = service_grouping.size()[service_grouping.size() > 1].index.values.tolist()
        for gl in sg_listing:
            group = service_grouping.get_group(gl)
            # check if we have inconsistent port-to-service matching
            have_dup = group[['service', 'port', 'protocol']].drop_duplicates()
            if have_dup.shape[0] >= 2:
                fixing_holder.append(have_dup.to_dict(orient='records'))
        if len(fixing_holder) > 0:
            # un-nest list
            fixing_holder = [l2 for l1 in fixing_holder for l2 in l1]
            dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d%H%M%S")
            fname = self.utils.create_file_path('CNI', f'{self.rule_prepend_name}_port_to_service_mismatch_{dt_now}.csv')
            pd.DataFrame(fixing_holder).to_csv(fname, index=False)

            # preprocess IPPP
            if should_preproc:
                preproc_fname = self.utils.create_file_path('preproc', self.config_data.get('preprocess_csv'))
                preproc_df = pd.read_csv(preproc_fname)
                preproc_df = self.fix_port_range_objects(preproc_df)
                # merge existing port data info with the preproc incase a matching is found in there that is correct
                fw_port_data = pd.DataFrame([{'protocol': pdata[1], 'service': pdata[0], 'port': pdata[2]} for pdata in self.port_data])
                preproc_df = pd.concat([preproc_df, fw_port_data], ignore_index=True, sort=False)

                # get all the port mismatch findings from the holder
                if not self.config_data.get('silent_mode'):
                    ans = self.utils.permission_check(
                        self.utils.highlight_important_message(f'you have {len(fixing_holder)} duplicate matches in this IPPP do you want to create an mapping in the object store for ALL objects? y/N'),
                        ['y', 'n'])
                else:
                    ans = 'y'

                if ans == 'n':
                    self.logfmc.critical(f'mismatched items saved to {fname}')
                    self.logfmc.critical(self.utils.highlight_important_message('PLEASE CREATING MAPPING AND RESTART ENGINE'))
                    quit()
                else:
                    for i in fixing_holder:
                        correct_match = preproc_df['service'][(preproc_df['port'] == i['port']) & (preproc_df['protocol'] == i['protocol'])]
                        # if we dont have a mapping then we cant continue since we would not know how to create this object in the manager
                        if correct_match.empty:
                            missed_mapping = f"{i['port']}_{i['protocol']}"
                            self.ippp['service'][(self.ippp['port'] == i['port']) & (preproc_df['protocol'] == i['protocol'])] = missed_mapping
                            continue

                        # take the first match and clean the formatting
                        correct_match = correct_match.iat[0]
                        correct_match = ''.join(e for e in correct_match if e.isalnum() or search(r'\s', e))
                        correct_match = sub(r'\s', '_', correct_match)
                        # replace old match with the correct one in IPPP
                        self.ippp['service'][(self.ippp['port'] == i['port']) & (preproc_df['protocol'] == i['protocol'])] = correct_match

                self.logfmc.info(self.utils.highlight_important_message(f'cleaned {len(fixing_holder)} dup service name items!'))
                self.logfmc.info(f'mismatched items saved to {fname}')

            else:
                self.logfmc.critical(self.utils.highlight_important_message('Please Check IPPP for inconsistencies.. found multiple services matching to varying ports'))
                self.logfmc.critical(f'mismatched items saved to {fname}')
                quit()

    @staticmethod
    def fix_port_range_objects(fix_item) -> pd.DataFrame:
        # drop trailing decimal point from str conversion
        fix_item['port_range_low'] = fix_item['port_range_low'].astype(str).apply(lambda x: x.split('.')[0])
        fix_item['port_range_high'] = fix_item['port_range_high'].astype(str).apply(lambda x: x.split('.')[0])
        # take care range ports
        fix_item['port'] = 0
        for i in fix_item.index:
            # catch any any clause
            if fix_item['port_range_low'][i] in ['nan', '0', '65535', 'any'] and fix_item['port_range_high'][i] in ['nan', '0', '65535', 'any']:
                fix_item['port_range_high'][i] = fix_item['port_range_low'][i] = 'any'
            elif fix_item['port_range_high'][i] in ['nan', '0', '65535', 'any'] and fix_item['port_range_low'][i] in ['nan', '0', '65535', 'any']:
                fix_item['port_range_high'][i] = fix_item['port_range_low'][i] = fix_item['port_range_high'][i] = 'any'
            # if the rows has nothing in the adjacent col copy from the other row. (this avoids nan bug)
            if fix_item['port_range_high'][i] in ['nan']:
                fix_item['port_range_high'][i] = fix_item['port_range_low'][i]
            elif fix_item['port_range_low'][i] in ['nan']:
                fix_item['port_range_low'][i] = fix_item['port_range_high'][i]
            # if port is a range append range symbol
            if fix_item['port_range_low'][i] != fix_item['port_range_high'][i]:
                fix_item['port'].loc[i] = fix_item['port_range_low'][i] + '-' + fix_item['port_range_high'][i]
            else:
                fix_item['port'].loc[i] = fix_item['port_range_low'][i]
        # take care of the random chars in protocol col ( we can only use TCP/UDP for its endpoint soo..
        fix_item['protocol'] = fix_item['protocol'].astype(str).apply(lambda x: x.strip()[:3])
        fix_item.drop(columns=['port_range_low', 'port_range_high'], inplace=True)
        return fix_item

    def create_fmc_object_names(self):
        for type_ in tqdm(['source', 'destination', 'port'], desc=f'creating new objects or checking if it exist.', total=3, colour='MAGENTA'):
            # whether we need to create an obj placeholder
            self.ippp[f'fmc_name_{type_}_install'] = True
            self.ippp[f'fmc_name_{type_}'] = 'None'
            if type_ != 'port':
                for name_ip in self.net_data:
                    # if ip is found in FMC store that info in a df
                    if not self.ippp[self.ippp[type_] == name_ip[1]].empty:
                        self.ippp[f'fmc_name_{type_}'].loc[self.ippp[type_] == name_ip[1]] = name_ip[0]
                        self.ippp[f'fmc_name_{type_}_install'].loc[self.ippp[type_] == name_ip[1]] = False
            else:
                # check if port data already exist on fmc
                for port_info in self.port_data:
                    port_protco = self.ippp[(self.ippp[type_] == port_info[2]) & (self.ippp['protocol'] == port_info[1])]
                    if not port_protco.empty:
                        self.ippp[f'fmc_name_{type_}'].loc[(self.ippp[type_] == port_info[2]) & (self.ippp['protocol'] == port_info[1])] = port_info[0]
                        self.ippp[f'fmc_name_{type_}_install'].loc[(self.ippp[type_] == port_info[2]) & (self.ippp['protocol'] == port_info[1])] = False

            # group the common IPs and ports into unique and push all objects in bulk
            install_pd = self.ippp[self.ippp[f'fmc_name_{type_}_install'] == True]
            install_pd = install_pd[install_pd[type_] != 'any']
            if type_ in ['source', 'destination']:
                self.fmc_net_port_info()
                install_pd[f'fmc_name_{type_}'] = install_pd[type_].apply(lambda net: f'{net.split("/")[0]}_{net.split("/")[1]}' if '/' in net else net)
                if not self.ippp[type_][(self.ippp[f'fmc_name_{type_}_install'] == True) & (self.ippp[type_] != 'any')].empty:
                    self.ippp[f'fmc_name_{type_}'] = self.ippp[type_][(self.ippp[f'fmc_name_{type_}_install'] == True) & (self.ippp[type_] != 'any')].apply(lambda net: f'{net.split("/")[0]}_{net.split("/")[1]}' if '/' in net else net)
                net_data = [nd[0] for nd in self.net_data]
                net_list = list(set([net for net in install_pd[f'fmc_name_{type_}'] if '_' in net]))
                net_list = [{'name': net, 'value': net.replace('_', '/')} for net in net_list if net not in net_data]

                host_list = list(set([host for host in install_pd[f'fmc_name_{type_}'] if not '_' in host]))

                # check if need to resolve names
                if self.config_data.get('resolve_objects'):
                    host_list = [{'name': self.retrieve_hostname(host), 'value': host} for host in tqdm(host_list,total=len(host_list)) if host not in net_data]
                else:
                    host_list = [{'name': host, 'value': host} for host in tqdm(host_list,total=len(host_list)) if host not in net_data]

                try:
                    self.fmc.object.network.create(data=net_list)
                except Exception as error:
                    self.logfmc.debug(error)

                try:
                    self.fmc.object.host.create(data=host_list)
                except Exception as error:
                    self.logfmc.debug(error)
            else:
                if not install_pd.empty:
                    group_port = install_pd.groupby(['port', 'protocol'])
                    gpl = group_port.size()[group_port.size() > 0].index.values.tolist()
                    for i in gpl:
                        i = group_port.get_group(i)
                        i = i.iloc[0]
                        ipd = install_pd['service'][(install_pd['port'] == i['port']) & (install_pd['protocol'] == i['protocol'])]
                        spipd = self.ippp['service'][(self.ippp['port'] == i['port']) & (self.ippp['protocol'] == i['protocol'])]
                        install_pd[f'fmc_name_{type_}'][ipd.index.tolist()] = ipd.iloc[0]
                        self.ippp[f'fmc_name_{type_}'][spipd.index.tolist()] = spipd.iloc[0]

                    port_data = [po[0] for po in self.port_data]
                    install_pd[f'fmc_name_{type_}'] = install_pd[f'fmc_name_{type_}'].apply(lambda port: port.replace(" ", "-"))
                    self.ippp[f'fmc_name_{type_}'] = self.ippp[f'fmc_name_{type_}'].apply(lambda port: port.replace(" ", "-"))

                    port_list = list(
                        set(
                            [
                                port
                                for port in install_pd[f'fmc_name_{type_}']
                                if port not in port_data
                            ]))
                    port_list = [
                        {
                            'name': port,
                            "protocol": install_pd['protocol'][install_pd[f'fmc_name_{type_}'] == port].iloc[0],
                            'port': install_pd['port'][install_pd[f'fmc_name_{type_}'] == port].iloc[0]
                        }
                        for port in port_list
                    ]
                    try:
                        self.fmc.object.protocolportobject.create(data=port_list)
                    except Exception as error:
                        self.logfmc.debug(error)

    def retrieve_hostname(self, ip):
        domain_check = self.config_data.get('dont_include_domains')
        try:
            retrieved = gethostbyaddr(ip)[0]
            if domain_check:
                reg_match = search(f'({domain_check})$', retrieved)
                if bool(reg_match):
                    mat_pat = reg_match.group(0)
                    retrieved = retrieved.split(mat_pat)[0]
                    check_if_gen_ptr = ''.join(dname for dname in retrieved if dname.isalnum())
                    if check_if_gen_ptr.isnumeric():
                        raise TypeError(f'GENERIC PTR RECORD RECEIVED FOR {retrieved}')
            # get new data in case we created a new obj
            self.fmc_net_port_info()
            host_names = [i[0] for i in self.net_data]
            count = 1
            while True:
                if retrieved in host_names:
                    count += 1
                    retrieved = f'{retrieved}_{count}'
                else:
                    return retrieved
        except Exception as error:
            self.logfmc.debug(error)
            return ip

    def zone_to_ip_information(self):
        route_zone_info = []
        ipv4_re = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        ftd_info = {
            'device_type': 'cisco_ftd_ssh', 'host': self.firewall_sensor,
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
        item_holder = []
        try:
            # handle literals
            for k in object_item.keys():
                if k == 'objects':
                    if not isinstance(object_item[k], list):
                        item_holder.append(object_item[k])
                    else:
                        for obj_info in object_item[k]:
                            if 'group' not in obj_info.get('type').lower():
                                if obj_info.get('name') is not None:
                                    item_holder.append(obj_info['name'])

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
                elif k == 'literals':
                    if not isinstance(object_item[k], list):
                        item_holder.append(object_item[k])
                    else:
                        for obj_info in object_item[k]:
                            if obj_info.get('value') is not None:
                                item_holder.append(obj_info['value'])
                            elif obj_info.get('port') is not None:
                                if obj_info.get('protocol') == '6':
                                    item_holder.append(f'TCP:{obj_info.get("port")}')
                                elif obj_info.get('protocol') == '17':
                                    item_holder.append(f'UDP:{obj_info.get("port")}')

            if len(item_holder) == 1:
                return item_holder[0]
            sorted(item_holder)
            return item_holder
        except Exception as error:
            self.logfmc.debug(error)
            return None

    def fdp_grouper(self, p, type_):
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

    def find_inter_dup_policies(self, ruleset):
        ruleset, current_ruleset, acp_id = self.transform_rulesets(proposed_rules=ruleset)

        if current_ruleset is not None:
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
                    # action
                    if current_ruleset['action'][i] == self.ruleset_type:
                        quondam += 1

                    if quondam >= 5:
                        idx_collector.append(idx)

            idx_collector = list(set(idx_collector))
            try:
                ruleset.drop(idx_collector, inplace=True)
                ruleset.reset_index(inplace=True, drop=True)
                self.logfmc.warning(f"{'#' * 3}DROP {len(idx_collector)} DUP RULES{'#' * 3}")
            except:
                # no dups to drop
                pass
            return ruleset, acp_id

        return ruleset, acp_id

    def get_zone_from_ip(self, type_, i):
        # drop 0.0.0.0 so we dont get the outside zone matching due to it being a wildcard
        normalized_zone_ip_info = self.zone_ip_info.copy()
        normalized_zone_ip_info = normalized_zone_ip_info[normalized_zone_ip_info['IP'] != "0.0.0.0"]
        normalized_zone_ip_info.reset_index(inplace=True, drop=True)

        if self.ippp[type_][i] == 'any':
            return {f"{type_}_zone": 'any', f'{type_}_network': 'any'}
        elif self.zbr_bypass is not None:
            # index of bypass MUST match ippp index
            return {f"{type_}_zone": str(self.zbr_bypass[type_][i]), f'{type_}_network': self.ippp[f'fmc_name_{type_}'][i]}

        ippp_subnet = ip_network(self.ippp[type_][i])
        # if we need to find where a host address lives exactly
        if '/' not in self.ippp[type_][i] or '/32' in self.ippp[type_][i]:
            for p in normalized_zone_ip_info.index:
                asp_subnet = normalized_zone_ip_info['ip_cidr'][p]
                if ippp_subnet.subnet_of(ip_network(asp_subnet)):
                    return {f"{type_}_zone": normalized_zone_ip_info['ZONE'][p], f'{type_}_network': self.ippp[f'fmc_name_{type_}'][i]}
        # if we need to find all zones a subnet might reside
        elif '/' in self.ippp[type_][i]:
            zone_group = list(set([normalized_zone_ip_info['ZONE'][p] for p in normalized_zone_ip_info.index if ippp_subnet.subnet_of(ip_network(normalized_zone_ip_info['ip_cidr'][p]))]))
            # if we have a 1.1.0.0/16 and we dont have the summarized route in our routing table we need to find all subnets of this subnets zone also!
            find_all_subnets_group = list(set([normalized_zone_ip_info['ZONE'][p] for p in normalized_zone_ip_info.index if ip_network(normalized_zone_ip_info['ip_cidr'][p]).subnet_of(ippp_subnet)]))
            zone_group = tuple(list(set(zone_group + find_all_subnets_group)))
 
            if len(zone_group) != 0:
                zone_group = zone_group if len(zone_group) > 1 else zone_group[0]
                return {f"{type_}_zone": zone_group, f'{type_}_network': self.ippp[f'fmc_name_{type_}'][i]}
        # if we dont know where this zone is coming it must be from external
        return {f"{type_}_zone": self.zone_of_last_resort, f'{type_}_network': self.ippp[f'fmc_name_{type_}'][i]}

    def zbr_bypass_check(self):
        if self.zbr_bypass is None:
            self.zone_ip_info['ip_cidr'] = self.zone_ip_info['IP'].astype(str) + '/' + self.zone_ip_info['CIDR'].astype(str)
            # sort df by subnet size to find the closet match first
            self.zone_ip_info.sort_values(by='ip_cidr', key=lambda x: x.apply(lambda y: ip_network(y)), ascending=False, inplace=True)
        else:
            # if we are not doing zone-ip lookup based rule creation then the zone must be loaded from init
            if not isinstance(self.zbr_bypass, dict):
                raise TypeError(f'zbr_bypass is a {type(self.zbr_bypass)} object not dict')

    def standardize_ippp(self):
        ruleset = []
        self.zbr_bypass_check()
        # sort rules in a pretty format
        for i in self.ippp.index:
            rule_flow = {}
            src_flow = self.get_zone_from_ip('source', i)
            dst_flow = self.get_zone_from_ip('destination', i)
            # block double zone
            if src_flow["source_zone"] == dst_flow["destination_zone"]:
                continue
            rule_flow.update(src_flow)
            rule_flow.update(dst_flow)
            rule_flow.update({'port': self.ippp['fmc_name_port'][i] if self.ippp['port'][i] != 'any' else 'any'})
            rule_flow.update({'comment': self.ippp['comments'][i]})
            ruleset.append(rule_flow)

        ruleset = pd.DataFrame(ruleset)
        # if their all the same zone then we got nothing to find dups of
        if ruleset.empty:
            self.logfmc.critical(self.utils.highlight_important_message('NOTHING IN RULESET THEY MIGHT ALL BE THE SAME ZONE'))
            if self.config_data.get('multi_rule_ippp'):
                return False
            else:
                quit()
        return ruleset

    def create_acp_rule(self):
        # get ruleset
        ruleset = self.standardize_ippp()
        if isinstance(ruleset,bool):
           return False, False
        ruleset, acp_id = self.find_inter_dup_policies(ruleset)

        # if we removed all the dups and we have no new rules or for some reason we dont have rules to deploy raise to stop the program
        for col in ruleset.columns:
            ruleset[col] = ruleset[col].apply(lambda x: tuple(v for v in x) if isinstance(x, list) else x)
        ruleset.drop_duplicates(ignore_index=True, inplace=True)
        if ruleset.empty:
            self.logfmc.critical(self.utils.highlight_important_message('NO RULES TO DEPLOY'))
            if self.config_data.get('multi_rule_ippp'):
                return False,False
            else:
                quit()

        # agg by zone
        ruleset_holder = []
        case4 = ruleset.groupby(['destination_zone', 'source_zone'])
        c4_listing = case4.size()[case4.size() >= 1].index.values.tolist()
        for gl in c4_listing:
            group = case4.get_group(gl)
            agg_src_net = []
            for i in group['source_network'].tolist():
                if isinstance(i, (list, tuple)):
                    for itr in i:
                        agg_src_net.append(itr)
                else:
                    agg_src_net.append(i)
            agg_dst_net = []
            for i in group['destination_network'].tolist():
                if isinstance(i, (list, tuple)):
                    for itr in i:
                        agg_dst_net.append(itr)
                else:
                    agg_dst_net.append(i)
            agg_port = []
            for i in group['port'].tolist():
                if isinstance(i, (list, tuple)):
                    for itr in i:
                        agg_port.append(itr)
                else:
                    agg_port.append(i)
            agg_src_net = sorted(list(set(agg_src_net)))
            agg_dst_net = sorted(list(set(agg_dst_net)))
            agg_port = sorted(list(set(agg_port)))
            # fit the agg lists into one cell since we captured the all the other info
            group = group.iloc[0]
            # dont take list items if the list only has 1 element
            group['source_network'] = agg_src_net if len(agg_src_net) > 1 else agg_src_net[0]
            group['destination_network'] = agg_dst_net if len(agg_dst_net) > 1 else agg_dst_net[0]
            group['port'] = agg_port if len(agg_port) > 1 else agg_port[0]
            # dup policy check
            dup_seen = False
            for rule_group in ruleset_holder:
                if group.to_dict() == rule_group:
                    dup_seen = True
                    break
            if not dup_seen:
                ruleset_holder.append(group.to_dict())
        ruleset = pd.DataFrame(ruleset_holder)
        # add rule name back to df if needed
        if self.config_data.get('multi_rule_ippp'):
            ruleset['policy_name'] = self.ippp['policy_name'].iloc[0]

        # remove tuples from multi-zoned rows
        for col in ruleset.columns:
            ruleset[col] = ruleset[col].apply(lambda x: list(v for v in x) if isinstance(x, tuple) else x)

        # since we grouped policy find the dups again and get rid of em
        ruleset, _ = self.find_inter_dup_policies(ruleset)
        if ruleset.empty:
            self.logfmc.warning('NO RULES TO DEPLOY')
            return

        # real cols are for function lookup use
        ruleset = ruleset.loc[:, ~ruleset.columns.str.startswith('real')]
        return ruleset, acp_id

    def deploy_rules(self, new_rules, current_acp_rules_id):
        def _fix_object(x):
            try:
                x = x[0]
            except:
                x = x
            return [{'name': x['name'], 'id': x['id'], 'type': x['type']}]

        dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d%H%M%S")
        ruleset_loc = self.utils.create_file_path('predeploy_rules', f"fmc_ruleset_preload_configs_{dt_now}.csv", )
        new_rules.to_csv(ruleset_loc, index=False)
        if not self.config_data.get('silent_mode'):
            self.utils.permission_check(f'REVIEW PRE-DEPLOY RULESET FILE located at {ruleset_loc}')

        temp_form = {
            "action": self.ruleset_type, "enabled": 'true', "type": "AccessRule",
            "name": "template_rule", "sendEventsToFMC": 'true', "enableSyslog": 'true',
            "logFiles": 'false',
            "logBegin": 'true' if self.ruleset_type == 'DENY' else 'false', "logEnd": 'true' if self.ruleset_type == 'ALLOW' else 'false'
        }
        # get all zone info
        all_zones = {_fix_object(i)[0]['name']: _fix_object(i)[0] for i in self.fmc.object.securityzone.get()}
        # create a bulk policy push operation
        charity_policy = []
        take_num = 1
        cgj_num = take_num
        cgp_num = take_num
        for i in tqdm(new_rules.index, desc='Loading bulk rule collection artifacts', total=len(new_rules.index), colour='green'):
            rule = new_rules.loc[i].to_dict()
            dh = {}
            for k, v in rule.items():
                if isinstance(v, str):
                    # everything was converted to str for comparison in dup func so convert list obj back
                    if '[' in v:
                        v = json.loads(v.replace("'", '"'))
                if isinstance(v, list):
                    # dont need create objs for zones or any ips,zone
                    if 'zone' in k or 'any' in v:
                        if 'any' in v:
                            # any is coming as list so lets strip it just in case this is due to how the policy lookup occurred
                            v = 'any'
                    else:
                        # avoid rate limiting
                        sleep(5)
                        # bug fix for connection dropping out mid way due to rate-limiting
                        self.rest_connection()
                        # get new port/net info per iteration so we dont create dup objects that have the same child IDs on creation if needed
                        self.fmc_net_port_info()
                        # the inner break controls the for-loop and need a mechanism to break IF we matched on already created group
                        matched = False
                        while not matched:
                            if 'destination' in k or 'source' in k:
                                # if this object exists already use it
                                for ip_lists in self.net_group_object:
                                    if sorted(ip_lists[1]) == sorted(v):
                                        # from cleanup module so we dont reuse net groups with less the min acceptable size for creation.
                                        if len(ip_lists[1]) >= 50:
                                            v = ip_lists[0]
                                            matched = True
                                            break
                                if not matched:
                                    # create group net or port objs by IDs since fmc cant create rules with more than 50 objects
                                    if len(v) >= 50:
                                        while True:
                                            create_group_obj = {'objects': [{'type': name_ip_id[1], 'id': name_ip_id[2]} for ip in v for name_ip_id in self.net_data if ip == name_ip_id[0]], 'name': f"{self.rule_prepend_name}_NetGroup_{cgj_num}"}
                                            cgj_num += 1
                                            try:
                                                if len(create_group_obj['objects']) > 1:
                                                    response = self.fmc.object.networkgroup.create(create_group_obj)
                                                    if 'already exists' not in str(response):
                                                        self._creation_check(response, create_group_obj['name'], output=False)
                                                v = create_group_obj['name']
                                                break
                                            except Exception as error:
                                                self.logfmc.error(error)
                                    matched = True

                            elif 'port' in k:
                                # if this object exist already use it
                                for port_lists in self.port_group_object:
                                    port_list_name = [p_name[0] for p_name in port_lists[1]]
                                    if sorted(port_list_name) == sorted(v):
                                        # from cleanup module so we dont reuse group with less the min acceptable size for creation.
                                        if len(port_lists[1]) >= 50:
                                            v = port_lists[0]
                                            matched = True
                                            break
                                if not matched:
                                    # create group net or port objs by IDs since fmc cant create rules with more than 50 objects
                                    if len(v) >= 50:
                                        while True:
                                            create_group_obj = {'objects': [{'type': name_port_id[4], 'id': name_port_id[3]} for port in v for name_port_id in self.port_data if port == name_port_id[0]], 'name': f"{self.rule_prepend_name}_PortGroup_{cgp_num}"}
                                            cgp_num += 1
                                            try:
                                                if len(create_group_obj['objects']) > 1:
                                                    response = self.fmc.object.portobjectgroup.create(create_group_obj)
                                                    if 'already exists' not in str(response):
                                                        self._creation_check(response, create_group_obj['name'], output=False)
                                                v = create_group_obj['name']
                                                break
                                            except Exception as error:
                                                self.logfmc.critical(error)
                                    matched = True
                dh[k] = v
            rule = dh
            rule_form = deepcopy(temp_form)
            # if we have a rule name already made for this item then use that if not Take a number!
            rule_form['name'] = f"{self.rule_prepend_name}_{take_num}" if not rule.get('policy_name') else f"{rule.get('policy_name')}_{take_num}"
            take_num += 1

            # strip net group to get only name for comparision
            striped_group_name = [i[0] for i in self.net_group_object]
            for srcdest_net in ['source', 'destination']:
                if 'any' != rule[f'{srcdest_net}_network']:
                    if '_NetGroup_' in rule[f'{srcdest_net}_network'] or '_net_group_' in rule[f'{srcdest_net}_network'] or rule[f'{srcdest_net}_network'] in striped_group_name:
                        # update npi if we created a grouped policy
                        self.fmc_net_port_info()
                        rule_form[f'{srcdest_net}Networks'] = {'objects': _fix_object(self.fmc.object.networkgroup.get(name=rule[f'{srcdest_net}_network']))}
                    else:
                        if not isinstance(rule[f'{srcdest_net}_network'], list):
                            net_list = [rule[f'{srcdest_net}_network']]
                        else:
                            net_list = rule[f'{srcdest_net}_network']
                        rule_form[f'{srcdest_net}Networks'] = {'objects': [{'name': i[0], 'id': i[2], 'type': 'Host' if '/' not in i[1] else 'Network'} for ip in net_list for i in self.net_data if i[0] == ip]}

            for srcdest_z in ['source', 'destination']:
                if all(['any' != rule[f'{srcdest_z}_zone'], 'any' not in rule[f'{srcdest_z}_zone']]):
                    if isinstance(rule[f'{srcdest_z}_zone'], list):
                        add_to_object = []
                        for i in rule[f'{srcdest_z}_zone']:
                            add_to_object.append(all_zones[i])
                        rule_form[f'{srcdest_z}Zones'] = {'objects': add_to_object}
                    else:
                        rule_form[f'{srcdest_z}Zones'] = {'objects': [all_zones[rule[f'{srcdest_z}_zone']]]}

            if 'any' != rule['port']:
                if '_PortGroup_' in rule['port'] or '_port_group_' in rule['port']:  # support legacy
                    # update npi if we created a grouped policy
                    self.fmc_net_port_info()
                    rule_form['destinationPorts'] = {'objects': _fix_object(self.fmc.object.portobjectgroup.get(name=rule['port']))}
                else:
                    if isinstance(rule['port'], str):
                        port = [rule['port']]
                    else:
                        port = rule['port']
                    rule_form['destinationPorts'] = {'objects': [{'name': i[0], 'id': i[3], 'type': i[4]} for p in port for i in self.port_data if i[0] == p]}

            rule_form['newComments'] = [rule['comment']]

            charity_policy.append(rule_form)

        try:
            res = self.fmc.policy.accesspolicy.accessrule.create(data=charity_policy, container_uuid=current_acp_rules_id, category=self.rule_section, )
            self._creation_check(res, charity_policy)
            self.logfmc.warning(f'{"#" * 5}RULES PUSHED SUCCESSFULLY{"#" * 5}')
            return True, 1
        except Exception as error:
            self.logfmc.error(error)
            return False, error

    def transform_acp(self, current_ruleset):
        changed_ruleset = []
        for i in current_ruleset:
            subset_rule = {}
            subset_rule['policy_name'] = i.get('name')
            subset_rule['action'] = i.get('action')
            subset_rule['src_z'] = self.find_nested_group_objects(i.get('sourceZones'))
            subset_rule['dst_z'] = self.find_nested_group_objects(i.get('destinationZones'))
            subset_rule['source'] = self.find_nested_group_objects(i.get('sourceNetworks'))
            subset_rule['destination'] = self.find_nested_group_objects(i.get('destinationNetworks'))
            subset_rule['port'] = self.find_nested_group_objects(i.get('destinationPorts'))
            if 'strict_checkup' in self.config_data and self.config_data.get('strict_checkup'):
                strict_holder = []
                # changed to get since port can be NONE value AKA 'any' in the Rules

                if i.get('destinationPorts') is not None:
                    real_dst_ports = i.get('destinationPorts')
                    for k in real_dst_ports.keys():
                        if k == 'literals':
                            for port_item in real_dst_ports[k]:
                                if port_item.get('port') is not None:
                                    if port_item.get('protocol') == '6':
                                        real_port = f'TCP:{port_item.get("port")}'
                                        strict_holder.append(real_port)
                                    elif port_item.get('protocol') == '17':
                                        real_port = f'UDP:{port_item.get("port")}'
                                        strict_holder.append(real_port)
                        elif k == 'objects':
                            for obj_item in real_dst_ports[k]:
                                if obj_item.get('type') == 'ProtocolPortObject':
                                    for port_item in self.port_data:
                                        if port_item[0] == obj_item['name']:
                                            real_port = [f'{port_item[1]}:{port_item[2]}']
                                            strict_holder.append(real_port)
                                elif obj_item.get('type') == 'PortObjectGroup':
                                    for port_item in self.port_group_object:
                                        if port_item[0] == obj_item['name']:
                                            # recurvsly look through the port objects for its names and get real port mapping from the port_data
                                            for port_list_item in port_item[1]:
                                                for port_item in self.port_data:
                                                    if port_item[0] == port_list_item[0]:
                                                        real_port = [f'{port_item[1]}:{port_item[2]}']
                                                        strict_holder.append(real_port)
                    if len(strict_holder) == 1:
                        if not isinstance(next(iter(strict_holder)), list):
                            subset_rule['real_port'] = strict_holder[0]
                        else:
                            subset_rule['real_port'] = [i for i in strict_holder[0]]
                    else:
                        save_list = []
                        for i in strict_holder:
                            if isinstance(i, list):
                                for inner_i in i:
                                    save_list.append(inner_i)
                            else:
                                save_list.append(i)
                        subset_rule['real_port'] = save_list
                else:
                    subset_rule['real_port'] = None

            changed_ruleset.append(subset_rule)
        current_ruleset = changed_ruleset
        return pd.DataFrame(current_ruleset)

    def create_new_rule_name(self):
        new_rule_name = input('please enter a new rule name to use in the ruleset: ')
        self.utils.permission_check(f'are you sure you want to continue with {new_rule_name} as the rule name?')
        self.rule_prepend_name = new_rule_name

    def multi_rule_processor(self, firecheck, strict_check):
        col_name = 'policy_name'
        # err handle
        try:
            self.ippp[col_name]
        except Exception as error:
            self.logfmc.critical(f'{col_name} is not present in the IPPP..Cannot process multiple rules..')
            self.logfmc.debug(error)
            quit()

        # keep original IPPP as we cycle
        multi_rule_holder = self.ippp.copy()

        # rotate rule names
        rule_rotator = self.ippp.groupby(col_name)
        for r_name, r_rotate in tqdm(rule_rotator, desc=f'creating rules with custom rule names.', total=int(rule_rotator.ngroups), colour='YELLOW'):
            # send rules to processor
            self.ippp = r_rotate.copy()
            firecheck.ippp = self.ippp
            ruleset, acp_set = self.create_acp_rule()
            if not isinstance(ruleset,bool):
                self.deployment_verification(firecheck, ruleset, acp_set, strict_check)

        # rejoin and check for completeness
        firecheck.ippp = multi_rule_holder
        firecheck.compare_ippp_acp(strict_checkup=strict_check)

    def deployment_verification(self,firecheck_class,ruleset,acp_set,strict_check):
        # need firecheck class object process
        while True:
            # deploy rules
            successful, error_msg = self.deploy_rules(new_rules=ruleset, current_acp_rules_id=acp_set)
            if successful:
                # test rule Checkup
                firecheck_class.compare_ippp_acp(strict_checkup=strict_check)
                break
            elif 'Please enter with another name' in str(error_msg):
                self.create_new_rule_name()
            else:
                self.logfmc.critical('An error occured while processing the rules')
                raise Exception('An error occured while processing the rules')

    def policy_deployment_flow(self,checkup=False,multi_rule=False):
        # login FMC
        self.rest_connection()
        # Get zone info first via ClI
        self.zone_ip_info = self.zone_to_ip_information()
        # get network and port information via rest
        self.fmc_net_port_info()
        # pull information from ippp IF DURING STANDARD READ FROM FILE
        if not self.config_data.get('conn_events'):
            self.ippp = pd.read_csv(self.ippp_location)

        self.ippp = self.prepare_ippp(self.ippp)
        self.ippp = self.fix_port_range_objects(self.ippp)
        self.find_dup_services()
        # create FMC objects
        self.create_fmc_object_names()
        # restart conn
        self.rest_connection(reset=True)
        ffc = FireCheck(self)
        # rule check strictness
        mod_ippp = None
        if self.config_data.get('strict_checkup'):
            mod_ippp = ffc.should_strict_check()
            strict_check = True
        else:
            strict_check = False
        ffc.ippp = mod_ippp if strict_check else self.ippp
        # JUST checkup
        if checkup:
            ffc.compare_ippp_acp(strict_checkup=strict_check)
        # parse IPPP with multiple rule names
        elif multi_rule:
            self.multi_rule_processor(ffc,strict_check)
        else:
            # create FMC rules
            ruleset, acp_set = self.create_acp_rule()
            # send to implement
            self.deployment_verification(ffc,ruleset,acp_set,strict_check)

    @staticmethod
    @deprecated
    def _get_device_creds(cred_file):
        cred_file = Util().create_file_path('safe', cred_file)
        with open(cred_file, 'r') as cf:
            return json.load(cf)

    def get_device_creds(self, cred_file=None, same_cred=True):
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
