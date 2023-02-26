import pandas as pd
from ipaddress import ip_network
from datetime import datetime
from tqdm import tqdm


class FireCheck:

    def __init__(self,af_class):
        self.fire_class = af_class
        self.logfmc = self.fire_class.logfmc
        # holder IPPP will get changed by called
        self.ippp = None

    def should_strict_check(self):
        literal_ippp = self.fire_class.ippp.copy()
        literal_ippp['port'] = literal_ippp['protocol'] + ':' + literal_ippp['port']
        return literal_ippp

    def _fix_ippp_data(self):
        # todo: need to grab ports if already in device and sub them out incase its incorrect on the ippp
        self.fire_class.zbr_bypass_check()
        test_ippp = self.ippp[['source', 'destination', 'protocol', 'port']]
        for port_info in self.fire_class.port_data:
            port_protco = test_ippp[(test_ippp['port'] == port_info[2]) & (test_ippp['protocol'] == port_info[1])]
            if not port_protco.empty:
                test_ippp['port'].loc[(test_ippp['port'] == port_info[2]) & (test_ippp['protocol'] == port_info[1])] = port_info[0]
        ruleset = []
        same_zone_counter = 0
        for i in test_ippp.index:
            rule_flow = {}
            src_flow = self.fire_class.get_zone_from_ip('source', i)
            dst_flow = self.fire_class.get_zone_from_ip('destination', i)
            # block double zone
            if src_flow["source_zone"] == dst_flow["destination_zone"]:
                same_zone_counter += 1
                continue
            rule_flow.update(src_flow)
            rule_flow.update(dst_flow)
            rule_flow.update({'port': test_ippp['port'][i] if test_ippp['port'][i] != 'any' else 'any'})

            ruleset.append(rule_flow)
        self.logfmc.warning(f'Dropped {same_zone_counter} rules from the IPPP which are the same zone')
        test_ippp = pd.DataFrame(ruleset)
        return test_ippp
    
    def compare_ippp_acp(self,fix_ippp=True,strict_checkup=False):
        if fix_ippp:
            test_ippp = self._fix_ippp_data()
        else:
            test_ippp = self.ippp

        acp_id = self.fire_class.fmc.policy.accesspolicy.get(name=self.fire_class.access_policy)
        acp_rules = self.fire_class.fmc.policy.accesspolicy.accessrule.get(container_uuid=acp_id['id'])
        acp_rules = self.fire_class.transform_acp(acp_rules)
        for col in test_ippp.columns:
            test_ippp[col] = test_ippp[col].apply(lambda x: sorted(list(v for v in x)) if isinstance(x, (tuple, list)) else x)
        for col in acp_rules.columns:
            acp_rules[col] = acp_rules[col].apply(lambda x: sorted(list(v for v in x)) if isinstance(x, (tuple, list)) else x)

        for ip in ['source_network', 'destination_network']:
            test_ippp[ip] = test_ippp[ip].apply(lambda p: self.fire_class.fdp_grouper(p, 'ip'))
        for ip in ['destination', 'source']:
            acp_rules[ip] = acp_rules[ip].apply(lambda p: self.fire_class.fdp_grouper(p, 'ip'))

        acp_rules.replace({None: 'any'}, inplace=True)
        test_ippp.replace({None: 'any'}, inplace=True)
        found_in_policy = []
        for ti in tqdm(test_ippp.index,desc='checking uniqueness of ruleset',colour='#FFA500',total=len(test_ippp.index)):
            for ai in acp_rules.index:
                match_found = 0
                test_rule = test_ippp.loc[ti]
                current_rule = acp_rules.loc[ai]
                cur_dst_ip = current_rule['destination']
                cur_src_ip = current_rule['source']
                cur_src_z = current_rule['src_z']
                cur_dst_z = current_rule['dst_z']
                if strict_checkup:
                    cur_port = current_rule['real_port']
                else:
                    cur_port = current_rule['port']
                cr_list = [cur_dst_ip,cur_src_ip,cur_src_z,cur_dst_z,cur_port]

                test_dst_ip = test_rule['destination_network']
                test_src_ip = test_rule['source_network']
                test_src_z = test_rule['source_zone']
                test_dst_z = test_rule['destination_zone']
                test_port = test_rule['port']

                for idx, test_item in enumerate([test_dst_ip,test_src_ip, test_src_z ,test_dst_z,test_port]):
                    if not isinstance(test_item,list):
                        test_item = [test_item]

                    if not isinstance(cr_list[idx],list):
                        cr_item = [cr_list[idx]]
                    else:
                        cr_item = cr_list[idx]

                    breakout = False
                    sub_match_found = 0
                    for i in test_item:
                        for ci in cr_item:
                            if fix_ippp:
                                if idx in [0,1]:
                                    # try to catch 'any'
                                    if i == ci:
                                        match_found += 1
                                        breakout = True
                                        break
                                    try:
                                        # catch None types
                                        if ip_network(i).subnet_of(ip_network(ci)):
                                            match_found += 1
                                            breakout = True
                                            break
                                    except Exception as error:
                                        if ci == 'any':
                                            match_found += 1
                                        self.logfmc.debug(error)

                                elif i == ci:
                                    match_found += 1
                                    breakout = True
                                    break
                            else:
                                # non ippps like flow
                                if idx in [0, 1]:
                                    if i == ci:
                                        sub_match_found += 1
                                        break
                                    try:
                                        # catch None types
                                        if ip_network(i).subnet_of(ip_network(ci)):
                                            sub_match_found +=1
                                            break
                                    except Exception as error:
                                        if ci == 'any':
                                            sub_match_found += 1
                                        self.logfmc.debug(error)
                                elif i == ci:
                                    sub_match_found += 1
                                    break
                        if breakout:
                            break
                    if not fix_ippp:
                        if sub_match_found == len(test_item):
                            match_found += 1

                if match_found >= 5:
                    found_in_policy.append(ti)
        self.logfmc.warning(f'Found {len(found_in_policy) if len(found_in_policy) <= len(test_ippp) else len(test_ippp)} of {len(test_ippp)} from IPPP implemented in ACP')
        # gather rules not seen in ACP from IPPP
        #  there might be a case where found_in_policy > test_ippp due to possible "any" redundant or preempt rules in the ACP.
        #  such as RULE1: x.x.x.1 > x.x.x.2 over 9000 and RULE2: any > x.x.x.2 over 9000 with the same other info would cause this to happen
        if len(found_in_policy) < len(test_ippp):
            dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d%H%M%S")
            not_found_rules = self.fire_class.utils.create_file_path(folder='404_rules', file_name=f'{self.fire_class.rule_prepend_name}_orphaned_rules_{dt_now}.csv')
            test_ippp.drop(found_in_policy,inplace=True)
            test_ippp.reset_index(inplace=True, drop=True)
            test_ippp.to_csv(not_found_rules, index=False)
            self.logfmc.warning(f'rules not found in ACP are located in {not_found_rules}')
            return False
        else:
            self.logfmc.warning(f'All Rules from IPPP implemented')
            return True







