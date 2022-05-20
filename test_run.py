import pandas as pd
from ipaddress import ip_network
from datetime import datetime
from tqdm import tqdm


class TestRun:
    def __init__(self,af_class):
        self.auto_fmc = af_class

    def compare_ipp_acp(self):
        self.auto_fmc.zbr_bypass_check()
        test_ippp = self.auto_fmc.ippp[['source','destination','protocol','port']]
        for port_info in self.auto_fmc.port_data:
            port_protco = test_ippp[(test_ippp['port'] == port_info[2]) & (test_ippp['protocol'] == port_info[1])]
            if not port_protco.empty:
                test_ippp['port'].loc[(test_ippp['port'] == port_info[2]) & (test_ippp['protocol'] == port_info[1])] = port_info[0]

        acp_id = self.auto_fmc.fmc.policy.accesspolicy.get(name=self.auto_fmc.access_policy)
        acp_rules = self.auto_fmc.fmc.policy.accesspolicy.accessrule.get(container_uuid=acp_id['id'])
        acp_rules = self.auto_fmc.utils.transform_acp(acp_rules, self.auto_fmc)
        acp_rules.replace({'None': 'any'}, inplace=True)


        ruleset = []
        same_zone_counter = 0
        for i in test_ippp.index:
            rule_flow = {}
            src_flow = self.auto_fmc.get_zone_from_ip('source', i)
            dst_flow = self.auto_fmc.get_zone_from_ip('destination', i)
            # block double zone
            if src_flow["source_zone"] == dst_flow["destination_zone"]:
                same_zone_counter += 0
                continue
            rule_flow.update(src_flow)
            rule_flow.update(dst_flow)
            rule_flow.update({'port': test_ippp['port'][i] if test_ippp['port'][i] != 'any' else 'any'})
            ruleset.append(rule_flow)
        self.auto_fmc.logfmc.logger.warning(f'Dropped {same_zone_counter} rules from the IPPP which are the same zone')
        test_ippp = pd.DataFrame(ruleset)

        for col in test_ippp.columns:
            test_ippp[col] = test_ippp[col].apply(lambda x: sorted(list(v for v in x)) if isinstance(x, (tuple, list)) else x)
        for col in acp_rules.columns:
            acp_rules[col] = acp_rules[col].apply(lambda x: sorted(list(v for v in x)) if isinstance(x, (tuple, list)) else x)

        for ip in ['source_network', 'destination_network']:
            test_ippp[ip] = test_ippp[ip].apply(lambda p: self.auto_fmc.fdp_grouper(p, 'ip'))
        for ip in ['destination', 'source']:
            acp_rules[ip] = acp_rules[ip].apply(lambda p: self.auto_fmc.fdp_grouper(p, 'ip'))

        found_in_policy = []
        for ti in tqdm(test_ippp.index,desc='checking uniqueness of ruleset',colour='#FFA500',total=len(test_ippp.index)):
            match_found = 0
            for ai in acp_rules.index:
                test_rule = test_ippp.loc[ti]
                current_rule = acp_rules.loc[ai]
                cur_dst_ip = current_rule['destination']
                cur_src_ip = current_rule['source']
                cur_src_z = current_rule['src_z']
                cur_dst_z = current_rule['dst_z']
                cur_port = current_rule['port']
                cr_list = [cur_dst_ip,cur_src_ip,cur_src_z,cur_dst_z,cur_port]

                test_dst_ip = test_rule['source_network']
                test_src_ip = test_rule['destination_network']
                test_src_z = test_rule['source_zone']
                test_dst_z = test_rule['destination_zone']
                test_port = test_rule['port']

                for idx, test_item in enumerate([test_dst_ip,test_src_ip, test_src_z ,test_dst_z ,test_port]):
                    if not isinstance(test_item,list):
                        test_item = [test_item]

                    if not isinstance(cr_list[idx],list):
                        cr_item = [cr_list[idx]]
                    else:
                        cr_item = cr_list[idx]

                    breakout = False
                    for i in test_item:
                        for ci in cr_item:
                            if i == ci:
                                match_found += 1
                                breakout = True
                                break
                            elif idx in [0,1]:
                                try:
                                    # catch None types
                                    if ip_network(i).subnet_of(ip_network(ci)):
                                        match_found += 1
                                        breakout = True
                                        break
                                except:
                                    pass
                        if breakout:
                            break

            if match_found >= 5:
                found_in_policy.append(ti)
        self.auto_fmc.logfmc.logger.warning(f'Found {len(found_in_policy)} of {len(test_ippp)} from IPPP implemented in ACP')
        if len(found_in_policy) != len(test_ippp):
            dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d%H%M%S")
            not_found_rules = self.auto_fmc.utils.create_file_path(folder='404_rules',file_name=f'{self.auto_fmc.rule_prepend_name}_orphaned_rules_{dt_now}.csv')
            test_ippp.drop(found_in_policy,inplace=True)
            test_ippp.reset_index(inplace=True, drop=True)
            test_ippp.to_csv(not_found_rules, index=False)
            self.auto_fmc.logfmc.logger.warning(f'rules not found in ACP are located in {not_found_rules}')
            return False
        else:
            self.auto_fmc.logfmc.logger.warning(f'All Rules from IPPP implemented')
            return True





