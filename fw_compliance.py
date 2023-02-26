from ipaddress import ip_network
from multiprocessing import Pool, cpu_count

from fw_deploy import FireStick
from datetime import datetime
import pandas as pd
from os import getpid


class FireComply(FireStick):

    def __init__(self, configuration_data: dict, cred_file=None):
        super().__init__(configuration_data=configuration_data, cred_file=cred_file)
        self.rest_connection()
        self.comply_dir = 'compliance_rules'
        self.dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d_%H%M")
        # placeholder if we need specific IPs
        self.specific_ips = None

    def export_current_policy(self):
        self.logfmc.warning('Trying to Export rule(s) from Firewall')
        output_dir = f'{self.comply_dir}/specific_rules' if self.config_data.get('save_specific_rules') else f'{self.comply_dir}/all_rules'
        output_file = f'{self.rule_prepend_name}_{self.access_policy}_{self.dt_now}.csv' if self.config_data.get('save_specific_rules') else f'{self.access_policy}_{self.dt_now}.csv'

        # get rules
        current_ruleset = self.transform_rulesets(save_current_ruleset=True)
        if self.config_data.get('save_specific_rules'):
            current_ruleset = current_ruleset[current_ruleset['policy_name'].str.startswith(self.rule_prepend_name)]

        # prettify
        if self.config_data.get('pretty_rules'):
            current_ruleset.drop(columns=['src_z', 'dst_z', 'port', 'source', 'destination'], inplace=True)
            parsed_ruleset = []
            # TRY to use n-1 physical cores ( dont want anymore imports)
            core_group = int((cpu_count() / 2)) - 1
            core_group = core_group if core_group > 0 else 1
            pool = Pool(core_group)

            # internal func to collect subset_df
            def rule_gatherer_callback(data):
                if not data.empty:
                    parsed_ruleset.append(data)
                    return parsed_ruleset

            def log_func_error(error):
                self.logfmc.error(error)

            current_ruleset.reset_index(inplace=True, drop=True)
            # break list elm into cells
            for cr_i in current_ruleset.index:
                pool.apply_async(self.rule_spool, args=(cr_i, current_ruleset,), callback=rule_gatherer_callback, error_callback=log_func_error)
            pool.close()
            pool.join()

            # combine dfs into one
            parsed_ruleset = pd.concat(parsed_ruleset, ignore_index=True)

            # save rule to disk in CSV format
            output_dir = f'{output_dir}/pretty'
            save_name = self.utils.create_file_path(output_dir, output_file)
            parsed_ruleset.to_csv(save_name, index=False)
            self.logfmc.warning(f'Current Rules saved to {save_name}')
            return

        # RAW output
        save_name = self.utils.create_file_path(output_dir, output_file)
        current_ruleset.to_csv(save_name, index=False)

    def rule_spool(self, idx, current_ruleset):
        self.logfmc.debug(f'spawning new process for rule_spool on {getpid()}')

        rule_loc = current_ruleset.iloc[idx]
        collasped_rule = [rule_loc.to_dict()]
        # useed to stop loop this is amount of columns to make pass on to make sure we unravel them all
        iter_stop = rule_loc.shape[0]
        # open rules up
        collsaped_collector = []
        while 0 < iter_stop:
            for rule_item in collasped_rule:
                for k, v in rule_item.items():
                    if isinstance(v, list):
                        for i in v:
                            # make a copy for editing
                            expanded_rule = rule_item.copy()
                            expanded_rule[k] = i
                            # dont double add
                            if expanded_rule not in collsaped_collector:
                                collsaped_collector.append(expanded_rule)
                # check if rule item is not a list and if hasent been seen in the col list
                if rule_item not in collsaped_collector and len(collsaped_collector) != 0:
                    collsaped_collector.append(rule_item)

            # test if we still have list in our df
            collasped_rule = collsaped_collector + collasped_rule
            iter_stop -= 1

        subset_df = pd.DataFrame(collasped_rule)
        # remove list items
        for col in subset_df.columns:
            subset_df[col] = subset_df[col][subset_df[col].apply(lambda x: not isinstance(x, list))]
        subset_df.dropna(inplace=True)

        # if we need rules just for specific IPs
        specific_ips = self.config_data.get('specific_src_dst')

        if specific_ips:
            # check if IPs dont have host bit set
            self.specific_ips = [ip_network(sips) for sips in specific_ips if self.ip_address_check(sips)]
            src_spec = subset_df[subset_df['real_source'].apply(lambda x: self.find_specific_ip_needed(x)) & subset_df['real_destination'].apply(lambda x: not self.find_specific_ip_needed(x))]
            dst_spec = subset_df[subset_df['real_destination'].apply(lambda x: self.find_specific_ip_needed(x)) & subset_df['real_source'].apply(lambda x: not self.find_specific_ip_needed(x))]
            subset_df = pd.concat([src_spec, dst_spec], ignore_index=True)
            subset_df.dropna(inplace=True)

        # need to get the port name, so we can match what we have listed in the FW
        port_data = pd.DataFrame(self.port_data)
        port_data['port_val'] = port_data[1].astype(str) + ":" + port_data[2].astype(str)

        # port lookup
        subset_df['port name'] = subset_df['real_port'].apply(lambda x: port_data[0][port_data['port_val'] == x].iloc[0])

        # adjust port cols and rename
        subset_df['protocol'] = subset_df['real_port'].apply(lambda x: x.split(':')[0])
        subset_df['low port range'] = subset_df['real_port'].apply(lambda x: x.split(':')[1].split('-')[0] if x != 'any' else x)
        subset_df['high port range'] = subset_df['real_port'].apply(lambda x: x.split(':')[1].split('-')[-1] if x != 'any' else x)
        subset_df.drop(columns=['real_port'], inplace=True)
        subset_df.rename(columns={'real_source': 'source', 'real_destination': 'destination'}, inplace=True)
        return subset_df

    def find_specific_ip_needed(self,x):
        # catch any
        try:
            x = ip_network(x)
        except ValueError as verror:
            self.logfmc.debug(verror)
            return False

        for sub_ip in self.specific_ips:
            if x.subnet_of(sub_ip):
                return True

        return False
