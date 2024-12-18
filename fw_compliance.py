from ipaddress import ip_network
from multiprocessing import Pool, cpu_count

from fw_deploy import FireStick
from datetime import datetime
import pandas as pd
from os import getpid


class FireComply(FireStick):

    def __init__(self, configuration_data: dict, cred_file=None, generate_conn: bool = True):
        super().__init__(configuration_data=configuration_data, cred_file=cred_file)
        self.comply_dir = 'compliance_rules'
        self.dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d_%H%M")
        # placeholder if we need specific IPs
        self.specific_ips = None
        # if we need to call the actual API instead of the Web UI ( prevents error session exist...)
        if generate_conn:
            self.rest_connection()

    def gen_output_info(self, new_dir, new_file):
        output_dir = f'{self.comply_dir}/{new_dir}'
        output_file = f'{new_file}_{self.dt_now}.csv'
        return output_dir, output_file

    def export_current_policy(self):
        self.logfmc.warning('Trying to Export rule(s) from Firewall')
        output_dir = 'specific_rules' if self.config_data.get('save_specific_rules') else 'all_rules'
        output_file = f'{self.rule_prepend_name}_{self.access_policy}' if self.config_data.get('save_specific_rules') else f'{self.access_policy}'
        output_dir, output_file = self.gen_output_info(output_dir, output_file)

        def save_zone_info(x):
            for szi in self.config_data.get('specific_zones'):
                if szi in x:
                    return True
                # include any zones incase we need to further process specific IPs.
                elif x == 'any':
                    return True
                else:
                    return False

        # get specific rules
        current_ruleset = self.transform_rulesets(save_current_ruleset=True)
        if self.config_data.get('save_specific_rules'):
            current_ruleset = current_ruleset[current_ruleset['policy_name'].str.startswith(self.rule_prepend_name)]

        # get specific zones
        if self.config_data.get('specific_zones'):
            spec_zone_list = ['specific_src_zone','specific_dst_zone']
            for szl,zone in zip(spec_zone_list,['src_z','dst_z']):
                current_ruleset[szl] = current_ruleset[zone].astype(str).apply(lambda x: save_zone_info(x))

            current_ruleset = current_ruleset[current_ruleset[spec_zone_list[0]] | current_ruleset[spec_zone_list[1]]]
            current_ruleset.drop(columns=spec_zone_list,inplace=True)
            current_ruleset.reset_index(inplace=True,drop=True)

        # prettify
        if self.config_data.get('pretty_rules'):
            current_ruleset.drop(columns=['src_z', 'dst_z', 'port', 'source', 'destination'], inplace=True)
            parsed_ruleset = []
            # TRY to use n-1 physical cores ( dont want anymore imports)
            core_group = int(cpu_count()) - 1
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
            cos_specific = self.config_data.get('check_only_specific_src_dst')
            if cos_specific == 'src':
                src_spec = subset_df[subset_df['real_source'].apply(lambda x: self.find_specific_ip_needed(x)) & subset_df['real_destination'].apply(lambda x: not self.find_specific_ip_needed(x))]
                subset_df = src_spec
            elif cos_specific == 'dst':
                dst_spec = subset_df[subset_df['real_destination'].apply(lambda x: self.find_specific_ip_needed(x)) & subset_df['real_source'].apply(lambda x: not self.find_specific_ip_needed(x))]
                subset_df = dst_spec
            else:
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

    def find_specific_ip_needed(self, x):
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

    def transform_connection_events(self) -> pd.DataFrame:
        self.logfmc.warning('Trying to Transform events from Firewall to csv')
        output_dir = 'analysis/connection_events'
        output_file = f'{self.rule_prepend_name}_RAW_CE_{self.dt_now}.csv'
        output_dir, output_file = self.gen_output_info(output_dir, output_file)

        # get report HTML File
        conn_dpath = self.utils.create_file_path(folder=output_dir, file_name=self.config_data.get('connections_data'))

        # transform
        if '.html' in conn_dpath:
            conn_events = pd.read_html(conn_dpath,header=0)[0]
        else:
             conn_events = pd.read_csv(conn_dpath,header=0)
        conn_events = conn_events[conn_events['Access Control Rule'] == self.rule_prepend_name]
        if conn_events.empty:
            self.logfmc.error('NO RULES TO TRANSFORM INTO CSV')

        return conn_events

    def generate_rules_from_events(self):
        # pull data into SilverTorch
        conn_events = self.transform_connection_events()

        # make sure IPPP format is in df if not pull them from YAML
        if self.utils.standard_ippp_cols not in conn_events.columns.tolist():
            # reverse dict k,v to a usable format
            trans_lib = {value: key for key, value in self.config_data.get('event_transform_lib').items()}
            conn_events.rename(columns=trans_lib,inplace=True)
        # drop useless cols
        conn_events['comments'] = self.config_data.get('rule_comment')
        conn_events = conn_events[self.utils.standard_ippp_cols]

        # since these are con events src ports will more than likely be ephemeral
        conn_events['port_range_low'] = 'nan'

        for c in self.utils.standard_ippp_cols:
            # if dont have a value for service insert generic service name
            if 'service' in c:
                conn_events[c] = conn_events[c].astype(str).apply(lambda x: 'generic_service' if x == 'nan' else x )

        self.ippp = conn_events
        # create a new rule name for events
        self.create_new_rule_name()
        # push rules
        self.policy_deployment_flow()




