from datetime import datetime
from re import split, match,sub

from fw_deploy import FireStick
from tqdm import tqdm
import pandas as pd
import pickle
from os import replace
from fw_test import FireCheck

class FireBroom(FireStick):
    def __init__(self, configuration_data: dict, cred_file=None):
        super().__init__(configuration_data=configuration_data, cred_file=cred_file)
        self.rest_connection()
        self.temp_dir = 'temp_rules'
        self.dt_now = datetime.now().replace(microsecond=0).strftime("%Y_%m_%d_%H%_M%_S")
        self.save_ext = 'rulbk'

    def is_prepend_naming_correct(self,name_of_obj):
        # check if it's a exact name match of the group
        name_check = split(r'[^a-zA-Z0-9\s]', name_of_obj)
        # # UC1: name kinda similar
        # if self.rule_prepend_name != name_check[0]:
        #     return False

        try:
            # UC1: name kinda similar
            # UC2: if its anything other than our naming that follows then dont use.
            if 'NetGroup' in name_check or ('net' and 'group' in  name_check):
                if match(f'^{self.rule_prepend_name}', name_of_obj).group() == self.rule_prepend_name:
                    return True
            else:
                return False
        except Exception as error:
            self.logfmc.debug(error)

        if self.rule_prepend_name == name_check[0]:
            return True
        else:
            return False

    def del_fmc_objects(self, type_, obj_type):
        """PLEASE BE AS SPECIFIC AS POSSIBLE"""
        # get the latest created objects
        self.fmc_net_port_info()
        if not isinstance(self.rule_prepend_name, str):
            raise ValueError(f'self.rule_prepend_name value is not type str. you passed an {type(self.rule_prepend_name)} object')
        normalize_str = sub('[^A-Za-z0-9|\-|_]+',' ', str(obj_type).upper())
        self.utils.permission_check(f'Are you sure you want to delete {normalize_str} ***{self.rule_prepend_name}*** {type_} objects?')
        if type_ == 'network':
            def net_delete():
                del_list = [i[2] for i in self.net_data if self.is_prepend_naming_correct(i[0])] if self.rule_prepend_name != 'all' else [i[2] for i in self.net_data]
                for obj_id in tqdm(del_list, total=len(del_list), desc=f'deleting {obj_type} objects'):
                    try:
                        if '/' in obj_id[1]:
                            self.fmc.object.network.delete(obj_id)
                        else:
                            self.fmc.object.host.delete(obj_id)
                    except Exception as error:
                        self.logfmc.error(f'Cannot delete {obj_id} from set {obj_type} of {type_} \n received code: {error}')

            def net_group_delete():
                del_list = [i[2] for i in self.net_group_object if self.is_prepend_naming_correct(i[0])] if self.rule_prepend_name != 'all' else [i[2] for i in self.net_group_object]
                for obj_id in tqdm(del_list, total=len(del_list), desc=f'deleting {obj_type} objects'):
                    try:
                        self.fmc.object.networkgroup.delete(obj_id)
                    except Exception as error:
                        self.logfmc.error(f'Cannot delete {obj_id} from set {obj_type} of {type_} \n received code: {error}')

            if obj_type == 'net':
                net_delete()
            elif obj_type == 'net_group':
                net_group_delete()
            elif obj_type == 'all':
                net_group_delete()
                net_delete()

        elif type_ == 'port':
            def del_port():
                del_list = [i[3] for i in self.port_data if self.rule_prepend_name in i[0]] if self.rule_prepend_name != 'all' else [i[3] for i in self.port_data]
                for obj_id in tqdm(del_list, total=len(del_list), desc=f'deleting {obj_type} objects'):
                    try:
                        self.fmc.object.protocolportobject.delete(obj_id)
                    except Exception as error:
                        self.logfmc.error(f'Cannot delete {obj_id} from set {obj_type} of {type_} \n received code: {error}')

            def del_port_group():
                del_list = [i[2] for i in self.port_group_object if self.rule_prepend_name in i[0]] if self.rule_prepend_name != 'all' else [i[2] for i in self.port_group_object]
                for obj_id in tqdm(del_list, total=len(del_list), desc=f'deleting {obj_type} objects'):
                    try:
                        self.fmc.object.portobjectgroup.delete(obj_id)
                    except Exception as error:
                        self.logfmc.error(f'Cannot delete {obj_id} from set {obj_type} of {type_} \n received code: {error}')

            if obj_type == 'port':
                del_port()
            elif obj_type == 'port_group':
                del_port_group()
            elif obj_type == 'all':
                del_port_group()
                del_port()

        elif type_ == 'rule':
            acp_id, acp_rules = self.retrieve_rule_objects()

            # check if we need to delete rules BEFORE a certain comment date
            if self.config_data.get('bestby_date'):
                for i in acp_rules:
                    if i.get('commentHistoryList'):
                        stored_dates = []
                        for comments_item in i.get('commentHistoryList'):
                            dt_obj = datetime.strptime(comments_item['date'].split('T')[0],'%Y-%M-%D')
                            stored_dates.append(dt_obj)
                        # get the most recent comment date
                        recent_date = max(stored_dates)
                    else:
                        # if there is no comment well have to leave the rule alone for now
                        recent_date = datetime.now().date()

                    # if we are past the best by then we should not keep
                    if recent_date > self.config_data.get('bestby_date'):
                        i['del_safe'] = True
                    else:
                        i['del_safe'] = False

            # new ruleset if we are going by bestby date
            if self.config_data.get('bestby_date'):
                fw_rules = [i for i in acp_rules if i['del_safe']]
            else:
                fw_rules = acp_rules

            # collect rules that need to deleted
            if isinstance(obj_type,str):
                obj_type = obj_type.lower()
                # deleting via kwrd rule name or 'all'
                del_list = [i['name'] for i in fw_rules if self.rule_prepend_name in i['name']] if obj_type != 'all' else fw_rules
            else:
                # deleting via passed list object
                # make sure rules exist in ruleset
                del_list = [i['name'] for i in fw_rules if i['name'] in obj_type]

            for obj_id in tqdm(del_list, total=len(del_list), desc=f'deleting {self.rule_prepend_name} rules'):
                try:
                    self.fmc.policy.accesspolicy.accessrule.delete(container_uuid=acp_id, name=obj_id)
                except Exception as error:
                    self.logfmc.error(f'Cannot delete {obj_id} from set {self.rule_prepend_name} for rules \n received code: {error}')
        else:
            raise ValueError(f'type_ not found please select rule, port, or network. you passed {type_}')

    @staticmethod
    def backup_rules_op(acp_rules,recovery_loc):
        rollback_acp = acp_rules.copy()
        with open(recovery_loc, 'wb') as save_rule:
            pickle.dump(rollback_acp, save_rule)

    def prep_and_recover_fw_rules(self, recover: bool = False):
        recovery_fname = f'{self.rule_prepend_name}_save_{self.dt_now}.{self.save_ext}'
        recovery_loc = self.utils.create_file_path(self.temp_dir, recovery_fname)

        acp_id, acp_rules = self.retrieve_rule_objects()
        self.fmc_net_port_info()
        if not recover:
            acp_rules = self.transform_acp(acp_rules)
            acp_rules = acp_rules[acp_rules['policy_name'].str.startswith(self.rule_prepend_name)]
            # no rule test
            if acp_rules.empty:
                raise Exception(f'rules starting with {self.rule_prepend_name} was not found!')

        # there should only one file in this dir from last run
        if recover:
            self.logfmc.warning('entering recovery mode')
            recovery_loc = self.utils.get_files_from_dir(self.temp_dir, self.save_ext)[0]
            with open(recovery_loc, 'rb') as save_rule:
                rollback_acp = pickle.load(save_rule)
            self.logfmc.debug(f'recovered {recovery_loc} file')
            acp_rules = rollback_acp
            # todo: need to let the user chose if they want to optimze the config are just insert the old config from the recover file
        else:
            # in case we fail our rule test or error happens while processing
            self.backup_rules_op(acp_rules,recovery_loc)

        for col in acp_rules.columns:
            acp_rules[col] = acp_rules[col].apply(lambda x: tuple(v for v in x) if isinstance(x, list) else x)
            # fill in vals that are really any
        acp_rules.replace({None: 'any'}, inplace=True)

        return acp_rules,acp_id,recovery_fname,recovery_loc

    def collapse_fw_rules(self, comment: str = False, recover: bool = False):
        if not isinstance(comment, str):
            raise ValueError('COMMENT VALUE MUST BE PASSED')
        # DRP the fw rules
        acp_rules,acp_id,recovery_fname,recovery_loc = self.prep_and_recover_fw_rules(recover)

        # collapse FW rules by zone
        grouped_rules = acp_rules.groupby(['src_z', 'dst_z'])
        gpl = grouped_rules.size()[grouped_rules.size() > 0].index.values.tolist()
        collapsed_rules = []
        for grules in gpl:
            grules = grouped_rules.get_group(grules)
            # separate rules with "any" values
            grules_any = grules[(grules['source'] == 'any') | (grules['destination'] == 'any') | (grules['port'] == 'any')]
            grules = grules[(grules['source'] != 'any') & (grules['destination'] != 'any') & (grules['port'] != 'any')]
            for sep_rules in [grules_any, grules]:
                if not sep_rules.empty:
                    # group frame attributes
                    agg_src_net = []
                    for i in sep_rules['source'].tolist():
                        if isinstance(i, (list, tuple)):
                            for itr in i:
                                agg_src_net.append(itr)
                        else:
                            agg_src_net.append(i)
                    agg_dst_net = []
                    for i in sep_rules['destination'].tolist():
                        if isinstance(i, (list, tuple)):
                            for itr in i:
                                agg_dst_net.append(itr)
                        else:
                            agg_dst_net.append(i)
                    agg_port = []
                    for i in sep_rules['port'].tolist():
                        if isinstance(i, (list, tuple)):
                            for itr in i:
                                agg_port.append(itr)
                        else:
                            agg_port.append(i)
                    agg_src_net = sorted(list(set(agg_src_net)))
                    agg_dst_net = sorted(list(set(agg_dst_net)))
                    agg_port = sorted(list(set(agg_port)))
                    group = sep_rules.iloc[0]
                    # dont take list items if the list only has 1 element
                    group['source_network'] = agg_src_net if len(agg_src_net) > 1 else agg_src_net[0]
                    group['destination_network'] = agg_dst_net if len(agg_dst_net) > 1 else agg_dst_net[0]
                    group['port'] = agg_port if len(agg_port) > 1 else agg_port[0]
                    collapsed_rules.append(group.to_dict())
        collapsed_rules = pd.DataFrame(collapsed_rules)
        # remove tuples from multi-zoned rows
        for rule_pd in [collapsed_rules, acp_rules]:
            for col in rule_pd.columns:
                rule_pd[col] = rule_pd[col].apply(lambda x: list(v for v in x) if isinstance(x, tuple) else x)

        collapsed_rules.rename(columns={'src_z': 'source_zone', 'dst_z': 'destination_zone'}, inplace=True)
        collapsed_rules.drop(columns=['policy_name', 'source', 'destination'], inplace=True)
        if comment:
            collapsed_rules['comment'] = comment

        # stop processing if the specified ruleset cant get any smaller
        if len(collapsed_rules) == len(acp_rules):
            self.logfmc.error(f'Cannot optimize rule set for {self.rule_prepend_name} as its already optimized')
            # move old temp to archive
            archive_dir = self.utils.create_file_path('archive', recovery_fname)
            replace(recovery_loc, archive_dir)
            return

        # Delete old rules
        self.del_fmc_objects(type_='rule', obj_type='all')
        # send new rules
        success,_ = self.deploy_rules(collapsed_rules, acp_id)
        if not success:
            self.logfmc.critical('Couldnt push new configs. Rolling Back!')
            self.rollback_acp_op(acp_rules, acp_id, comment=comment)
            # move old temp to archive
            archive_dir = self.utils.create_file_path('archive', recovery_fname)
            replace(recovery_loc, archive_dir)
            return

        # test if deploy matches original
        fcheck = FireCheck(self)
        self.ippp = acp_rules.copy()
        self.ippp.rename(columns={'src_z': 'source_zone', 'dst_z': 'destination_zone', 'source': 'source_network', 'destination': 'destination_network'}, inplace=True)
        fcheck.ippp = self.ippp
        rules_present = fcheck.compare_ippp_acp(fix_ippp=False)
        if not rules_present:
            self.logfmc.critical('UNROLLED RULES NOT PRESENT IN COLLAPSED RULE SET. ROLLING BACK!')
            # delete collapsed wrong rules
            self.del_fmc_objects(type_='rule', obj_type='all')
            # reinstall old ones
            self.rollback_acp_op(acp_rules, acp_id, comment=comment)
        else:
            self.del_fmc_objects(type_='port', obj_type='all')
            self.del_fmc_objects(type_='network', obj_type='all')
            self.logfmc.warning(f'completed firewall cleanup for ***{self.rule_prepend_name}***')
        # move old temp to archive
        archive_dir = self.utils.create_file_path('archive', recovery_fname)
        replace(recovery_loc, archive_dir)

    def clean_object_store(self, clean_type):
        self.fmc_net_port_info()

        if clean_type == 'resolve':
            # delete unused
            if self.config_data.get('remove_unused'):
                self.del_fmc_objects(type_='network', obj_type='net')
                self.fmc_net_port_info()

            objects_ = [tuple([str(x['name']), str(x['value']), str(x['id'])]) for x in self.fmc.object.host.get()]
            for obj in tqdm(objects_, total=len(objects_), desc=f'updating {clean_type} for objects'):
                obj_ip = obj[1]
                try:
                    new_name = self.retrieve_hostname(obj_ip)
                    if new_name != obj_ip:
                        # update_objects.append({'name': new_name, 'value': obj[1],'id':obj[2]})
                        update_obj = {'name': new_name, 'value': obj[1], 'id': obj[2]}
                        self.fmc.object.host.update(update_obj)
                except Exception as error:
                    self.logfmc.debug(error)
                    continue

        elif clean_type == 'group':
            new_name = self.config_data.get('group_clean_name') if self.config_data.get('group_clean_name') else '_NetGroup_'
            # delete unused
            if self.config_data.get('remove_unused'):
                self.del_fmc_objects(type_='network',obj_type='net_group')
                self.fmc_net_port_info()

            target_change_list = []
            # get objects that need to be changed
            for ngo in self.net_group_object:
                name_of_group = ngo[0]
                if self.rule_prepend_name in name_of_group:
                    correct_name = self.is_prepend_naming_correct(name_of_group)
                    if not correct_name:
                        continue

                    if new_name not in name_of_group:
                        target_change_list.append(ngo)
            # change the name based on if this is the default or not
            whole_name_change = False if new_name == '_NetGroup_' else True
            counter = 0
            for grouped_obj in tqdm(target_change_list, total=len(target_change_list), desc=f'updating {clean_type} objects name'):
                existing_obj = self.fmc.object.networkgroup.get(grouped_obj[2])
                # error looper
                while True:
                    try:
                        repl_name = f"{self.rule_prepend_name}{new_name}{counter + 1}" if not whole_name_change else f"{new_name}_NetGroup_{counter + 1}"
                        existing_obj['name'] = repl_name
                        self.fmc.object.networkgroup.update(existing_obj)
                        counter += 1
                        break
                    except Exception as error:
                        self.logfmc.error(error)
                        # if the name exist already. up the counter and try again
                        if 'already exists' in str(error):
                            counter += 1
                        else:
                            raise NotImplementedError('grouped cleaned issue')

    def remove_non_hit_rules(self):
        if not self.config_data.get('delete_unused_rules'):
            self.logfmc.error('NO HITCOUNT CSV TO ANALYZE')
            return
        else:
            file_name = self.config_data.get('delete_unused_rules')

        # open hitcount CSV
        fname = self.utils.create_file_path('archive/non_hit_rules',file_name)
        non_hit_rules = pd.read_csv(fname)

        # make sure all hit counts are 0
        non_hit_rules_names = non_hit_rules['Rule Name'][non_hit_rules["Hit Count"] == 0].tolist()

        # send rules for deletion
        self.del_fmc_objects(type_='rule',obj_type=non_hit_rules_names)

    def combine_acp_ruleset(self):
        com_rules = self.config_data.get('combine_ruleset')
        comment = self.config_data.get('rule_comment') if isinstance(self.config_data.get('rule_comment'),str) else 'NONE'
        new_rule_landing = self.config_data.get('access_policy')

        # checker
        if isinstance(com_rules,list):
            if len(com_rules) != 2 or not new_rule_landing:
                self.logfmc.error('Please only use two ACPs for comparison')
                return
        elif not com_rules:
            self.logfmc.error('NO rules in compare list')
            return

        # ETL rulesets
        self.fmc_net_port_info()
        _, com_rule_1 = self.retrieve_rule_objects(get_diff_access_pol=com_rules[0])
        _, com_rule_2 = self.retrieve_rule_objects(get_diff_access_pol=com_rules[1])
        com_rule_1 = self.transform_acp(com_rule_1)
        com_rule_2 = self.transform_acp(com_rule_2)

        # combine all row data to a str and create hashes for every row
        com_rule_1['rule_HiD'] = com_rule_1.apply(lambda x:  self.utils.create_hash(x.astype(str).str.cat()), axis=1)
        com_rule_2['rule_HiD'] = com_rule_2.apply(lambda x:  self.utils.create_hash(x.astype(str).str.cat()), axis=1)

        # drop dup rules
        combined_rules = pd.concat([com_rule_1, com_rule_2])
        combined_rules.drop_duplicates(subset=['rule_HiD'],inplace=True,ignore_index=True)

        # transform rules to ACP
        nrl_id, _ = self.retrieve_rule_objects(get_diff_access_pol=new_rule_landing)
        combined_rules = combined_rules[combined_rules['action'].str.upper() == self.config_data.get('ruleset_type')]
        combined_rules.drop(columns=['real_port', 'action','rule_HiD'],inplace=True)
        combined_rules.rename(columns={'src_z':'source_zone',"dst_z":'destination_zone','source':'source_network','destination':"destination_network"},inplace=True)
        combined_rules['comment'] = comment
        combined_rules.fillna('any',inplace=True)

        # using chatGPT for this part..its getting late and running out of LAB time
        duplicates = combined_rules.duplicated(subset='policy_name', keep=False)
        counter = combined_rules[duplicates].groupby('policy_name').cumcount() + 1
        combined_rules.loc[duplicates, 'policy_name'] = combined_rules.loc[duplicates, 'policy_name'].astype(str) + '_' +counter.astype(str)

        # deploy rules to FW
        self.deploy_rules(new_rules=combined_rules, current_acp_rules_id=nrl_id)
        fcheck = FireCheck(self)
        fcheck.ippp = combined_rules.copy()
        fcheck.compare_ippp_acp(fix_ippp=False)

    def rollback_acp_op(self, rollback_pd, acp_id, comment: str = False):
        rollback_pd.rename(columns={'src_z': 'source_zone', 'dst_z': 'destination_zone', 'source': 'source_network', 'destination': 'destination_network'}, inplace=True)
        rollback_pd.drop(columns=['policy_name'], inplace=True)
        if comment:
            rollback_pd['comment'] = comment
        self.deploy_rules(rollback_pd, acp_id)
