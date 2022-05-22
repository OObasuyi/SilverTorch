from datetime import datetime

from fw_deploy import FireStick
from tqdm import tqdm
import pandas as pd
import pickle
from os import replace
from fw_test import FireCheck


class FireBroom(FireStick):
    def __init__(self, fmc_host: str, ftd_host: str, access_policy: str, rule_prepend_name: str,
            zone_of_last_resort: str, same_cred=False, ruleset_type='ALLOW',domain='Global'):
        ippp_location = None
        # todo: testing
        cred_file = 'cF.json'
        super().__init__(fmc_host, ftd_host, ippp_location, access_policy, rule_prepend_name,
                         zone_of_last_resort,same_cred=same_cred, cred_file=cred_file,ruleset_type=ruleset_type,domain=domain)
        self.rest_connection()

    def rule_objects(self):
        acp_id = self.fmc.policy.accesspolicy.get(name=self.access_policy)
        acp_rules = self.fmc.policy.accesspolicy.accessrule.get(container_uuid=acp_id['id'])
        return acp_id,acp_rules

    def del_fmc_objects(self, type_, obj_type):
        """PLEASE BE AS SPECIFIC AS POSSIBLE"""
        # get the latest created objects
        self.fmc_net_port_info()
        if not isinstance(self.rule_prepend_name, str):
            raise ValueError(f'self.rule_prepend_name value is not type str. you passed an {type(self.rule_prepend_name)} object')
        self.utils.permission_check(f'Are you sure you want to delete {obj_type.upper()} ***{self.rule_prepend_name}*** {type_} objects?')
        if type_ == 'network':
            def net_delete():
                del_list = [i[2] for i in self.net_data if self.rule_prepend_name in i[0]] if self.rule_prepend_name != 'all' else [i[2] for i in self.net_data]
                for obj_id in tqdm(del_list, total=len(del_list), desc=f'deleting {obj_type} objects'):
                    try:
                        if '/' in obj_id[1]:
                            self.fmc.object.network.delete(obj_id)
                        else:
                            self.fmc.object.host.delete(obj_id)
                    except Exception as error:
                        self.logfmc.error(f'Cannot delete {obj_id} from set {obj_type} of {type_} \n received code: {error}')

            def net_port_delete():
                del_list = [i[2] for i in self.net_group_object if self.rule_prepend_name in i[0]] if self.rule_prepend_name != 'all' else [i[2] for i in self.net_group_object]
                for obj_id in tqdm(del_list, total=len(del_list), desc=f'deleting {obj_type} objects'):
                    try:
                        self.fmc.object.networkgroup.delete(obj_id)
                    except Exception as error:
                        self.logfmc.error(f'Cannot delete {obj_id} from set {obj_type} of {type_} \n received code: {error}')

            if obj_type == 'net':
                net_delete()
            elif obj_type == 'net_group':
                net_port_delete()
            elif obj_type == 'all':
                net_port_delete()
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
            acp_id,acp_rules = self.rule_objects()
            del_list = [i['name'] for i in acp_rules if self.rule_prepend_name in i['name']] if self.rule_prepend_name != 'all' else acp_rules
            for obj_id in tqdm(del_list, total=len(del_list), desc=f'deleting {self.rule_prepend_name} rules'):
                try:
                    self.fmc.policy.accesspolicy.accessrule.delete(container_uuid=acp_id['id'], name=obj_id)
                except Exception as error:
                    self.logfmc.error(f'Cannot delete {obj_id} from set {self.rule_prepend_name} for rules \n received code: {error}')
        else:
            raise NotImplementedError(f'type_ not found please select rule, port, or network. you passed {type_}')

    def collapse_fmc_rules(self,comment:str=False,recover:bool=False):
        dt_now = datetime.now().replace(microsecond=0).strftime("%Y%m%d%H%M%S")
        save_ext = 'rulbk'
        recovery_fname = f'{self.rule_prepend_name}_save_{dt_now}.{save_ext}'
        recovery_loc = self.utils.create_file_path('temp',recovery_fname)
        if not isinstance(comment,str):
            raise ValueError('COMMENT VALUE MUST BE PASSED')
        acp_id, acp_rules = self.rule_objects()
        self.fmc_net_port_info()
        if not recover:
            acp_rules = self.utils.transform_acp(acp_rules, self)
            acp_rules = acp_rules[acp_rules['policy_name'].str.startswith(self.rule_prepend_name)]
            # no rule test
            if acp_rules.empty:
                raise Exception(f'rules starting with {self.rule_prepend_name} was not found!')

        # there should only one file in this dir from last run
        if recover:
            self.logfmc.warning('entering recovery mode')
            recovery_loc = self.utils.get_files_from_dir('temp', save_ext)[0]
            with open(recovery_loc, 'rb') as save_rule:
                rollback_acp = pickle.load(save_rule)
            self.logfmc.debug(f'recovered {recovery_loc} file')
            acp_rules = rollback_acp
        else:
            # in case we fail our rule test or error happens while processing
            rollback_acp = acp_rules.copy()
            with open(recovery_loc, 'wb') as save_rule:
                pickle.dump(rollback_acp, save_rule)

        for col in acp_rules.columns:
            acp_rules[col] = acp_rules[col].apply(lambda x: tuple(v for v in x) if isinstance(x, list) else x)
        # fill in vals that are really any
        acp_rules.replace({None:'any'},inplace=True)
        # collapse FW rules by zone
        grouped_rules = acp_rules.groupby(['src_z','dst_z'])
        gpl = grouped_rules.size()[grouped_rules.size() > 0].index.values.tolist()
        collapsed_rules = []
        for grules in gpl:
            grules = grouped_rules.get_group(grules)
            # separate rules with "any" values
            grules_any = grules[(grules['source'] == 'any') | (grules['destination'] == 'any') | (grules['port'] == 'any')]
            grules = grules[(grules['source'] != 'any') & (grules['destination'] != 'any') & (grules['port'] != 'any')]
            for sep_rules in [grules_any,grules]:
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
        for rule_pd in [collapsed_rules,acp_rules]:
            for col in rule_pd.columns:
                rule_pd[col] = rule_pd[col].apply(lambda x: list(v for v in x) if isinstance(x, tuple) else x)

        collapsed_rules.rename(columns={'src_z':'source_zone','dst_z':'destination_zone'},inplace=True)
        collapsed_rules.drop(columns=['policy_name','source','destination'],inplace=True)
        if comment:
            collapsed_rules['comment'] = comment
        # Delete old rules
        self.del_fmc_objects(type_='rule',obj_type='all')
        # send new rules
        self.deploy_rules(collapsed_rules,acp_id)
        # test if deploy matches original
        self.ippp = acp_rules.copy()
        self.ippp.rename(columns={'src_z': 'source_zone', 'dst_z': 'destination_zone', 'source': 'source_network', 'destination': 'destination_network'}, inplace=True)
        rules_present = FireCheck(self).compare_ippp_acp(fix_ippp=False)
        if not rules_present:
            self.logfmc.critical('UNROLLED RULES NOT PRESENT IN COLLAPSED RULE SET. ROLLING BACK!')
            # delete collapsed wrong rules
            self.del_fmc_objects(type_='rule', obj_type='all')
            # reinstall old ones
            self.rollback_acp_op(acp_rules, acp_id, comment=comment)
        else:
            self.del_fmc_objects(type_='port',obj_type='all')
            self.del_fmc_objects(type_='network',obj_type='all')
            self.logfmc.warning(f'completed firewall cleanup for ***{self.rule_prepend_name}***')
        # move old temp to archive
        archive_dir = self.utils.create_file_path('archive', recovery_fname)
        replace(recovery_loc,archive_dir)

    def rollback_acp_op(self,rollback_pd,acp_id,comment:str=False):
        rollback_pd.rename(columns={'src_z': 'source_zone', 'dst_z': 'destination_zone','source': 'source_network', 'destination': 'destination_network'}, inplace=True)
        rollback_pd.drop(columns=['policy_name'], inplace=True)
        if comment:
            rollback_pd['comment'] = comment
        self.deploy_rules(rollback_pd, acp_id)


if __name__ == "__main__":
    weeper = FireBroom(access_policy='test12', ftd_host='10.11.6.191', fmc_host='10.11.6.60', rule_prepend_name='test_st_beta_1', zone_of_last_resort='outside_zone')
    weeper.collapse_fmc_rules(comment='tester123')
    # augWork.del_fmc_objects(type_='port',obj_type='all')
    # augWork.del_fmc_objects(type_='network',,obj_type='all')
    # augWork.del_fmc_objects(type_='network',obj_type='all')
