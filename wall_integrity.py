from fw_deploy import FireStick
from fw_test import FireCheck
import pandas as pd


class FireDetector(FireStick):
    def __init__(self, fmc_host: str, ftd_host: str, ippp_location, access_policy: str, rule_prepend_name: str, zone_of_last_resort: str, **kwargs):
        super().__init__(fmc_host, ftd_host, ippp_location, access_policy, rule_prepend_name, zone_of_last_resort, **kwargs)

    def policy_deployment_flow(self, checkup=False):
        # login FMC
        self.rest_connection()
        # Get zone info first via ClI
        self.zone_ip_info = self.zone_to_ip_information()
        # test_run
        if 'man_test_zones' in self.pass_thru_commands and self.pass_thru_commands.get('man_test_zones'):
            self.zone_ip_info = pd.read_csv('temp_zii.csv')
        # get network and port information via rest
        self.fmc_net_port_info()
        # pull information from ippp
        self.ippp = self.retrieve_ippp()
        self.fix_port_range_objects()
        if not checkup:
            # check ippp service values for uniqueness
            self.find_dup_services()
        # create FMC objects
        self.create_fmc_object_names()
        # restart conn
        self.rest_connection(reset=True)
        ffc = FireCheck(self)
        if checkup:
            if 'strict_checkup' in self.pass_thru_commands and self.pass_thru_commands.get('strict_checkup'):
                literal_ippp = self.ippp.copy()
                literal_ippp['port'] = literal_ippp['protocol'] + ':' + literal_ippp['port']
                self.ippp = literal_ippp
                ffc.compare_ippp_acp(strict_checkup=True)
            else:
                ffc.compare_ippp_acp()
        else:
            # create FMC rules
            ruleset, acp_set = self.create_acp_rule()
            # deploy rules
            successful = self.deploy_rules(new_rules=ruleset, current_acp_rules_id=acp_set)
            if successful:
                # test rule Checkup
                ffc.compare_ippp_acp()
            else:
                raise Exception('An error occured while processing the rules')


if __name__ == "__main__":
    augWork = FireDetector(ippp_location='gfrs.csv', access_policy='test12', ftd_host='10.11.6.191', fmc_host='10.11.6.60',
                           rule_prepend_name='test_st_beta_2', zone_of_last_resort='outside_zone', same_cred=False, cred_file='cF.json',
                           strict_checkup=True,dont_include_domain='apple')
    augWork.policy_deployment_flow()

    # augWork.policy_deployment_flow(checkup=True)
    # augWork.transform_rulesets(save_all=True,save=True)
    # augWork.rest_connection()
    # augWork.del_fmc_objects(type_='port',where='all',obj_type='all')
    # augWork.del_fmc_objects(type_='network',where='all',obj_type='all')
    # augWork.del_fmc_objects(type_='network',where='all',obj_type='all')
