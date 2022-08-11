from fw_deploy import FireStick





if __name__ == "__main__":
    augWork = FireStick(ippp_location='gfrs.csv', access_policy='test12', ftd_host='10.11.6.191', fmc_host='10.11.6.60',
                        rule_prepend_name='test_st_beta_2', zone_of_last_resort='outside_zone', same_cred=False, cred_file='cF.json',strict_checkup=True)
    augWork.policy_deployment_flow()
    # augWork.policy_deployment_flow(checkup=True)
    # augWork.transform_rulesets(save_all=True,save=True)
    # augWork.rest_connection()
    # augWork.del_fmc_objects(type_='port',where='all',obj_type='all')
    # augWork.del_fmc_objects(type_='network',where='all',obj_type='all')
    # augWork.del_fmc_objects(type_='network',where='all',obj_type='all')