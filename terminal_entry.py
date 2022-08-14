from argparse import ArgumentParser

from fw_cleanup import FireBroom
from fw_deploy import FireStick
from utilites import Util


def terminal_entry():
    parser = ArgumentParser(prog='SilverTorch Configuration Management')
    mandatory_args = parser.add_argument_group(title='SilverTorch Mandatory Fields')
    mandatory_args.add_argument('-config_file', help='YAML config file for SilverTorch', required=True, type=str)

    optional_args = parser.add_argument_group(title='SilverTorch Optional Fields')
    optional_args.add_argument('--cred_file', default=None, type=str)

    args = parser.parse_args()
    util = Util()
    config_file = util.create_file_path(folder='SilverConfigs', file_name=args.config_file)
    config_file = util.open_yaml_files(config_file)

    # handle optional None input
    zbr_bypass = config_file.get('zone_based_routing_bypass') if config_file.get('zone_based_routing_bypass') else None
    if config_file.get('ruleset_type') not in ['ALLOW', 'DENY']:
        raise ValueError('RuleSet_type must be either allow or deny')

    if config_file.get('rule_cleanup'):
        fb = FireBroom(access_policy=config_file.get('access_policy'), ftd_host=config_file.get('firewall_sensor'),
                       fmc_host=config_file.get('management_center'), rule_prepend_name=config_file.get('rule_prepend_name'),
                       zone_of_last_resort=config_file.get('zone_of_last_resort'), same_cred=config_file.get('same_creds'))

        fb.collapse_fmc_rules(comment=config_file.get('comment'), recover=config_file.get('recovery_mode'))
    else:
        fm = FireStick(cred_file=args.cred_file, ippp_location=config_file.get('ippp_location'), access_policy=config_file.get('access_policy'),
                       rule_prepend_name=config_file.get('rule_prepend_name'), fmc_host=config_file.get('management_center'), ftd_host=config_file.get('firewall_sensor'),
                       domain=config_file.get('domain'), zbr_bypass=zbr_bypass, zone_of_last_resort=config_file.get('zone_of_last_resort'), same_cred=config_file.get('same_creds'),
                       ruleset_type=config_file.get('ruleset_type'))
        if config_file.get('ippp_checkup'):
            fm.policy_deployment_flow(checkup=True)
        else:
            fm.policy_deployment_flow()


if __name__ == "__main__":
    terminal_entry()
