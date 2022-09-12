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

    if config_file.get('ruleset_type') not in ['ALLOW', 'DENY']:
        raise ValueError('RuleSet_type must be either allow or deny')

    if config_file.get('rule_cleanup'):
        fb = FireBroom(cred_file=args.cred_file,configuration_data=config_file)
        #todo: need to continue working on object cleanup
        fb.collapse_fmc_rules(comment=config_file.get('rule_comment'), recover=config_file.get('recovery_mode'))
    else:
        fm = FireStick(cred_file=args.cred_file, configuration_data=config_file)
        if config_file.get('ippp_checkup'):
            fm.policy_deployment_flow(checkup=True)
        else:
            fm.policy_deployment_flow()


if __name__ == "__main__":
    terminal_entry()
