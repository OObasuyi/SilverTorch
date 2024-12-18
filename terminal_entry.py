from argparse import ArgumentParser

from fw_cleanup import FireBroom
from fw_compliance import FireComply
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

    # clean up
    if config_file.get('cleanup'):
        fb = FireBroom(cred_file=args.cred_file, configuration_data=config_file)
        # rule cleanup
        if config_file.get('rule_cleanup'):
            fb.collapse_fw_rules(comment=config_file.get('rule_comment'), recover=config_file.get('recovery_mode'))
        # objects cleanup
        if config_file.get('object_cleanup'):
            fb.clean_object_store(clean_type=config_file.get('clean_type'))
        # delete ununsed rules
        if config_file.get('delete_unused_rules'):
            fb.remove_non_hit_rules()
        if config_file.get('combine_ruleset'):
            fb.combine_acp_ruleset()
        return

    # check rule consistency or deploy new rules
    if config_file.get('stage_ippp') or config_file.get('ippp_checkup'):
        fm = FireStick(cred_file=args.cred_file, configuration_data=config_file)
        if config_file.get('ippp_checkup'):
            # check if IPPP is in current ruleset
            fm.policy_deployment_flow(checkup=True)
        elif config_file.get('single_rule_ippp'):
            # standard policy deployment
            fm.policy_deployment_flow()
        elif config_file.get('multi_rule_ippp'):
            # standard policy deployment
            fm.policy_deployment_flow(multi_rule=True)
        return

    # save CURRENT rules to disk
    if config_file.get('save_rules'):
        fm = FireComply(cred_file=args.cred_file, configuration_data=config_file)
        fm.export_current_policy()
        return

    # save connection events
    if config_file.get('conn_events'):
        fm = FireComply(cred_file=args.cred_file, configuration_data=config_file,generate_conn=False)
        fm.generate_rules_from_events()
        return


if __name__ == "__main__":
    terminal_entry()
