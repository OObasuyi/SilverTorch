from argparse import ArgumentParser
from fw_deploy import FireStick


def terminal_entry():

    parser = ArgumentParser(prog='FirePyower')
    mandatory_args = parser.add_argument_group(title='SilverTorch Mandatory Fields')
    mandatory_args.add_argument('-fmc_host',required=True,type=str)
    mandatory_args.add_argument('-ftd_host',required=True,type=str)
    mandatory_args.add_argument('-ippp_location',required=True,type=str)
    mandatory_args.add_argument('-access_policy',required=True,type=str)
    mandatory_args.add_argument('-rule_prepend_name',required=True,type=str)
    mandatory_args.add_argument('-zolr',help='zone of last resort', required=True,type=str)

    optional_args = parser.add_argument_group(title='SilverTorch Optional Fields')
    optional_args.add_argument('--ippp_checkup',default=False, help='Check whether the IPPP is found in the ACP', type=bool)
    optional_args.add_argument('--domain',default='Global',action="store",type=str)
    optional_args.add_argument('--zbr_bypass',default=None,action="store",type=str)
    optional_args.add_argument('--cred_file', default=None, type=str)
    optional_args.add_argument('--same_creds', default=True,help='True or False/case-sensitive', type=bool)
    optional_args.add_argument('--ruleset_type', default='ALLOW',help='ALLOW OR DENY TYPE OF RULESET', type=str)

    args = parser.parse_args()
    # handle optional None input
    args.zbr_bypass = args.zbr_bypass if args.zbr_bypass else None
    if args.ruleset_type not in ['ALLOW','DENY']:
        raise ValueError('RuleSet_type must be either allow or deny')

    fm = FireStick(cred_file=args.cred_file, ippp_location=args.ippp_location, access_policy=args.access_policy,
                   rule_prepend_name=args.rule_prepend_name, fmc_host=args.fmc_host, ftd_host=args.ftd_host, domain=args.domain, zbr_bypass=args.zbr_bypass,
                   zone_of_last_resort=args.zolr, same_cred=args.same_creds, ruleset_type=args.ruleset_type)

    if args.ippp_checkup:
        fm.policy_deployment_flow(checkup=True)
    else:
        fm.policy_deployment_flow()


if __name__ == "__main__":
    terminal_entry()
    
