from argparse import ArgumentParser
from auto_fmc import AugmentedWorker


def terminal_entry():

    parser = ArgumentParser(prog='FirePyower')
    mandatory_args = parser.add_argument_group(title='Mandatory Args')
    mandatory_args.add_argument('-fmc_host',required=True,type=str)
    mandatory_args.add_argument('-ftd_host',required=True,type=str)
    mandatory_args.add_argument('-ppsm_location',required=True,type=str)
    mandatory_args.add_argument('-access_policy',required=True,type=str)
    mandatory_args.add_argument('-rule_prepend_name',required=True,type=str)
    mandatory_args.add_argument('-zone_of_last_resort',required=True,type=str)

    optional_args = parser.add_argument_group(title='Optional Args')
    optional_args.add_argument('--domain',default='Global',action="store",type=str)
    optional_args.add_argument('--zbr_bypass',default=None,action="store",type=str)
    optional_args.add_argument('--cred_file', default='cF.json', type=str)

    args = parser.parse_args()
    # handle optional None input
    args.zbr_bypass = args.zbr_bypass if args.zbr_bypass else None

    fm = AugmentedWorker(cred_file=args.cred_file, ppsm_location=args.ppsm_location ,access_policy=args.access_policy,
                         rule_prepend_name=args.rule_prepend_name,fmc_host=args.fmc_host,ftd_host=args.ftd_host,domain=args.domain,zbr_bypass=args.zbr_bypass,
                         zone_of_last_resort=args.zone_of_last_resort)
    fm.driver()


if __name__ == "__main__":
    terminal_entry()
    
