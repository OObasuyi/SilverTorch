from argparse import ArgumentParser
from auto_fmc import AugmentedWorker


def terminal_entry():
    mand_arg_list = ['-cred_file', '-fmc_host', '-ftd_host', '-ppsm_location', '-access_policy','-rule_prepend_name']
    opt_arg_list = ['--domain','--zbr_bypass']
    parser = ArgumentParser(prog='FirePyower')
    for marg in mand_arg_list:
        parser.add_argument(marg,action="store",default=True,type=str)
    for oarg in opt_arg_list:
        parser.add_argument(oarg,default=False,action="store",type=str)
    
    args = parser.parse_args()
    # handle optinal input
    domain= args.domain if args.domain else 'Global'
    zbr_bypass = args.zbr_bypass if args.zbr_bypass else None

    return args
    
    fm = AugmentedWorker(cred_file=args.cred_file, ppsm_location=args.ppsm_location ,access_policy=args.access_policy,
    rule_prepend_name=args.rule_prepend_name,fmc_host=args.fmc_host,ftd_host=args.ftd_host,domain=domain,zbr_bypass=zbr_bypass)
    fm.driver()


if __name__ == "__main__":
    terminal_entry()
    
