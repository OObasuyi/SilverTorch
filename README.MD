# SilverTorch
This script stages rules into the FMC. It also inserts rules based on their Zone to create an automated Zone Based firewall. This script also can help clean up firewall rules if needed

## As Palpatine would say *DO IT*
### Pre-requisites for deploying rules to the firewall
* The ruleset files must use the same template as  "acl_ingest_templete.csv" in the templates folder.
* the deployment configuration YAML file must be filled using the template "firewall_config_template.yaml" 

### Deploy Rules Workflow (DRW)
1. import IPPP file
2. extract src,dst,ports,protocols(UDP/TCP),proposed Port name, ticket number
3. Get zone and Fastpath (CEF equivalent) from sensor
4. get ports,protocols,IPs and their respective groups from FMC
5. Create the FMC object name for the relevant artifacts if needed or get the object if its already in FMC
6. Check if a duplicate policy exist in the ACP if it does drop that rule
7. Insert rule in a rule_prepend_name_comment_ruleseqnum" format with the rule info
8. Check if all rules in the original IPPP match whats was staged on the fmc
   1. if ANY rules from the IPPP is not present in the ACP then roll back the ACP to the pre-installed state.

### Cleanup ACP Workflow (CAW)
1. the rule_prepend_name argument will be used to find what subset of rules to looks for in the ACP
2.  a comment must be assigned to show to practice proper rule auditing implementations
3. if a match is found then it will try to optimize the ruleset by the zone information as much as possible
4. follow steps 7 & 8 from DRW

### IPPP Checkup (IC)
1. import IPPP file
2. extract src,dst,ports,protocols(UDP/TCP),proposed Port name, ticket number
3. basically steps 7 & 8 from DRW

## Caveats
1. it more than likely possible to pull the zone info by looking up the logical interface name but for now please name the logical interface the same as the security zone.
2. <= 7.0 ver of FMC API only allows TCP or UDP for protocols to used.

## Special Cases
1. if you have new ip information and don't want to use the fastpath info to find the correct zone to put the IP, the zbr_bypass argument MUST match the row lines of the PPS rows
2. any IP that doesn't have a fastpath match can have a zone assigned to it using the zone_of_last_resort argument

## Optional Dependencies
There is one separate dependency that may be needed if you have FIPS enabled since paramiko has not incorporated this in its code it is:
1. OObasuyi/paramiko (for FIPS compliance)

# Quick start
## Calling the function directly examples

### DRW
```python
from fw_deploy import FireStick

# will ask for the creds on the terminal
augWork = FireStick(ippp_location='ippp_rel4.csv', access_policy='acp', ftd_host='10.11.6.191', fmc_host='10.11.6.60',
                    rule_prepend_name='zoom_rules', zone_of_last_resort='outside_zone', same_cred=True)

# starts workflow
augWork.policy_deployment_flow()
```
### CAW
```python
from fw_cleanup import FireBroom
sweeper = FireBroom(access_policy='test12', ftd_host='10.11.6.191', fmc_host='10.11.6.60', rule_prepend_name='test_st_beta_2', zone_of_last_resort='outside_zone')
sweeper.collapse_fmc_rules(comment='tester123')
```  
### IC
```python
from fw_deploy import FireStick

augWork = FireStick(ippp_location='ippp_rel4.csv', access_policy='acp', ftd_host='10.11.6.191', fmc_host='10.11.6.60',
                    rule_prepend_name='zoom_rules', zone_of_last_resort='outside_zone', same_cred=True)
# IPPP checkup
augWork.policy_deployment_flow(checkup=True)
```

### Command line interface
```console
user@machine:~/SilverTorch$ python3 terminal_entry.py -config_file firepower_configs.yaml
```
### console options
```console
SilverTorch Mandatory Fields:
   -config_file YAML config file for SilverTorch

SilverTorch Optional Fields:
  --cred_file CRED_FILE

```
## CAT-FAQs
1. **Q. Well how does this deal with rule deduplication????**  
A. it scans the ACP and if a rule has the same Source and Destination Zone **AND** IPs and port  it will drop the potential rule from getting staged.  
2. **Q. Thats fancy what about rules with nested objects???? hmmmm!**   
A. It also scans recrusively to find potential duplicate IP or port objects.  
