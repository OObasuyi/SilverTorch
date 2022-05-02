# FirePyower (AKA SilverTorch) 
This script stages rules into the FMC. It also inserts rules based on their port/application to create a more app-controlled firewall.

## As Palpatine would say *DO IT*
1. get CSV
2. extract src,dst,ports,protocols(UDP/TCP),proposed Port name, ticket number
3. Get zone and Fastpath (CEF equivalent) from sensor
4. get ports,protocols,IPs and their respective groups from FMC
5. Create the FMC object name for the relevant artifacts if needed or get the object if its already in FMC
6. Check if a duplicate policy exist in the ACP if it does drop that rule
7. Insert rule in a rule_prepend_name_comment_randomNUM" format with the rule info

## Caveats
1. it more than likely possible to pull the zone info by looking up the logical interface name but for now please name the logical interface the same as the security zone.
2. <= 7.0 ver of FMC API only allows TCP or UDP for protocols to used.

## Special Cases
1. if you new ip information and dont want to use the fastpath info to find the correct zone to put the IP, the zbr_bypass argument MUST match the row lines of the PPS rows
2. any IP that doesn't have a fastpath match can have a zone assigned to it using the zone_of_last_resort argument

## WIPS
 1. better error and log handling
 2.  RATE LIMITING ISSUE
 3.  CASE4 DEDUPING
## Main Dependencies
pandas \
netmiko \
tqdm \
fireREST\
OObasuyi/paramiko (for FIPS compliance)
# Quick start
### Calling function directly from *auto_fmc.py*
```python
from auto_fmc import AugmentedWorker

# cred file must be imported see example_cred.json
augWork = AugmentedWorker(cred_file='cred_file.json', ppsm_location='pps_file.csv',access_policy='acp')

# starts workflow
augWork.driver()
```
### Command line interface
```console
user@machine:~/SilverTorch$ python3 terminal_entry.py -fmc_host 10.11.6.60 -ftd_host 10.11.6.191 -ppsm_location gfrs.csv -access_policy test_acp -zolr outside_zone
```
### console options
```console
optional arguments:
  -h, --help            show this help message and exit

Mandatory Args:
  -fmc_host FMC_HOST
  -ftd_host FTD_HOST
  -ppsm_location PPSM_LOCATION
  -access_policy ACCESS_POLICY
  -rule_prepend_name RULE_PREPEND_NAME
  -zolr ZOLR            zone of last resort

Optional Args:
  --domain DOMAIN
  --zbr_bypass ZBR_BYPASS
  --cred_file CRED_FILE
   --same_creds SAME_CREDS True or False/case-sensitive

```
## CAT-FAQs
1. **Q. Well how does this deal with rule deduplication????**  
A. it scans the ACP and if a rule has the same Source and Destination Zone **AND** IPs and port  it will drop the potential rule from getting staged  
2. **Q. Thats fancy what about rules with nested objects???? hmmmm!**   
A. It also scans recrusively to find potential duplicate IP or port objects.  
