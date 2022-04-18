# FirePyower

## STANDARD WORK FLOW OF THE PROGRAM
1. get CSV
2. extract src,dst,ports,protocols(UDP/TCP),proposed Port name, ticket number
3. Get zone and Fastpoath (CEF equivalent) from sensor
4. get ports,protocols,IPs and their respective groups from FMC
5. Create the FMC object name for the relevent artifacts if needed or get the object if its already in FMC
6. Check if a duplicate policy exist in the ACP if it does drop that rule
7. Insert rule in a [SRC_DST_randomINT] format with the rule info

## Caveats
1. it more than likely possible to pull the zone info by looking up the logical interface name but for now please name the logical interface the same as the security zone.
2. <= 7.0 ver of FMC API only allows TCP or UDP for protocols to used.

## Special Cases:
1. if you new ip information and dont want to use the fastpath info to find the correct zone to put the IP, the zbr_bypass argument MUST match the row lines of the PPS rows
2. any IP that doesn't have a fastpath match can have a zone assigned to it using the zone_of_last_resort argument

## WIPS:
 1. better error and log handling
 2. send preload config to a separate location since you would need to another terminal to properly view the preload ruleset
 3. multiprocessing to speed up search times

## Main Dependencies
pandas \
netmiko \
tqdm \
fireREST\
OObasuyi/paramiko (for FIPS compliance)
## Quck start
```python
from auto_fmc import AugmentedWorker

# cred file must be imported see example_cred.json
augWork = AugmentedWorker(cred_file='cred_file.json', ppsm_location='pps_file.csv',access_policy='acp')

# starts workflow
augWork.driver()