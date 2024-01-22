# SilverTorch 🔥
Silver Torch is a Python application designed to streamline and automate the creation and administration of large ruleset 
within Cisco Firepower Management Center.

## Getting Started 🌵
* Located within the [templates](templates) Directory, There are two primary files to for rule creation
  1. [acl_ingest_template.csv](templates%2Facl_ingest_template.csv)
  2. [firewall_config_template.yaml](templates%2Ffirewall_config_template.yaml)
* You can use these files as a example on how to stage and/or manage rules unto the Firewall.

## Core Workflows  🎛️
Below explains how some of the workflow work.
### Deploy Rules
1. import IPPP file
2. extract src,dst,ports,protocols(UDP/TCP),proposed Port name, comment or ticket number
3. Get zone and Fastpath (CEF equivalent) from sensor
4. get ports,protocols,IPs and their respective groups from FMC
5. Create the FMC object name for the relevant artifacts if needed or get the object if its already in FMC
6. Check if a duplicate policy exist in the ACP if it does drop that rule
7. Insert rule in a rule_prepend_name_comment_sequence_number" format with the rule info
8. Check if all rules in the original IPPP match what was staged on the fmc
   1. if ANY rules from the IPPP is not present in the ACP then roll back the ACP to the pre-installed state.

### Cleanup ACP Workflow
1. the rule_prepend_name argument will be used to find what subset of rules to looks for in the ACP
2.  a comment must be assigned to show to practice proper rule auditing implementations
3. if a match is found then it will try to optimize the ruleset by the zone information as much as possible
4. follow steps 7 & 8 from Deploy Rules

### IPPP Checkup
1. import CSV file
2. extract src,dst,ports,protocols(UDP/TCP),proposed Port name, ticket number
3. basically step 8 from Deploy Rules

## Caveats 👀
1. it more than likely possible to pull the zone info by looking up the logical interface name but for now please name the logical interface the same as the security zone.
2.  To support backward compatibility of the FMC API (<=7.0), only TCP or UDP can be used in the protocols section of ACL injest CSV you create.

## Special Cases 🎍
1. any IP that doesn't have a fastpath match can have a zone assigned to it using the zone_of_last_resort argument

----------------

## CLI to boot 👢
```console
user@machine:~/SilverTorch$ python3 terminal_entry.py -config_file firepower_configs.yaml
```

## CAT-FAQs 🐱
1. **Q. Well how does this deal with rule deduplication????**  
A. it scans the ACP and if a rule has the same Source and Destination Zone **AND** IPs and port  it will drop the potential rule from getting staged.  
2. **Q. Thats fancy what about rules with nested objects???? hmmmm!**   
A. It also scans recrusively to find potential duplicate IP or port objects.  
3. **Q.what is [template_cred.json](templates%2Ftemplate_cred.json) used for???**
A. that is for testing temporary purposes only. **IT SHOULD** not be used permanently as it holds your credentials in the clear!!
