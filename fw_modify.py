from fw_cleanup import FireBroom
import pandas as pd
# MODIFICATION:
# NEED TO GET RULE THAT NEEDS TO BE MODIFIED, SAVE IT TO A BACKUP
# NEED TO ASK IF YOU WANT TO ADD/REMOVE RULE OBJECTS OR DIRECTION
# CREATE OBJECTS IF NECCASTY USING INHERATED CREATE FMC NAME MOD
# GO INTO CLEANUP MODE TO REMOVE ONE RULE AND ADD A NEW ONE IN ITS PLACE

# caveats
# should only mod acp rules that have the same source and dest IF its addition

# ADDDITION
# SAME AS PRIOR BUT NO NEED TO SAVE OLD RULE

## ADDONS
# CHANGE CAN RANGE FROM ONE TO N SO MAYBE WE CREATE A NEW CSV THAT CAN BE IN THE FORMAT AS THE INJEST.csv as switch between that and entering it via CLI
#                           but have a new colum for the rules to affect and another col to see if its add or sub from the rule
# make it sO THE RULE NAME MATCHING IS COMPLETEL!!  to avoid accidental changes

class FireHands(FireBroom):

    def __init__(self, configuration_data: dict, cred_file=None):
        super().__init__(configuration_data=configuration_data,cred_file=cred_file)
        self.temp_dir = f'{self.temp_dir}/FH'

    def modify_ruleset(self):
        # backup rules
        acp_rules,acp_id,recovery_fname,recovery_loc = self.prep_and_recover_fw_rules()
        # Get zone info first via ClI
        self.zone_ip_info = self.zone_to_ip_information()
        # get rules that need to inserted/deleted
        ippp = pd.read_csv(self.ippp_location)
        self.ippp = self.retrieve_ippp(ippp)
        self.fix_port_range_objects()
        # standardize operation col in ippp
        self.ippp['comments'] = self.ippp['comments'].apply(lambda x: 1 if x == 'add' else 0)
        # create FMC objects if needed
        self.create_fmc_object_names()
        # restart conn
        self.rest_connection(reset=True)
        # transform IPPP to ruleset
        self.ippp = self.standardize_ippp()
        # need to recurse there src_z, and dst_z and make sure zone from ippp matches

        pass
