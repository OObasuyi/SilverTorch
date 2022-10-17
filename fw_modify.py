from fw_deploy import FireStick

# MODIFICATION:
# NEED TO GET RULE THAT NEEDS TO BE MODIFIED, SAVE IT TO A BACKUP
# NEED TO ASK IF YOU WANT TO ADD/REMOVE RULE OBJECTS OR DIRECTION
# CREATE OBJECTS IF NECCASTY USING INHERATED CREATE FMC NAME MOD
# GO INTO CLEANUP MODE TO REMOVE ONE RULE AND ADD A NEW ONE IN ITS PLACE

# ADDDITION
# SAME AS PRIOR BUT NO NEED TO SAVE OLD RULE

## ADDONS
# CHANGE CAN RANGE FROM ONE TO N SO MAYBE WE CREATE A NEW CSV THAT CAN BE IN THE FORMAT AS THE INJEST.csv as switch between that and entering it via CLI
#                           but have a new colum for the rules to affect and another col to see if its add or sub from the rule
# make it sO THE RULE NAME MATCHING IS COMPLETEL!!  to avoid accidental changes

class FireHands(FireStick):

    def __init__(self, configuration_data: dict, cred_file=None):
        configuration_data['ippp_location'] = None
        super().__init__(configuration_data=configuration_data,cred_file=cred_file)

    def get_rule_operation(self,new_rule=True):
        pass

    def single_rule_change(self):
        pass