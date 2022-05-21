from functools import wraps
from json import load, dump
from logging import warning
from os import path, makedirs, replace

import pandas as pd


class Util:

    @staticmethod
    def csv_to_dict(csv_file) -> dict:
        return pd.read_csv(csv_file).to_dict()

    @staticmethod
    def try_block(val,output_msg=False,return_val=None):
        try:
            return val
        except Exception as error:
            if output_msg:
                print(error)
            return return_val

    @staticmethod
    def create_file_path(folder:str,file_name:str):
        top_dir = path.dirname(path.abspath(__file__))
        allowed_exts = ['csv','log','txt','json']

        input_ext = '.'.join(file_name.split(".")[1:])
        if input_ext.lower() not in allowed_exts:
            raise ValueError(f'please ensure you using one of the allowed file types you gave {input_ext}')

        fName = f'{top_dir}/{folder}/{file_name}'
        if not path.exists(f'{top_dir}/{folder}'):
            makedirs(f'{top_dir}/{folder}')

        # move file to correct dir if needed
        if not path.exists(fName):
            try:
                replace(f'{top_dir}/{file_name}',fName)
            except:
                # file has yet to be created or not in top path
                pass
        return fName

    def pull_creds(self, type_, rmdata=False):

        def _pull_cred_helper(type_):
            username_input = input("USERNAME:")
            userpasswd_input = input("PASSWORD:")
            cdict = {type_: {'username': username_input, 'password': userpasswd_input}}
            return cdict

        def _internal_pull_creds_01(cdict):
            for k in cdict['secret_stuff']:
                if list(k.keys())[0] == type_:
                    return k[type_]
            # if it couldnt find any matches raise an execption
            raise Exception

        def _internal_pull_creds_02(cdict):
            cdump = _pull_cred_helper(type_)
            cdict['secret_stuff'].append(cdump)
            with open('cHolder.json', 'w', encoding='utf-8') as fj:
                dump(cdict, fj, ensure_ascii=False, indent=4)
                return cdump[type_]

        try:
            cred_file = self.create_file_path('safe','cred_store.json')
            with open(cred_file,'r') as cf:
                cdict = load(cf)
            if rmdata:
                for k in cdict['secret_stuff']:
                    if list(k.keys())[0] == type_:
                        del cdict['secret_stuff'][cdict['secret_stuff'].index(k)]
                        return _internal_pull_creds_02(cdict)
            else:
                try:
                    return _internal_pull_creds_01(cdict)
                except:
                    return _internal_pull_creds_02(cdict)
        except:
            cdict = {'secret_stuff': []}
            return _internal_pull_creds_02(cdict)

    @staticmethod
    def permission_check(deploy_msg:str):
        if not isinstance(deploy_msg,str):
            raise ValueError(f'deploy_msg value is not type str. you passed an {type(deploy_msg)} object')

        warn_msg = f'{deploy_msg}.\nENTER c TO CONTINUE'
        while True:
            warning(warn_msg)
            user_input = input()
            if user_input.lower() == 'c':
                break

    @staticmethod
    def rename_ippp_instances(f_name:str,replace_with_list:list,to_look_for:str,col_to_process_list:list,return_pd=False):
        """renames instances where the IPPP(ip port & protocol) sheet has an unwanted attribute. IE. rename all instances from a col where row == 'intranet-IPs' with '192.168.1.0/24' """
        old_pd = pd.read_csv(f_name)
        new_changes = old_pd.copy()
        for col in col_to_process_list:
            non_selected_cols = old_pd.drop(columns=[col])
            for x in old_pd.index:
                if old_pd[col][x] == to_look_for:
                    for replace_with in replace_with_list:
                        nsc_pd = non_selected_cols.loc[x].to_dict()
                        nsc_pd[col] = replace_with
                        new_changes = new_changes.append(nsc_pd,ignore_index=True)
            new_changes.drop_duplicates(inplace=True)
            new_changes = new_changes[new_changes[col] != to_look_for]
        if return_pd:
            return new_changes
        else:
            new_changes.to_csv(f_name,index=False)

    @staticmethod
    def transform_acp(current_ruleset,self_instance):
        changed_ruleset = []
        for i in current_ruleset:
            subset_rule = {}
            subset_rule['policy_name'] = i.get('name')
            subset_rule['src_z'] = self_instance.find_nested_group_objects(i.get('sourceZones'))
            subset_rule['dst_z'] = self_instance.find_nested_group_objects(i.get('destinationZones'))
            subset_rule['source'] = self_instance.find_nested_group_objects(i.get('sourceNetworks'))
            subset_rule['destination'] = self_instance.find_nested_group_objects(i.get('destinationNetworks'))
            subset_rule['port'] = self_instance.find_nested_group_objects(i.get('destinationPorts'))
            changed_ruleset.append(subset_rule)
        current_ruleset = changed_ruleset
        return pd.DataFrame(current_ruleset)


def deprecated(func):
    fname = func.__name__

    @wraps(func)
    def wrapper(*args):
        warning(f'the {fname} function is deprecated and will be removed in future releases')
        return func(*args)
    return wrapper


