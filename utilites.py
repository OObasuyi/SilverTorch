from gzip import open as gzopen
import logging
from functools import wraps
from json import load, dump
from logging.handlers import TimedRotatingFileHandler
from os import path, makedirs, replace,rename, remove,walk
import pandas as pd
import yaml

TOP_DIR = path.dirname(path.abspath(__file__))


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
        TOP_DIR = path.dirname(path.abspath(__file__))
        allowed_exts = ['csv','log','txt','json','rulbk','yaml']

        input_ext = '.'.join(file_name.split(".")[1:])
        if input_ext.lower() not in allowed_exts:
            raise ValueError(f'please ensure you using one of the allowed file types you gave {input_ext}')

        fName = f'{TOP_DIR}/{folder}/{file_name}'
        if not path.exists(f'{TOP_DIR}/{folder}'):
            makedirs(f'{TOP_DIR}/{folder}')

        # move file to correct dir if needed
        if not path.exists(fName):
            try:
                replace(f'{TOP_DIR}/{file_name}',fName)
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
        logc = log_collector()
        if not isinstance(deploy_msg,str):
            raise ValueError(f'deploy_msg value is not type str. you passed an {type(deploy_msg)} object')

        warn_msg = f'{deploy_msg}.\nENTER c TO CONTINUE'
        while True:
            logc.warning(warn_msg)
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
            subset_rule['action'] = i.get('action')
            subset_rule['src_z'] = self_instance.find_nested_group_objects(i.get('sourceZones'))
            subset_rule['dst_z'] = self_instance.find_nested_group_objects(i.get('destinationZones'))
            subset_rule['source'] = self_instance.find_nested_group_objects(i.get('sourceNetworks'))
            subset_rule['destination'] = self_instance.find_nested_group_objects(i.get('destinationNetworks'))
            subset_rule['port'] = self_instance.find_nested_group_objects(i.get('destinationPorts'))
            if 'strict_checkup' in self_instance.pass_thru_commands and self_instance.pass_thru_commands.get('strict_checkup'):
                strict_holder = []
                # changed to get since port can be NONE value AKA 'any' in the Rules

                if i.get('destinationPorts') is not None:
                    real_dst_ports = i.get('destinationPorts')
                    for k in real_dst_ports.keys():
                        if k == 'literals':
                            for port_item in real_dst_ports[k]:
                                if port_item.get('port') is not None:
                                    if port_item.get('protocol') == '6':
                                        real_port = f'TCP:{port_item.get("port")}'
                                        strict_holder.append(real_port)
                                    elif port_item.get('protocol') == '17':
                                        real_port = f'UDP:{port_item.get("port")}'
                                        strict_holder.append(real_port)
                        elif k == 'objects':
                            for obj_item in real_dst_ports[k]:
                                if obj_item.get('type') == 'ProtocolPortObject':
                                    for port_item in self_instance.port_data:
                                        if port_item[0] == obj_item['name']:
                                            real_port = [f'{port_item[1]}:{port_item[2]}']
                                            strict_holder.append(real_port)
                                elif obj_item.get('type') == 'PortObjectGroup':
                                    for port_item in self_instance.port_group_object:
                                        if port_item[0] == obj_item['name']:
                                            # recurvsly look through the port objects for its names and get real port mapping from the port_data
                                            for port_list_item in port_item[1]:
                                                for port_item in self_instance.port_data:
                                                    if port_item[0] == port_list_item[0]:
                                                        real_port = [f'{port_item[1]}:{port_item[2]}']
                                                        strict_holder.append(real_port)
                    if len(strict_holder) == 1:
                        if not isinstance(next(iter(strict_holder)),list):
                            subset_rule['real_port'] = strict_holder[0]
                        else:
                            subset_rule['real_port'] = [i for i in strict_holder[0]]
                    else:
                        save_list = []
                        for i in strict_holder:
                            if isinstance(i,list):
                                for inner_i in i:
                                    save_list.append(inner_i)
                            else:
                                save_list.append(i)
                        subset_rule['real_port'] = save_list
                else:
                    subset_rule['real_port'] = None


                #     dest_item = i.get('destinationPorts') if isinstance(i.get('destinationPorts'),list) else [i.get('destinationPorts')]
                #     for i in dest_item:
                # #
                #     if i.get('destinationPorts')['objects'][0]['type'] == 'ProtocolPortObject':
                #         for port_item in self_instance.port_data:
                #             if port_item[0] == i.get('destinationPorts')['objects'][0]['name']:
                #                 subset_rule['real_port'] = [f'{port_item[1]}:{port_item[2]}']
                #     elif i.get('destinationPorts')['objects'][0]['type'] == 'PortObjectGroup':
                #         for port_item in self_instance.port_group_object:
                #             if port_item[0] == i.get('destinationPorts')['objects'][0]['name']:
                #                 # recurvsly look through the port objects for its names and get real port mapping from the port_data,
                #                 subset_rule['real_port'] = [f'{port_item[1]}:{port_item[2]}' for port_list_item in port_item[1] for port_item in self_instance.port_data if port_item[0] == port_list_item[0]]

            changed_ruleset.append(subset_rule)
        current_ruleset = changed_ruleset
        return pd.DataFrame(current_ruleset)

    @staticmethod
    def get_files_from_dir(folder,look_for_ext):
        dir_path = path.join(TOP_DIR, folder)
        _, _, filenames = next(walk(dir_path))
        return [path.join(dir_path, file) for file in filenames if file.endswith(look_for_ext)]

    @staticmethod
    def open_yaml_files(file_name):
        with open(file_name, "r") as stream:
            try:
                return yaml.safe_load(stream)
            except yaml.YAMLError as yaml_error:
                logc = log_collector()
                logc.error(f'ERROR READ FILE: {file_name}. PLEASE ENSURE YOUR ARE USING THE CORRECT YAML FORMAT.')
                logc.error(yaml_error)


def deprecated(func):
    fname = func.__name__
    logc = log_collector()

    @wraps(func)
    def wrapper(*args):
        logc.warning(f'the {fname} function is deprecated and will be removed in future releases')
        return func(*args)
    return wrapper


def log_collector(log_all=False):
    fName = Util().create_file_path('logs', 'firepyower.log')

    if not log_all:
        logger = logging.getLogger('SilverTorch')
    else:
        logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers():
        logger.handlers = []

    conHandler = logging.StreamHandler()
    conHandler.setLevel(logging.WARN)
    logformatCon = logging.Formatter('%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')
    conHandler.setFormatter(logformatCon)
    logger.addHandler(conHandler)

    fileHandler = TimedRotatingFileHandler(filename=fName, when='midnight', backupCount=90, interval=1)
    fileHandler.setLevel(logging.DEBUG)
    logformatfile = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')
    fileHandler.setFormatter(logformatfile)
    fileHandler.rotator = GZipRotator()
    logger.addHandler(fileHandler)
    return logger


class GZipRotator:
    def __call__(self, source, dest):
        rename(source, dest)
        f_in = open(dest, 'rb')
        f_out = gzopen("{}.gz".format(dest), 'wb')
        f_out.writelines(f_in)
        f_out.close()
        f_in.close()
        remove(dest)
