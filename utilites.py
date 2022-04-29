from logging import warning
import pandas as pd
from os import path,makedirs,replace
from json import load,dump
from functools import wraps


def csv_to_dict(csv_file) -> dict:
    return pd.read_csv(csv_file).to_dict()


def try_block(val,output_msg=False,return_val=None):
    try:
        return val
    except Exception as error:
        if output_msg:
            print(error)
        return return_val


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


def pull_creds( type_, rmdata=False):

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
        cred_file = create_file_path('safe','cred_store.json')
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


def deprecated(func):
    fname = func.__name__

    @wraps(func)
    def wrapper(*args):
        warning(f'the {fname} function is deprecated and will be removed in future releases')
        return func(*args)
    return wrapper




