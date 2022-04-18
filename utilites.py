import pandas as pd
from os import path,makedirs

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
    allowed_exts = ['csv','log','txt']

    input_ext = '.'.join(file_name.split(".")[1:])
    if input_ext not in allowed_exts:
        raise ValueError(f'please ensure you using one of the allowed file types you gave {input_ext}')

    fName = f'{top_dir}/{folder}/{file_name}'
    if not path.exists(f'{top_dir}/{folder}'):
        makedirs(f'{top_dir}/{folder}')
    return fName


