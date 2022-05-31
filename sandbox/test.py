import pickle
from random import randint, shuffle, choice
from fw_deploy import FireStick
import pandas as pd
import utilites


def gen_half_way_ippp():
    net_objects = slacker.fmc.object.network.get()
    net_info = [no['value'] for no in net_objects]
    keepers = []
    for i in net_info:
        if '/32' in i:
            i = i.split('/')[0]
        keepers.append(i)

    rand_ip = [".".join(str(randint(0, 255)) for _ in range(4)) for ip in range(1 ,len(keepers))] + keepers
    shuffle(rand_ip)

    src ,dst = rand_ip[:50] ,rand_ip[50:]

    dst ,src = src + dst, dst + src
    ports = [randint(10 ,55556) for _ in src]
    external_check = [choice(['Y' ,''] )for _ in src]
    dst = dst[:len(src)]
    dict_pd = {'source' :src ,'destination' :dst ,'port' :ports ,'external' :external_check ,'comments': 'tck87457'}
    data_temp = pd.DataFrame.from_dict(dict_pd)
    data_temp.to_csv('dump_test_new.csv')


def gen_fake_rule_set(amount_of_rules=300,upload=False):
    if not upload:
        port_info = [str(randint(20,30650)) for _ in range(1,amount_of_rules)]
        proto_info = [choice(['TCP','UDP']) for _ in range(1,amount_of_rules)]
        src_ip_info = [".".join(str(randint(0, 255)) for _ in range(4)) for _ in range(1, amount_of_rules)]
        dest_ip_info = [".".join(str(randint(0, 255)) for _ in range(4)) for _ in range(1, amount_of_rules)]
        tckt_ip_info = ["test_run" for _ in range(1, amount_of_rules)]
        shuffle(src_ip_info)
        shuffle(dest_ip_info)
        gfrs_pd = {'source':src_ip_info,'destination' :dest_ip_info,'port_range_low':port_info,'port_range_high':port_info,'protocol':proto_info,'comments':tckt_ip_info}
        gfrs_pd = pd.DataFrame.from_dict(gfrs_pd)
        gfrs_pd.to_csv('gfrs.csv',index=False)

        zone_info = [sz['name'] for sz in slacker.fmc.object.securityzone.get()]
        zone_info.append('any')
        src_zone_info = [choice(zone_info) for _ in range(1, amount_of_rules)]
        dest_zone_info = [choice(zone_info) for _ in range(1, amount_of_rules)]
        zone_dat = {'source': src_zone_info, 'destination': dest_zone_info}
        with open('zone_dat.pkl', 'wb') as pkf:
            pickle.dump(zone_dat,pkf)
    else:
        gfrs_pd = pd.read_csv('gfrs.csv')
        gfrs_pd = gfrs_pd.astype(str)
        with open('zone_dat.pkl', 'rb') as pkf:
            zone_dat = pickle.load(pkf)

    # slacker.zbr_bypass = zone_dat
    # slacker.ippp = gfrs_pd
    # slacker.fmc_net_port_info()
    # slacker.create_fmc_object_names()
    # slacker.create_acp_rule()


# def get_zbf_files_test():
#     zbf_dict = utilites.csv_to_dict('zone_info.csv')
#     slacker = FireStick(creds=dict(fmc_username='api_admin', fmc_password='1qaz!QAZ'),zbr_bypass=zbf_dict)



if __name__ == "__main__":
    # slacker = FireStick(creds = dict(fmc_username='api_admin',fmc_password='1qaz!QAZ'))
    fg = 'HTTP(TCP)'
    import re
    qqq = re.sub('[^0-9a-zA-Z]+', '_', fg)
    qqq = [i.split()[0] for i in qqq.split('_') if i == 'TCP' or i == 'UDP'][0]
    print()
    # slacker.rest_connection()
    # gen_fake_rule_set(25,upload=True)
