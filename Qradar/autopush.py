# ---------------------------------------------- Libraries --------------------------------------------------------------------------------------
from pymisp import ExpandedPyMISP
import requests
import urllib3
import re
import time
# from colorama import init as colorama_init
# from colorama import Fore
# from colorama import Style
# -----------------------------------------------------------------------------------------------------------------------------------------------

# -----------------------------------------------------------------ToDo-------------------------------------------------------------------------\
# add check on attributes score --> If 
# -----------------------------------------------------------------------------------------------------------------------------------------------\

# colorama_init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------- MISP API Settings ------------------------------------------------------------------------------
misp_url = 'https://' # <----------------------------------- add misp instance url here
misp_key = '' # <------------------------------------------- add misp api key
misp_verifycert = True
# --------------------------------------------- Qradar API Settings -----------------------------------------------------------------------------
qradar_url = 'https://________________/api/reference_data/sets/bulk_load/{list_name}' # <------- add Qradar instance IP/URL here
qradar_key = '' # <------------------------------------------- add Qradar api key
# -----------------------------------------------------------------------------------------------------------------------------------------------

def create_qradar_list(api_key, list_name):
    headers = {
        'Content-Type': 'application/json',
        'SEC': api_key
    }
    url = f'https://________________/api/reference_data/sets?element_type=ALN&name={list_name}'
    try:
        response = requests.post(url, headers=headers, verify=False)
        if response.status_code == 201:
            print('QRadar list created successfully.')
        else:
            print('Create QRadar list: Failed. Status Code:', response.status_code)
            print('Response:', response.text)
            
    except requests.exceptions.RequestException as e:
        print('An error occurred while sending the request:', str(e))

def auto_push(iocs_list,misp_tag_list):  
    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    for tag in misp_tag_list:
        events = misp.search(tag=tag)
        if isinstance(events, dict) and 'response' in events:
            events = events['response']
        for event in events:
            iocs_list = []
            iocs = event['Event']['Attribute']
            event_name = event['Event']['info']
            #print('Event name: ',event_name)
            if event_name.endswith('feed'):
                event_name = event_name[:-4]
            # todo: check types --> get_ioc()
            ioc_type='altro'  
            get_ioc(iocs,ioc_type, iocs_list)
            list_name = name_cleaner(event_name)      
            reference_set_cleaner(list_name)
            if len(iocs_list) >= 10000:
                list_splitter(list_name, iocs_list)
            else:
                qradar_url = 'https://________________/api/reference_data/sets/bulk_load/' + list_name
                sender(qradar_url, list_name, iocs_list)

def name_cleaner(event_name): 
    pattern = r'[^a-zA-Z0-9&-]'
    list_name = re.sub(pattern, ' ', event_name)
    list_name = list_name.replace('&', 'n')
    return list_name

def list_splitter(list_name, iocs_list):
    splitted_iocs_list = []
    qradar_url = 'https://________________/api/reference_data/sets/bulk_load/' + list_name
    chunk_size = 10000
    for i in range(0, len(iocs_list), chunk_size):
        splitted_iocs_list = iocs_list[i:i+chunk_size]
        sender(qradar_url, list_name, splitted_iocs_list)
        time.sleep(3)
        print(list_name, ' chunk sent.')

def reference_set_cleaner(list_name):
    headers = {
    'Version': '17.0',
    'Content-Type': 'application/json',
    'SEC': qradar_key
    }
    qradar_url = 'https://________________/api/reference_data/sets/' + list_name +'?purge_only=true'
    try:
        response = requests.delete(qradar_url, headers=headers, verify=False)
        time.sleep(2)
        if response.status_code == 202:
            print(f"Reference set content successfully wiped.")
    except Exception as e:
        print('1Generic Error: ', e)

# Sends IOCs to QRadar
def sender(qradar_url, list_name, iocs_list):   
    headers = {
    'Content-Type': 'application/json',
    'SEC': qradar_key
    }
    try:
        response = requests.post(qradar_url, headers=headers, json=iocs_list, verify=False)
        if response.status_code == 200:
            print('IOCs successfully sent to QRadar')  
            # print(f'{Fore.GREEN}IOCs successfully sent to QRadar.{Style.RESET_ALL}')   
        elif response.status_code == 404:
            print('Reference Set not found')
            create_qradar_list(qradar_key, list_name)
            response = requests.post(qradar_url, headers=headers, json=iocs_list, verify=False)
            if response.status_code == 200:
                print('IOCs successfully sent to QRadar') 
                # print(f'{Fore.GREEN}IOCs succesfully sent to QRadar.{Style.RESET_ALL}') 
    except requests.HTTPError as e:
        print('HTTPError: ', e)
    except requests.exceptions.ConnectionError as e:
        print('Connection-Error: ', e)
        print('Retrying the request in 30 seconds...')
        time.sleep(30)
        response = requests.post(qradar_url, headers=headers, json=iocs_list, verify=False)
    except Exception as e:
        print('2Generic Error: ', e)
    time.sleep(5)   

# Getting iocs
def get_ioc(iocs, ioc_type,iocs_list):
    for ioc in iocs:
        if ioc_type == 'altro':
            iocs_list.append(ioc['value'])


if __name__ == '__main__' :
    misp_tag_list = [''] # <----------------- add tag here 
    print('Gonna search for:', misp_tag_list,'tags in MISP\'s instance')
    iocs_list = []
    auto_push(iocs_list,misp_tag_list)

