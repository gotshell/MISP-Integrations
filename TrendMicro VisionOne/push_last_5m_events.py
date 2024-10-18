# Importing libraries
from datetime import datetime, timedelta
from pymisp import PyMISP
import requests
import urllib3
import time
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import validators
import ipaddress
import logging


colorama_init()

# ==============================================================================================================
# 
# TODO : CHECK FOR REFERENCE SET BEFORE TRYING TO PUSH SOMETHING IN IT
# TODO : ADD EXPIRATION DATE TO IOCS PUSHED TO QRADAR
# 
# This script searches for events in the last 5 minutes and pushes attributes value to Qradar's 
# reference sets and VisionOne UDSO list
#
# Please add your keys/urls first
#
# If you don't need qradar integration just comment line 96 and 97
#
# ==============================================================================================================


# ---------------------------------------------- MISP API Settings ----------------------------------------------

misp_url = 'https://'
misp_key = ''
misp_verifycert = True

# --------------------------------------------- Qradar API Settings ---------------------------------------------

qradar_url = 'https://_____________/api/reference_data/sets/bulk_load/'
qradar_key = ''

# -------------------------------Trend Micro VisionOne API configuration----------------------------------

url_base = 'https://api.eu.xdr.trendmicro.com/'
url_path = '/v3.0/threatintel/suspiciousObjects'
token = ''

query_params = {}
headers = {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json;charset=utf-8'
}

#---------------------------------------------GLOBAL VARIABLES----------------------------------------------
DAYS_TO_EXPIRATION = '15'
RISK_LEVEL = 'high'
SCAN_ACTION = 'block'
QRADAR_IP_REFERENCE_SET = 'qradar_reference_set_name_IP'
QRADAR_URL_REFERENCE_SET = 'qradar_reference_set_name_URL'
LAST_MINUTES = '5m'
#----------------------------------------------------------------------------------------------------------


# Disabling certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def search_and_create_set(orgs) -> None:
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    for organization in orgs:
        # Some sets/lists to be pushed through API
        url_set, domain_set, ip_set, email_set, sha1_set, sha256_set = set(), set(), set(), set(), set(), set()
        qradar_url_list, qradar_ip_list = [], []
        print(f'Start searching for ORG: {organization}')
        start_time = time.time()
        # Search for events in the last 5 minutes
        events = misp.search(controller='events', published=True, org=organization, to_ids=1, last=LAST_5_MINS, pythonify=True)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f'MISP search ended in {elapsed_time}') 
        for event in events:
            # for each event get info and attributes 
            attributes, event_info = event.attributes, event.info
            event_tag_names = [tag.name for tag in event.tags]
            # if 'tryTag' not in event_tag_names or 'tryTag1' not in event_tag_names:
            for attribute in attributes:
                att_value = attribute.value
                att_type = check_type(att_value)
                att_timestamp = attribute.timestamp
                adjusted_timestamp = attribute.timestamp + timedelta(hours=2)
                attribute_timestamp = adjusted_timestamp.replace(tzinfo=None)
                # print(f'attribute_timestamp {attribute_timestamp} of {att_value}')
                current_time = datetime.now()
                # print('current_time', current_time)
                five_minutes_ago = current_time-timedelta(minutes=5)
                # print('five_minutes_ago',five_minutes_ago)
                if attribute_timestamp>five_minutes_ago:
                    # create sets/lists
                    if att_type == 'url': 
                        url_set.add(att_value)
                        qradar_url_list.append(att_value)
                    elif att_type == 'domain': 
                        domain_set.add(att_value)
                        qradar_url_list.append(att_value)
                    elif att_type == 'Public IPv4': 
                        ip_set.add(att_value)
                        qradar_ip_list.append(att_value)
                    elif att_type == 'file_sha1': sha1_set.add(att_value)
                    elif att_type == 'SHA-256': sha256_set.add(att_value)
                        
        # push to IDS if lists are not empty
        if url_set: push_to_tm_vision_one(url_set, 'url', f'{organization}\'s MISP event - {event_info}')      
        if domain_set: push_to_tm_vision_one(domain_set, 'domain', f'{organization}\'s MISP event - {event_info}')          
        if ip_set: push_to_tm_vision_one(ip_set, 'ip', f'{organization}\'s MISP event - {event_info}')
        if sha1_set: push_to_tm_vision_one(sha1_set, 'fileSha1', f'{organization}\'s MISP event - {event_info}')
        if sha256_set: push_to_tm_vision_one(sha256_set, 'fileSha256', f'{organization}\'s MISP event - {event_info}')
        if qradar_ip_list: push_to_qradar(qradar_ip_list, QRADAR_IP_REFERENCE_SET)
        if qradar_url_list: push_to_qradar(qradar_url_list, QRADAR_URL_REFERENCE_SET)

# This method does a post request to qradar's API url. The post request contains the list that has to be pushed to the reference set
def push_to_qradar(iocs_list, list_name):
    headers = {
    'Content-Type': 'application/json',
    'SEC': qradar_key
    }
    qradar_url_ = qradar_url+list_name
    try:
        response = requests.post(qradar_url_, headers=headers, json=iocs_list, verify=False)
        if response.status_code == 200:
            print(f'{Fore.GREEN}IOCs successfully sent to QRadar.{Style.RESET_ALL}')   
    except requests.HTTPError as e:
        print('HTTPError: ', e)
    except requests.exceptions.ConnectionError as e:
        print('Connection-Error: ', e)
        print('Retrying the request in 30 seconds...')
        time.sleep(30)
        response = requests.post(qradar_url_, headers=headers, json=iocs_list, verify=False)
    except Exception as e:
        print('2Generic Error: ', e)
    time.sleep(3) 

# This method creates a json body from an IOCs list and does a post request to TM VisionOne API url.
def push_to_tm_vision_one(bad_ioc, ioc_type, event_name):
    body = []
    for ioc in bad_ioc:
        body.append({
                f"{ioc_type}": f"{ioc}",
                'description': f"{event_name}",
                'scanAction': SCAN_ACTION,
                'riskLevel': RISK_LEVEL,
                'daysToExpiration': DAYS_TO_EXPIRATION
        })

    r = requests.post(url_base + url_path, params=query_params, headers=headers, json=body)
    time.sleep(0.3)
    if r.status_code == 207:
        print('----------------------------------------------------------------------------------')
        print('IOC sent to VisionOne instance')

# This method checks if the input ip address is private or public
def is_public_ipv4(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False

def check_type(data):
    if validators.url(data): return "url"
    elif validators.domain(data): return "domain"
    try:
        ip = ipaddress.ip_address(data)
        if ip.version == 4:
            if is_public_ipv4(ip): return "Public IPv4"
            else: return "Private IPv4"
        elif ip.version == 6: return "IPv6"
    except ValueError:
        pass
        # Check hash types
    if len(data) == 40 and all(c in '0123456789abcdefABCDEF' for c in data): return "file_sha1"
    elif len(data) == 32 and all(c in '0123456789abcdefABCDEF' for c in data): return "MD5"
    elif len(data) == 64 and all(c in '0123456789abcdefABCDEF' for c in data): return "SHA-256"
    return "Not recognised"


if __name__ == '__main__' :
    org_names_list = ['SIAG',  'CERT-AGID_6929'] #'Lepida', 'Pasubio Tecnologia', 'Trentino Digitale',
    search_and_create_set(org_names_list)
