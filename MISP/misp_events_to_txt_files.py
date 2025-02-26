import os
import requests
import re
from pymisp import PyMISP
import time
from datetime import datetime,timedelta
import urllib3
import logging

# ---------------------------------------MISP API configuration-------------------------------------------
misp_url = 'https://ADDHERE'
misp_key = 'ADDHERE'
misp_verifycert = True 
#---------------------------------------------GLOBAL VARIABLES----------------------------------------------
ORG_TO_SEARCH_FOR = ['YOUR_ORG', 'OTHER_ORGS']
CHECK_ATTRIBUTE_TAGS_ORG_ = 'YOUR_TAG'
RISK_SCORE_RF = 83
DOMAIN_FILE_PATH = '/script/txt_for_firewall_block/domain.txt' 
IP_FILE_PATH = '/script/txt_for_firewall_block/ip.txt'
HASH_FILE_PATH = '/script/txt_for_firewall_block/hash.txt'
URL_FILE_PATH = '/script/txt_for_firewall_block/url.txt'
LOG_FILE_PATH = '/script/txt_for_firewall_block/logs/misp_to_txt.log'
#----------------------------------------------------------------------------------------------------------

# Disabling certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def list_maker(misp_tag_list):
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    ip_list, domain_list, url_list, hash_list =  [], [], [], []
    logging.info(f"Tags provided {misp_tag_list}")
    for tag in misp_tag_list:
        logging.info(f"Starting search for tag: {tag}")
        start_time = time.time()
        events = misp.search(controller='events', tag=tag, org=ORG_TO_SEARCH_FOR, timestamp='14d', to_ids=1, pythonify=True)
        end_time = time.time()
        elapsed_time = end_time - start_time
        logging.info(f"Elapsed time misp.search(tag={tag}): {elapsed_time}")
        iocs_count = 0 
        for event in events:
            iocs = event.attributes
            event_name = event.info 
            logging.info(f"Processing event: {event_name}")
            org_name = event.Orgc.name
            for ioc in iocs:
                att_count, att_list, ioc_type, ioc_value = 0, [], ioc.type, ioc.value
                ''' 
                You can use this piece of code to check for attribute tag. In this case it searches for recorded-future:risk-score="SOMETHING" and if it's more than 83 then appends value to the list. 
                if  org_name == CHECK_ATTRIBUTE_TAGS_ORG_:
                    try:
                        attribute_tag_list = ioc.Tag
                        if attribute_tag_list:   
                            pattern = r'recorded-future:risk-score="(\d+)"'   
                            att_list = [att_tag.name for att_tag in attribute_tag_list]
                            for tag_ in att_list:
                                match_rf_risk_score = re.search(pattern, tag_)
                                risk_score_number = int(match_rf_risk_score.group(1)) if match_rf_risk_score else None
                                if risk_score_number is not None and risk_score_number >= RISK_SCORE_RF and att_count==0: 
                                    if ioc_type == 'ip-src' or ioc_type =='ip-dst': ip_list.append(ioc_value)
                                    elif ioc_type == 'domain': domain_list.append(ioc_value)
                                    elif ioc_type =='url': url_list.append(ioc_value)
                                    elif ioc_type == 'ip-dst|port' or ioc_type == 'ip-src|port':
                                        cleaned_ioc = ioc_value_cleaner(ioc_value)
                                        ip_list.append(cleaned_ioc)
                                    elif ioc_type == 'hostname|port':
                                        cleaned_ioc = ioc_value_cleaner(ioc_value)
                                        domain_list.append(cleaned_ioc)
                                    elif ioc_type == 'sha1' or ioc_type == 'sha256': hash_list.append(ioc_value)
                                    att_count=1
                    except Exception as e:
                        print(repr(e))
                else:
                '''
                if ioc_type == 'ip-src' or ioc_type =='ip-dst': ip_list.append(ioc_value)
                elif ioc_type == 'domain': domain_list.append(ioc_value)
                elif ioc_type =='url': url_list.append(ioc_value)
                elif ioc_type == 'ip-dst|port' or ioc_type == 'ip-src|port':
                    cleaned_ioc = ioc_value_cleaner(ioc_value)
                    ip_list.append(cleaned_ioc)
                elif ioc_type == 'hostname|port':
                    cleaned_ioc = ioc_value_cleaner(ioc_value)
                    domain_list.append(cleaned_ioc)
                elif ioc_type == 'sha1' or ioc_type == 'sha256': hash_list.append(ioc_value)
    iocs_count = len(domain_list) + len(url_list) + len(ip_list) + len(hash_list)
    logging.info(f"Processed {len(domain_list)} domains, {len(url_list)} urls, {len(ip_list)} IPs, {len(hash_list)} hashes.")
    logging.info(f"Processed a total of {iocs_count} IOCs.")
   
    if domain_list: create_txt(domain_list, DOMAIN_FILE_PATH)
    if url_list: create_txt(url_list, URL_FILE_PATH)
    if ip_list: create_txt(ip_list, IP_FILE_PATH)
    if hash_list: create_txt(hash_list, HASH_FILE_PATH)
      
def create_txt(txt_list, file_path):
    file_exists = os.path.exists(file_path)
    with open(file_path, 'w') as file: 
        file.write('\n'.join(map(str,txt_list)))
    if file_exists:
        logging.info(f"Updated existing file: {file_path}")
    else:
        logging.info(f"Created new file: {file_path}")

def ioc_value_cleaner(ioc_value):
    if '|' in ioc_value:
        value_no_port = ioc_value.split('|')
        value_no_port_cleaned = value_no_port[0]
    return value_no_port_cleaned

if __name__ == '__main__' :
    tags = ['YOUR_TAG, 'MORE_TAGS']
    list_maker(tags)
