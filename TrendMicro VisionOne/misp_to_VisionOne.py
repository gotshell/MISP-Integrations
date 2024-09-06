# -------------------------------------------LIBRARIES--------------------------------------------------
import requests
import re
from pymisp import PyMISP
import time
from datetime import datetime,timedelta
import urllib3
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

# ---------------------------------------MISP API configuration-------------------------------------------

misp_url = 'https://'    <--------- add misp url
misp_key = ''            <--------- add misp key
misp_verifycert = True

# -------------------------------Trend Micro VisionOne API configuration----------------------------------

url_base = 'https://api.eu.xdr.trendmicro.com/'
    # U.S. (global) api.tmcas.trendmicro.com
    # EU            api-eu.tmcas.trendmicro.com
    # Japan         api.tmcas.trendmicro.co.jp
    # Australia and New Zealand api-au.tmcas.trendmicro.com
    # UK            api.tmcas.trendmicro.co.uk
    # Canada        api-ca.tmcas.trendmicro.com
    # Singapore     api.tmcas.trendmicro.com.sg
    # India         api-in.tmcas.trendmicro.com
url_path = '/v3.0/threatintel/suspiciousObjects'
token = '' # <----------Enter VisionOne Token [Administration/API-KEYS/add_new_api_key]-----------------
query_params = {}
headers = {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json;charset=utf-8'
}

#---------------------------------------------GLOBAL VARIABLES----------------------------------------------
DAYS_TO_EXPIRATION = '15'
RISK_LEVEL = 'high'
SCAN_ACTION = 'block'
ORG_TO_SEARCH_FOR = ['BRN', 'BLABLA']
ORG_ = 'BRN'
#----------------------------------------------------------------------------------------------------------

# Disabling certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def autopush_TrendMicro_VisionOne(misp_tag_list):
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    start_time = time.time()
    for tag in misp_tag_list:
        events = misp.search(controller='events', tag=tag, org=ORG_TO_SEARCH_FOR, to_ids=1, pythonify=True)
        for event in events:
            iocs, event_name, org_name = event.attributes, event.info, event.Orgc.name
            ip_list, domain_list, url_list, sha1_list, sha256_list = [], [], [], [], []
            print(event_name)
            for ioc in iocs:
                att_count, att_list, ioc_type, ioc_value = 0, [], ioc.type, ioc.value
            '''
            # You can use this piece of code to check for attribute tag. In this case it searches for recorded-future:risk-score="SOMETHING" and if it's more than 80 then appends value to the list. 
                if  org_name == ORG_:                                                                                                                       #       |
                    try:                                                                                                                                    #       |
                        attribute_tag_list = ioc.Tag                                                                                                        #       |
                        if attribute_tag_list:                                                                                                              #       |    
                            pattern = r'recorded-future:risk-score="(\d+)"'                                                                                 #    <--|
                            att_list = [att_tag.name for att_tag in attribute_tag_list]                                                                     #       |
                            print(att_list)                                                                                                                 #       |
                            for tag_ in att_list:                                                                                                           #       |
                                match_rf_risk_score = re.search(pattern, tag_)                                                                              #       |
                                risk_score_number = int(match_rf_risk_score.group(1)) if match_rf_risk_score else None                                      #       |
                                if risk_score_number is not None and risk_score_number>=80 and att_count==0:                                                #    <--
                                    if ioc_type == 'ip-src' or ioc_type =='ip-dst': ip_list.append(ioc_value)
                                    elif ioc_type == 'domain': domain_list.append(ioc_value)
                                    elif ioc_type =='url': url_list.append(ioc_value)
                                    elif ioc_type == 'ip-dst|port' or ioc_type == 'ip-src|port':
                                        cleaned_ioc = ioc_value_cleaner(ioc_value)
                                        ip_list.append(cleaned_ioc)
                                    elif ioc_type == 'hostname|port':
                                        cleaned_ioc = ioc_value_cleaner(ioc_value)
                                        domain_list.append(cleaned_ioc)
                                    elif ioc_type == 'sha1': sha1_list.append(ioc_value)
                                    elif ioc_type == 'sha256': sha256_list.append(ioc_value)
                                    att_count=1
                    except Exception as e:
                        print("--------------------------ERROR--------------------------: ", e) 
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
                elif ioc_type == 'sha1': sha1_list.append(ioc_value)
                elif ioc_type == 'sha256': sha256_list.append(ioc_value)

            if ip_list: send_it_to_VisionOne(ip_list, 'ip', event_name)
            if domain_list: send_it_to_VisionOne(domain_list, 'domain', event_name)
            if url_list: send_it_to_VisionOne(url_list, 'url', event_name)
            if sha1_list: send_it_to_VisionOne(sha1_list, 'fileSha1', event_name)
            if sha256_list: send_it_to_VisionOne(sha256_list, 'fileSha256', event_name)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print("Elapsed time misp.search: ", elapsed_time)

def ioc_value_cleaner(ioc_value):
    if '|' in ioc_value:
        value_no_port = ioc_value.split('|')
        value_no_port_cleaned = value_no_port[0]
    return value_no_port_cleaned

def send_it_to_VisionOne(bad_ioc, ioc_type, event_name):
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

if __name__ == '__main__' :
    tags = [''] # <----------------ADD TAGS HERE-----------------------
    autopush_TrendMicro_VisionOne(tags)
