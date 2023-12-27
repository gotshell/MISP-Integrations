# ---------------------------------------------Libraries----------------------------------------------------

import re
import requests
import json
from pymisp import ExpandedPyMISP
import base64
import jwt
import hashlib
import time
from datetime import datetime,timedelta
import urllib3

# ---------------------------------------MISP API configuration----------------------------------------------

misp_url = ''
misp_key = ''
misp_verifycert = True

# -------------------------------Trend Micro Apex Central API configuration----------------------------------

use_url_base = '' 
use_application_id = ''
use_api_key = '' 

# -----------------------------------------------------------------------------------------------------------

# Disabling certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def autopush_TrendMicro_ApexCentral(misp_tag_list):
    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    # start_time = time.time()

    for tag in misp_tag_list:
        events = misp.search(tag=tag)
        for event in events:
            # iocs_list = []
            iocs = event['Event']['Attribute']
            event_name = event['Event']['info']
            for ioc in iocs:
                ioc_type = ioc['type']
                ioc_value = ioc['value']
                ioc_timestamp = datetime.utcfromtimestamp(int(ioc['timestamp']))
                ioc_expire_date = ioc_timestamp + timedelta(days=30)
                ioc_expire_date_iso = ioc_expire_date.isoformat()
                if ioc_type == 'ip-src' or ioc_type =='ip-dst':
                    ioc_type = 'ip'
                    send_it_to_TM(ioc_value, ioc_type,ioc_expire_date_iso, event_name)
                elif ioc_type == 'domain':
                    send_it_to_TM(ioc_value, ioc_type,ioc_expire_date_iso, event_name)
                elif ioc_type =='url':
                    send_it_to_TM(ioc_value, ioc_type,ioc_expire_date_iso, event_name)
                elif ioc_type == 'ip-dst|port' or ioc_type == 'ip-src|port':
                    ioc_type = 'ip'
                    cleaned_ioc = ioc_value_cleaner(ioc_value)
                    send_it_to_TM(cleaned_ioc, ioc_type,ioc_expire_date_iso, event_name)
                elif ioc_type == 'hostname|port':
                    ioc_type = 'domain'
                    cleaned_ioc = ioc_value_cleaner(ioc_value)
                    send_it_to_TM(cleaned_ioc, ioc_type,ioc_expire_date_iso, event_name)

    # end_time = time.time()
    # elapsed_time = end_time - start_time
    # print("Elapsed time misp.search: ", elapsed_time)

def create_checksum(http_method, raw_url, headers, request_body):
    string_to_hash = http_method.upper() + '|' + raw_url.lower() + '|' + headers + '|' + request_body
    base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
    return base64_string

def create_jwt_token(appication_id, api_key, http_method, raw_url, headers, request_body,
                     iat=time.time(), algorithm='HS256', version='V1'):
    payload = {'appid': appication_id,
               'iat': iat,
               'version': version,
               'checksum': create_checksum(http_method, raw_url, headers, request_body)}
    token = jwt.encode(payload, api_key, algorithm=algorithm)
    return token  

def ioc_value_cleaner(ioc_value):
    if '|' in ioc_value:
        value_no_port = ioc_value.split('|')
        value_no_port_cleaned = value_no_port[0]
    return value_no_port_cleaned

def send_it_to_TM(bad_ioc, ioc_type, ioc_expire_date_iso, event_name):

    productAgentAPIPath = '/WebApp/api/SuspiciousObjects/UserDefinedSO/'
    # productAgentAPIPath = '/WebApp/api/v1/SuspiciousObjects/UserDefinedSO/'
    canonicalRequestHeaders = ''
    useQueryString = '' 

    payload = {
    "param":{
            "type":f"{ioc_type}",
            "content":f"{bad_ioc}",
            "notes":f"{event_name}",
            "scan_action":"block",
            "expiration_utc_date": f"{ioc_expire_date_iso}"
            }
    }
    useRequestBody = json.dumps(payload)  
    jwt_token = create_jwt_token(use_application_id, use_api_key, 'PUT',
                                productAgentAPIPath + useQueryString,
                                canonicalRequestHeaders, useRequestBody, iat=time.time())
    headers = {'Authorization': 'Bearer ' + jwt_token, 'Content-Type': "application/json"}

    r = requests.put(use_url_base + productAgentAPIPath + useQueryString, headers=headers, data=useRequestBody, verify=False) 
    if r.status_code == 200:
        print('----------------------------------------------------------------------------------')
        print('IOC sent to TM instance')
        print('Type:',ioc_type)
        print('IOC:',bad_ioc)
        print('Event Name:',event_name)
        print('Action: block')
        print('Expire date:',ioc_expire_date_iso)


if __name__ == '__main__' :
    tags = ['ANYTAG']
    autopush_TrendMicro_ApexCentral(tags)



"""
# Checks for each attribute's tag, if the tag is found then pushes the attribute's value to TM AC only if the tag (in this case risk-score) contains a number higher than 90. 
# You can easily adapt it to your needs

for tag in misp_tag_list:
        events = misp.search(tag=tag)
        for event in events:
            # iocs_list = []
            iocs = event['Event']['Attribute']
            event_name = event['Event']['info']
            for ioc in iocs:
                att_count = 0
                att_list = []
                ioc_type = ioc['type']
                ioc_value = ioc['value']
                ioc_timestamp = datetime.utcfromtimestamp(int(ioc['timestamp']))
                ioc_expire_date = ioc_timestamp + timedelta(days=30)
                ioc_expire_date_iso = ioc_expire_date.isoformat()
                try:
                    attribute_tag_list = ioc.get('Tag', [])
                    if attribute_tag_list:   
                        pattern = r'recorded-future:risk-score="(\d+)"'     
                        att_list = [att_tag['name'] for att_tag in attribute_tag_list]
                        for tag_ in att_list:
                            match_rf_risk_score = re.search(pattern, tag_)
                            risk_score_number = int(match_rf_risk_score.group(1)) if match_rf_risk_score else None
                            if risk_score_number is not None and risk_score_number >= 90 and att_count==0: 
                                if ioc_type == 'ip-src' or ioc_type =='ip-dst':
                                    ioc_type = 'ip'
                                    send_it_to_TM(ioc_value, ioc_type,ioc_expire_date_iso, event_name)
                                elif ioc_type == 'domain':
                                    send_it_to_TM(ioc_value, ioc_type,ioc_expire_date_iso, event_name)
                                elif ioc_type =='url':
                                    send_it_to_TM(ioc_value, ioc_type,ioc_expire_date_iso, event_name)
                                elif ioc_type == 'ip-dst|port' or ioc_type == 'ip-src|port':
                                    ioc_type = 'ip'
                                    cleaned_ioc = ioc_value_cleaner(ioc_value)
                                    send_it_to_TM(cleaned_ioc, ioc_type,ioc_expire_date_iso, event_name)
                                elif ioc_type == 'hostname|port':
                                    ioc_type = 'domain'
                                    cleaned_ioc = ioc_value_cleaner(ioc_value)
                                    send_it_to_TM(cleaned_ioc, ioc_type,ioc_expire_date_iso, event_name)
                                att_count=1

"""









