import re
import requests
from pymisp import PyMISP
import logging
from datetime import datetime, timedelta, timezone
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# APP Registrated \ SABES' Azure Platform

tenant_id = "your tenant id"
client_id = "your client id"
client_secret = "your client secret"

misp_url = 'https://yourdomain/'
misp_key = 'your misp key'
misp_verifycert = False

# ------------------------------------------------------------------------------------------------------
ORG_TO_SEARCH_FOR = [] # Tags to search for
TAGS_TO_SEARCH_FOR = []
EXP_DAYS = 30
# ------------------------------------------------------------------------------------------------------

def get_iocs_from_misp(misp_tag_list, access_token, ioc_list):
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    total_domains, total_urls, total_ips, total_sha1, total_sha256, iocs_count = 0, 0, 0, 0, 0, 0
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    logging.info(f"Tags provided {misp_tag_list}")
    for tag in misp_tag_list:
        logging.info(f'Processing tag: {tag}')
        # start_time = time.time()
        events = misp.search(controller='events', tag=tag, org=ORG_TO_SEARCH_FOR, last='20m', to_ids=1, pythonify=True)
        # end_time = time.time()
        # elapsed_time = end_time - start_time
        # logging.info(f"Elapsed time misp.search(tag={tag}): {elapsed_time}")
        
        for event in events:
            ip_list, domain_list, url_list, sha1_list, sha256_list =  set(), set(), set(), set(), set()
            iocs = event.attributes
            event_name = event.info
            logging.info(f"Processing event: {event_name}")
            # logging.info(f"Attributes list: {iocs}")
            org_name = event.Orgc.name
            for ioc in iocs:
                att_count, att_list, ioc_type, ioc_value = 0, [], ioc.type, ioc.value
                if ioc_value not in ioc_list:
                    if ioc_type == 'ip-src' or ioc_type =='ip-dst': ip_list.add(ioc_value)
                    elif ioc_type == 'domain': domain_list.add(ioc_value)
                    elif ioc_type =='url': url_list.add(ioc_value)
                    elif ioc_type == 'ip-dst|port' or ioc_type == 'ip-src|port':
                        cleaned_ioc = ioc_value_cleaner(ioc_value)
                        ip_list.add(cleaned_ioc)
                    elif ioc_type == 'hostname|port':
                        cleaned_ioc = ioc_value_cleaner(ioc_value)
                        domain_list.add(cleaned_ioc)
                    elif ioc_type == 'sha1': sha1_list.add(ioc_value)
                    elif ioc_type == 'sha256': sha256_list.add(ioc_value)
            domain_len, url_len, ip_len, sha1_len, sha256_len = len(domain_list), len(url_list), len(ip_list), len(sha1_list), len(sha256_list)
            if domain_len: 
                push_ioc_to_defender(domain_list, domain_len, 'DomainName', access_token, event_name)
                total_domains += domain_len
            if url_list: 
                push_ioc_to_defender(url_list, url_len, 'Url', access_token, event_name)
                total_urls += url_len
            if ip_list: 
                push_ioc_to_defender(ip_list, ip_len, 'IpAddress', access_token, event_name)
                total_ips += ip_len
            if sha1_list: 
                push_ioc_to_defender(sha1_list, sha1_len, 'FileSha1', access_token, event_name)
                total_sha1 += sha1_len
            if sha256_list: 
                push_ioc_to_defender(sha256_list, sha256_len, 'FileSha256', access_token, event_name)
                total_sha256 += sha256_len

    if total_domains or total_urls or total_ips or total_sha1 or total_sha256:  logging.info(f"Processed {total_domains} domains, {total_urls} urls, {total_ips} IPs, {total_sha1} Sha1 hashes, {total_sha256} Sha256 hashes")
    iocs_count = total_domains + total_urls + total_ips + total_sha1 + total_sha256
    if total_domains or total_urls or total_ips or total_sha1 or total_sha256: logging.info(f"Processed a total of {iocs_count} IOCs")

def ioc_value_cleaner(ioc_value):
    return ioc_value.split('|')[0] if '|' in ioc_value else ioc_value

def delete_iocs_from_defender(id_list, access_token):    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    try:
        for id_ioc in id_list:
            url = f'https://api.securitycenter.microsoft.com/api/indicators/{id_ioc}'
            response = requests.request(method='DELETE', url=url, headers=headers)
            if response.status_code == 200:  # DELETE OK
                print(f"IOC {id_ioc} cancellato correttamente")
            else:
                print(f"Error IOC has not been deleted: {id_ioc}: {response.status_code} - {response.text}")
    except  Exception as e:
        print(f"Error: {e}")

def chunk_list(data, size):
    data_ = list(data)
    for i in range(0, len(data), size): 
        yield data_[i:i + size]

def push_ioc_to_defender(list_, list_len, list_type, access_token, event_name):
    now_utc = datetime.now(timezone.utc)  
    expiration = now_utc + timedelta(days=EXP_DAYS)  
    expiration_time_str = expiration.strftime("%Y-%m-%dT%H:%M:%SZ") 

    url = 'https://api.securitycenter.microsoft.com/api/indicators/import'
    post_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    for index, chunk in enumerate(chunk_list(list_, 500), start=1):
        indicators_payload = {
            "Indicators": [   
                {
                    "indicatorValue": ioc,  
                    "indicatorType": list_type,  
                    "title": f'MISP event: {event_name}',
                    "application": "mloss custom script", 
                    "expirationTime": expiration_time_str,  
                    "action": "Block",  
                    "severity": "High",  
                    "description": "IoC fetched by MISP instance", 
                    "recommendedActions": "Check",  
                    "rbacGroupNames": []  
                } for ioc in chunk  
            ]
        }
        logging.info(f"Sending chunk {index} con {len(chunk)} IoC...")
        response = requests.post(url, headers=post_headers, json=indicators_payload)

        if response.status_code == 200:logging.info(f"[✅] Chunk {index} successfully sent")
        else:
            logging.error(f"[❌] Chunk Error {index}: {response.status_code}")
            logging.error(response.text)

def get_access_token():
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://api.securitycenter.microsoft.com/.default"
    }
    token_headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    token_response = requests.post(token_url, data=token_data, headers=token_headers)
    token_response.raise_for_status()
    access_token = token_response.json()["access_token"]
    return access_token

def get_defender_ioc_list():
    url = "https://api.securitycenter.microsoft.com/api/indicators" #?$filter=indicatorType eq 'IpAddress'
    access_token = get_access_token()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    response = requests.get(url,headers=headers)
    if response.status_code == 200:
        data = response.json()
        list_iocs_estratti = [ioc['indicatorValue'] for ioc in data['value']] if data is not None else []
        return list_iocs_estratti
    else:
        print("[❌] Error:", response.status_code)
        print(response.text)

def get_defender_ioc_and_ids():
    url = "https://api.securitycenter.microsoft.com/api/indicators" #?$filter=indicatorType eq 'IpAddress'
    access_token = get_access_token()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print("[✅] Got IOCs")
        data = response.json()
        dict_iocs_estratti = {
            ioc["id"]: ioc["indicatorValue"]
            for ioc in data.get("value", [])
        } 
        return dict_iocs_estratti
    else:
        print("[❌] Error:", response.status_code)
        print(response.text)
        return {}
    
if __name__ == '__main__':
    access_token = get_access_token()
    ioc_list = get_defender_ioc_list()
    get_iocs_from_misp(TAGS_TO_SEARCH_FOR, access_token, ioc_list)

    
    
