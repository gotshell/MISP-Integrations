import requests
import json
import time
import logging
from colorama import init, Fore, Back, Style
import urllib3
from datetime import datetime, timedelta
import os

# Gets Qradar Reference Set containing malicious IPs, checks each IP that was seen in the last 180days on abuseipdb, if score==0 then removes it from the reference set.

init(autoreset=False)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QRADAR_URL = "https://YOUR_QRADAR/api"
API_TOKEN = ''
REFERENCE_SET_NAME = 'REFERENCE SET NAME'
ABUSEIPDB_API_TOKEN = 'ABUSEIPDB TOKEN'
ABUSEIPDB_MAX_AGE_IN_DAYS = '365'
headers = {
    'Content-Type': 'application/json',
    'SEC': API_TOKEN
}
def get_qradar_reference_set():
    url = f"{QRADAR_URL}/reference_data/sets/{REFERENCE_SET_NAME}"
    try:    
        response = requests.get(url, headers=headers, verify=False)  
        if response.status_code == 200:
            data = response.json()
            reference_list = data.get("data", [])
            return reference_list
        else:
            print(f"Error getting Qradar reference set - {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print('An error occurred while sending the request:', str(e))


def check_abuse(ip_to_check):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip_to_check,
        'maxAgeInDays': ABUSEIPDB_MAX_AGE_IN_DAYS
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_TOKEN
    }
    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        if response.status_code == 429:
            logging.error(f'Abuseipdb API Limit Reached {response.status_code}: {response.text}')
            exit(1)
        elif response.status_code != 200:
            logging.error(f"API Error {response.status_code}: {response.text}")
            return None
        elif response.status_code == 200:
            decodedResponse = json.loads(response.text)
            abuse_score = int(decodedResponse["data"]["abuseConfidenceScore"])
            if abuse_score > 0: logging.info(Fore.RED + f'IP {ip_to_check} has score {abuse_score}'+ Style.RESET_ALL)
            else: logging.info(Fore.GREEN + f'IP {ip_to_check} has score: {abuse_score}'+ Style.RESET_ALL)
    except  Exception as e: print(f"Error: {e}")
    return abuse_score

def check_timestamp(last_seen_timestamp_ms):
    current_timestamp_ms = int(datetime.utcnow().timestamp() * 1000)
    some_time_ago = current_timestamp_ms - (180 * 24 * 60 * 60 * 1000) # 6 Months
    return last_seen_timestamp_ms < some_time_ago

def delete_ioc_from_rs(ioc_to_remove):
    url = f"{QRADAR_URL}/reference_data/sets/{REFERENCE_SET_NAME}/{ioc_to_remove}"
    try:
        response = requests.delete(url, headers=headers, verify=False) 
        if response.status_code == 200: logging.info(f"The following IOC {ioc_to_remove} has been successfully removed from the reference set.")
        else: logging.info(f"Errore {response.status_code}: {response.text}")
    except requests.exceptions.RequestException as e:
        logging.info(f'Qradar Delete API Request Error: {str(e)}')


if __name__ == '__main__':
    file_path = r'/your_path/above_0.txt'
    above_0_old_list = []
    above_0_list = []
    count = 0
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        with open(file_path, 'r') as old_above_0_file: above_0_old_list = [line.strip() for line in old_above_0_file.readlines()]
    qradar_rs_list = get_qradar_reference_set()
    try:
        for ioc in qradar_rs_list:
            if count > 1000: break
            current_ioc = ioc.get('value')
            if current_ioc not in above_0_old_list:
                last_seen_timestamp = ioc.get('last_seen')
                if check_timestamp(last_seen_timestamp): 
                    abuse_score_ = check_abuse(current_ioc)
                    if abuse_score_==0: delete_ioc_from_rs(current_ioc)
                    elif abuse_score_>0: above_0_list.append(current_ioc)
                    elif abuse_score_ == None: continue
                    count += 1 
    except KeyboardInterrupt: print("\nIntercepted CTRL+C, exit...")
    except Exception as e: print(f"Errore: {e}")
    finally:
        with open(file_path, 'a') as above_0_file:
            # if count > 0: print(count)
            if above_0_list: print(f'Scrivo nel file')
            for item in above_0_list: above_0_file.write(item + "\n")
