# ---------------------------------------------Libraries----------------------------------------------------
import urllib3
from pymisp import PyMISP
# from colorama import init as colorama_init # Just if you need some colors :)
# from colorama import Fore # Just if you need some colors :)
# from colorama import Style # Just if you need some colors :)
# colorama_init() # Just if you need some colors :)

# ---------------------------------------MISP API configuration---------------------------------------------
misp_url = '' # <---------- Please add your MISP URL
misp_key = '' # <---------- Please add your MISP API Key
misp_verifycert = False 
# ----------------------------------------------------------------------------------------------------------

# Disable certificate related warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fetches events having tag in tag_list
def fetch_all_events(tag_list):
    feeds = misp.feeds()
    for feed in feeds:
        if 'Tag' in feed:
            tagname=feed['Tag']['name']
            if tagname in tag_list and feed['Feed']['enabled'] != False:
                # uncomment to see the *magic* 
                # print("Fetching: "+feed['Feed']['name']+f" having tag: {Fore.RED}"+tagname +f"{Style.RESET_ALL}") 
                misp.fetch_feed(feed['Feed']['id'])
                # print(f"{Fore.BLUE}"+feed['Feed']['name']+f"{Style.RESET_ALL}"+f" {Fore.GREEN}Fetch Job Queued{Style.RESET_ALL}!")
 
if __name__ == '__main__' :
    tags = [] # <----------ADD TAGS HERE---Example: 'misptag' ------- // Just remember to assign tags to each feed by using MISP's UI
    tag_list_no_duplicates = list(set(tags))
    if tag_list_no_duplicates:
        # Connect to MISP
        misp = PyMISP(misp_url, misp_key, misp_verifycert)
        fetch_all_events(tag_list_no_duplicates)
    else:
        print('Please, add at least one tag to \'tags\' variable')
