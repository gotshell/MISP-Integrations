# MISP-Integrations

# Utils.txt: Tips and tricks / troubleshooting file

# autopush.py ---> Push Misp events to Qradar Reference Set

The script works with Misp and Qradar APIs. In order to make it work, you need to change some settings. 

------------------------------------------------ MISP API Settings ---------------------------------------------------------

        20  misp_url = 'https://'    # <-------- add misp instance url here
        21  misp_key = ''            # <-------- add misp api key (you maybe should allow IP's from MISP GUI -> api key settings)

------------------------------------------------ Qradar API Settings -------------------------------------------------------

        24  qradar_url = 'https://________________/api/reference_data/sets/bulk_load/{list_name}' # <------- add Qradar instance IP/URL here
        25  qradar_key = ''                                                                       # <------- add Qradar api key

------------------------------------------------ Other settings -------------------------------------------------------------

        137  misp_tag_list = [''] # <----------------- add tag here 


LOGIC: 
- Search for events by tag(s)
- For each event create a list of attributes
- Push the list to Qradar's Reference Set (RS)
  - If the RS already exists, wipe the contents and push new attributes
  - If the RS doesn't exist, create the RS and push attributes.
  - The name of the RS comes from MISP's event info.
- If the list is bigger than 10k attributes, then split it and POST chunks to Qradar.

More:
You can easily change the get_ioc() function to check for whatever you need. For instance: pushing just attributes with - a certain tag - IDS enabled - risk score >/< *number* etc. 

ToDo:
- Implement a proper way to check if the RF already exists --> Just check for 404 is bad as f*ck but works :')


# autofetch.py ---> Fetch enabled feeds by tag

---------------------------------------MISP API configuration---------------------------------------------

        misp_url = '' # <---------- Please add your MISP URL
        misp_key = '' # <---------- Please add your MISP API Key
        misp_verifycert = False 

----------------------------------------------------------------------------------------------------------

        32    tags = ['ETPRO','RecordedFuture', 'to_qradar'] # <------ ADD TAGS HERE // Just remember to assign tags to each feed by using MISP's UI

----------------------------------------------------------------------------------------------------------

LOGIC: 
- Search for feeds by tag(s)
- If an enabled feed does have a 'Tag' that is part of the list we gave it, the script will fetch it (it will create a backgorund job, managed by default worker --> could take a while if you don't have many default workers but a lot of feeds)


ToDo: 
- maybe implement a module that pulls/pushes from/to remote servers.


# misp_to_TM_UDSO.py ---> Push MISP IOC(s) to Trend Micro User Defined Suspicious Objects List

There's always some stuff to change.

------------------------------------------------ MISP Settings -------------------------------------------------------------

        misp_url = '' # <---- example: https://misp.yourdomain.com
        misp_key = '' # <---- Your MISP API key
        misp_verifycert = True

---------------------------------------- TrendMicro Apex Central API Settings -----------------------------------------------

        use_url_base = ''  #      <---- Complete url base - example: https://yourdomain.com
        use_application_id = ''   <---- Can create one of this at TM AC Console Administration --> Settings --> Automation API Access Settings
        use_api_key = ''          <---- Can create one of this at TM AC Console Administration --> Settings --> Automation API Access Settings

------------------------------------------------------------------------------------------------------------------------------

LOGIC: 
- Search for events by tag(s)
- For each ioc in each event, check for the timestamp and add 30 days.
- If cases then do some changes
- Send IOC value, IOC type, IOC expiration date (timestamp+30days), event name through API to TM.
- Each IOC will be sent via a separate PUT request --> could take a while if you're pushing a huge amount of IOCs.


# misp_to_VisionOne.py ---> Push Misp's events to TrendMicro VisionOne

------------------------------------------------ MISP Settings -------------------------------------------------------------

        misp_url = '' # <---- example: https://misp.yourdomain.com
        misp_key = '' # <---- Your MISP API key
        misp_verifycert = True

------------------------------------------ TrendMicro VisionOne API Settings -------------------------------------------------

        url_base = 'https://api.eu.xdr.trendmicro.com/'            
        url_path = '/v3.0/threatintel/suspiciousObjects'
        token = '' # <--------------------------------------Enter VisionOne Token [Administration/API-KEYS/add_new_api_key]
        query_params = {}
        headers = {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json;charset=utf-8'
        }

------------------------------------------------ GLOBAL VARIABLES -----------------------------------------------------------

        DAYS_TO_EXPIRATION = '15'          <---- according to your needs
        RISK_LEVEL = 'high'                <---- according to your needs
        SCAN_ACTION = 'block'              <---- according to your needs
        
------------------------------------------------------------------------------------------------------------------------------

LOGIC: 
- Search for events by tag(s)
- For each event create lists by type and fill them with iocs
- Create body json from each ioc list
- Send json to VisionOne through API. 


# push_last_5m_events.py ---> Push newest Misp's events to TrendMicro VisionOne and Qradar Reference Sets

This script searches for events in the last 5 minutes and pushes attributes value to Qradar's reference sets and VisionOne UDSO list.
Please add your keys/urls first

If you don't need qradar integration just comment line 96 and 97

You should setup a cronjob that runs this code every 5 minutes. You can use the following: 
- */5 7-18 * * * /path/to/your/python3 /path/to/your/push_last_events.py

------------------------------------------------ MISP Settings -------------------------------------------------------------

        misp_url = '' # <---- example: https://misp.yourdomain.com
        misp_key = '' # <---- Your MISP API key
        misp_verifycert = True
        
------------------------------------------------ Qradar API Settings -------------------------------------------------------------

        qradar_url = 'https://_____________/api/reference_data/sets/bulk_load/'
        qradar_key = ''

------------------------------------------ TrendMicro VisionOne API Settings -------------------------------------------------

        url_base = 'https://api.eu.xdr.trendmicro.com/'            
        url_path = '/v3.0/threatintel/suspiciousObjects'
        token = '' # <--------------------------------------Enter VisionOne Token [Administration/API-KEYS/add_new_api_key]
        query_params = {}
        headers = {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json;charset=utf-8'
        }

------------------------------------------------ GLOBAL VARIABLES -----------------------------------------------------------

        QRADAR_IP_REFERENCE_SET = 'qradar_reference_set_name_IP'           <---- according to your needs
        QRADAR_URL_REFERENCE_SET = 'qradar_reference_set_name_URL'         <---- according to your needs
        LAST_MINUTES = '5m'                                                <---- according to your needs
        DAYS_TO_EXPIRATION = '15'                                          <---- according to your needs
        RISK_LEVEL = 'high'                                                <---- according to your needs
        SCAN_ACTION = 'block'                                              <---- according to your needs
        
------------------------------------------------------------------------------------------------------------------------------

Cyall BRN

