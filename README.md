# MISP-Integrations

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


Cyall BRN

