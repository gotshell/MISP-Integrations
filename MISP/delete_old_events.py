import urllib3
from pymisp import PyMISP
from datetime import datetime
from datetime import date
from dateutil.relativedelta import relativedelta

misp_url = 'https://yourMispDomain'
misp_key = '' 
misp_verifycert = True

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def old_event_eraser(misp, delete_from):
    events = misp.search(org='')                                                           # <-------- Search by org/tag etc.
    for event in events:
        last_change_timestamp = datetime.fromtimestamp(int(event['Event']['timestamp']))
        event_info = event['Event']['info']
        if last_change_timestamp.date() < delete_from:
            misp.delete_event(event)
            print(event_info)
            print('Deleted')

if __name__ == '__main__' :
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    today = date.today()
    one_month_ago = today - relativedelta(months=1)                                         # <------- It will delete events older than 1 month
    old_event_eraser(misp, one_month_ago)
