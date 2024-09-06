import requests
import json
import threading
from queue import Queue


# MISP Config
misp_url = 'https://***********************************' # Add your MISP instance base url
api_key = '********************************************' # Add API Key
headers = {
    'Authorization': api_key,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

tags_to_keep = ['']  # Add tag names you want to keep
num_worker_threads = 20  # Max thread number MODIFY THIS TO RUN FASTER/SLOWER  (try to NOT DoS yourself)
queue = Queue() # Task queue

def get_all_tags(): 
    try:
        url = f"{misp_url}/tags"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error asking for tags list: {e}")
        return None

def delete_tag(tag_id, tag_name): 
    try:
        url = f"{misp_url}/tags/delete/{tag_id}"
        response = requests.post(url, headers=headers)
        response.raise_for_status() 
        print(f"Tag {tag_id} - {tag_name} deleted.")
    except requests.exceptions.RequestException as e:
        print(f"Error deleting {tag_id} - {tag_name}: {e}")

def process_tag():
    while True:
        tag = queue.get()  # Get tag from queue
        if tag is None:  # Stops if tag == None
            break
        try:
            tag_name = tag['name']
            tag_id = tag['id']
            if tag_name not in tags_to_keep:
                delete_tag(tag_id, tag_name)
            else:
                print(f"Tag {tag_name} kept.")
        finally:
            queue.task_done()  # Task completed

def main():
    tags = get_all_tags()
    
    if tags:
        # Create + start threads
        threads = []
        for _ in range(num_worker_threads):
            thread = threading.Thread(target=process_tag)
            thread.start()
            threads.append(thread)

        # Add tags to queue
        for tag in tags['Tag']:
            queue.put(tag)   
        queue.join() # Wait for tasks to complete
        for _ in range(num_worker_threads): # Send None
            queue.put(None)
        for thread in threads: # Wait for threads to complete
            thread.join()

        print("Done")

if __name__ == '__main__':
    main()
