import os
import sys
import hashlib
import requests
import argparse
import ntpath
from time import sleep
from dotenv import load_dotenv

# Setup instructions:
# - Optional: Create & start virtual environment
#      > python3 -m venv venv
#      > .\venv\Scripts\activate
# - Install requirements 
#      > python3 -m pip install -r requirements.txt
# - Create .env file with the API_KEY and FILE_TO_SCAN 
#   If the file is specified as an arg. it supersedes the one from env.
# - Run the script with > python3 scanFile.py [samplefile.txt]

class APIWrapper:
    api_base_url = "https://api.metadefender.com/v4/"
        
    def __init__(self, api_key):
        self.api_key = api_key
    
    # Handle generalized response error codes
    def __handle_API_response(self, response):
        if (response.status_code==400):
            print("Received Bad request.", file=sys.stderr)
            return (False, 400, response.json())
        elif response.status_code == 401:
            print("Received Unauthorised request. " + str(response.json()["error"]["messages"]), file=sys.stderr)
            return (False, 401, response.json())
        elif response.status_code == 404:
            print("Received Not found. " + str(response.json()["error"]["messages"][0]), file=sys.stderr)
            return (False, 404, response.json())
        elif response.status_code == 500:
            print("Received Internal server error.", file=sys.stderr)
            return (False, 500, response.json())
        elif response.status_code!=200:
            print("Received " + str(response.status_code) + " from server.", file=sys.stderr)
            return (False, response.status_code, response.json())
        
        # Request succeeded with 200
        return (True, 200, response.json())
    
    def check_hash(self, hash):
        lookup_url = self.api_base_url + "hash/" + hash
        headers = {
            "apikey": self.api_key,
        }
        response = requests.request("GET", lookup_url, headers=headers)
        return self.__handle_API_response(response)
    
    def analyze_file(self, file_path):
        analyze_url = self.api_base_url + "file"
        headers = {
            "apikey": self.api_key,
            "filename": ntpath.basename(file_path),
            "samplesharing": "1",
            "privateprocessing": "0",
            "rule": "multiscan",
        }
        
        # Submit the file for analisys
        with open(file_path, 'rb') as file:
            files = {"file": file}
            response = requests.request("POST", analyze_url, headers=headers, files=files)
        return self.__handle_API_response(response)
    def fetch_analysis_result(self, dataId):
        result_url = self.api_base_url + "file/" + dataId
        headers = {
            "apikey": self.api_key,
        }
        response = requests.request("GET", result_url, headers=headers)
        return self.__handle_API_response(response)

def main():
    # Load .env file and options
    load_dotenv()
    API_KEY = os.getenv('API_KEY')
    FILE_TO_SCAN = os.getenv('FILE_TO_SCAN')
    
    # Load args
    parser = argparse.ArgumentParser(description='Run analisys on a file using the MetaDefender Cloud API.')
    parser.add_argument('filename', help='a file to scan', type=str, nargs='?', default=FILE_TO_SCAN)
    args = parser.parse_args()
    
    # Overrite file to scan if specified
    FILE_TO_SCAN = args.filename
    
    print("Filename: " + FILE_TO_SCAN)
    if not os.path.exists(FILE_TO_SCAN):
        print("File does not exist")
        return
    
    # Calculate hash
    hash = ""
    with open(FILE_TO_SCAN, 'rb') as f:
        hash = hashlib.file_digest(f, 'sha256').hexdigest()
    print("Calculated hash: " + hash)
    
    # Scan the selected file
    api = APIWrapper(API_KEY)
    (success, code, response) = api.check_hash(hash)
    
    # Submit file for scanning
    if success==False and code==404:
        print("Submitting file for scanning.")
        (analysis_success, analysis_code, analysis_response) = api.analyze_file(FILE_TO_SCAN)
        if analysis_success!=True:
            print("Could not start sample analysis")
            return
        # print(analysis_response)
        submission_id = analysis_response["data_id"]
        
        print("Waiting for analysis to complete...")
        scan_percentage = 0
        while(scan_percentage != 100):
            (result_success, result_code, result_response) = api.fetch_analysis_result(submission_id)
            if result_success != True:
                print("Failed to check for submission results")
                return
            scan_percentage = result_response["scan_results"]["progress_percentage"]
            # Wait 10 seconds before checking again
            sleep(10)
            
    elif success==True and code==200:
        print("Hash is present in the cache.")
    
    # Either the hash is found, or the analisys is complete
    (success, code, response) = api.check_hash(hash)
    if success==False:
        print("The file was analized, but is not present in the cache")
        return
    else:
        # print(response)
        print("Overall status: " + str(response["scan_results"]["scan_all_result_a"]))
        
        for av_name, av_result in response["scan_results"]["scan_details"].items():
            print("---------------------------")
            print("Engine: "+ av_name)
            print("ThreatFound: "+ av_result["threat_found"])
            print("ScanResult: "+ str(av_result["scan_result_i"]))
            print("DefTime: "+ av_result["def_time"])
        
if __name__ == "__main__":
    main()