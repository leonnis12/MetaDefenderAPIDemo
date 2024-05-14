import os
import sys
import hashlib
import requests
import argparse
import ntpath
from colorama import just_fix_windows_console, Fore, Back, Style
from colorama import Fore, Back, Style
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

# This script uses a wrapper around the v4 API to encapsulate the interactions with specific endpoints. Based on it's usecase and integration,
# the handling of the response errors could be implemented more generalized, or more thoroughly. The sleep implementation could be replaced,
# with threading for not blocking the entire program, again depending on the usecase, but for this example it was out of scope. 

# Also, for the "Fetch analysis result" endpoint, scan_results.progress_percentage is mentioned in the description in the docs, but not in the
# response body specification a few lines below. Still it appeared to be sent, so it was used for describing the progress.


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
    
    # Call the check hash endpoint to check if the file was scanned before, and get it's results
    def check_hash(self, hash):
        lookup_url = self.api_base_url + "hash/" + hash
        headers = {
            "apikey": self.api_key,
        }
        response = requests.request("GET", lookup_url, headers=headers)
        return self.__handle_API_response(response)
    
    # Call the analyze file endpoint to submit a file for analysis
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
    
    # Retreive a running analysis status, and it's results
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
    
    print(Fore.LIGHTRED_EX + "Filename: " + Fore.GREEN + FILE_TO_SCAN)
    if not os.path.exists(FILE_TO_SCAN):
        print(Fore.LIGHTRED_EX + "File does not exist", file=sys.stderr)
        return
    
    # Calculate hash
    hash = ""
    with open(FILE_TO_SCAN, 'rb') as f:
        hash = hashlib.file_digest(f, 'sha256').hexdigest()
    print(Fore.LIGHTRED_EX + "Calculated hash: " + Fore.GREEN + hash)
    
    # Scan the selected file
    api = APIWrapper(API_KEY)
    (success, code, response) = api.check_hash(hash)
    
    # Submit file for scanning
    if success==False and code==404:
        print("Submitting file for scanning.")
        (analysis_success, analysis_code, analysis_response) = api.analyze_file(FILE_TO_SCAN)
        if analysis_success!=True:
            print(Fore.LIGHTRED_EX + "Could not start sample analysis", file=sys.stderr)
            return
        # print(analysis_response)
        submission_id = analysis_response["data_id"]
        
        print("Waiting for analysis to complete...")
        scan_percentage = 0
        while(scan_percentage != 100):
            (result_success, result_code, result_response) = api.fetch_analysis_result(submission_id)
            if result_success != True:
                print(Fore.LIGHTRED_EX + "Failed to check for submission results", file=sys.stderr)
                return
            scan_percentage = result_response["scan_results"]["progress_percentage"]
            # Wait 10 seconds before checking again
            sleep(10)
        # Check if the hash exists in cache
        (success, code, response) = api.check_hash(hash)
        if success==False:
            print(Fore.LIGHTRED_EX + "The file was analized, but is not present in the cache", file=sys.stder)
            return
    elif success==True and code==200:
        print("Hash is present in the cache.")
    
    # Display scan results
    print(Fore.LIGHTRED_EX + "Overall status: " + Fore.GREEN + str(response["scan_results"]["scan_all_result_a"]))
    for av_name, av_result in response["scan_results"]["scan_details"].items():
        print("---------------------------")
        print(Fore.LIGHTRED_EX + "Engine: " + Fore.GREEN + av_name)
        print(Fore.LIGHTRED_EX + "ThreatFound: " + Fore.GREEN + av_result["threat_found"])
        print(Fore.LIGHTRED_EX + "ScanResult: " + Fore.GREEN + str(av_result["scan_result_i"]))
        print(Fore.LIGHTRED_EX + "DefTime: " + Fore.GREEN + av_result["def_time"])
        
if __name__ == "__main__":
    # Fix ANSI escapes for Windows
    just_fix_windows_console()
    main()
    print(Style.RESET_ALL)