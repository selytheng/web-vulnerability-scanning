from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import requests
import ssl
import time
import urllib3

app = Flask(__name__)

# Enable CORS for all routes
CORS(app)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to run the scan
def run_scan(target_url):
    MyAXURL = "https://192.168.20.100:3443/api/v1"
    MyAPIKEY = "1986ad8c0a5b3df4d7028d5f3c06e936c4eee11c5979346d9a8a8abeaaf2643e3"
    FullScanProfileID = "11111111-1111-1111-1111-111111111111"
    MyRequestHeaders = {
        'X-Auth': MyAPIKEY,
        'Content-Type': 'application/json'
    }

    # Create our intended target - target ID is in the JSON response
    MyRequestBody = {
        "address": target_url,
        "description": "Scan initiated via Flask",
        "type": "default",
        "criticality": 10
    }

    try:
        # Create the target
        MyTargetIDResponse = requests.post(MyAXURL + '/targets', json=MyRequestBody, headers=MyRequestHeaders, verify=False)
        MyTargetIDResponse.raise_for_status()
        MyTargetIDjson = MyTargetIDResponse.json()
        MyTargetID = MyTargetIDjson["target_id"]

        # Trigger a scan on the target
        MyRequestBody = {
            "profile_id": FullScanProfileID,
            "incremental": False,
            "schedule": {
                "disable": False,
                "start_date": None,
                "time_sensitive": False
            },
            "user_authorized_to_scan": "yes",
            "target_id": MyTargetID
        }

        MyScanIDResponse = requests.post(MyAXURL + '/scans', json=MyRequestBody, headers=MyRequestHeaders, verify=False)
        MyScanIDResponse.raise_for_status()
        MyScanID = MyScanIDResponse.headers["Location"].replace("/api/v1/scans/", "")

        # Check scan status
        while True:
            MyScanStatusResponse = requests.get(MyAXURL + '/scans/' + MyScanID, headers=MyRequestHeaders, verify=False)
            MyScanStatusResponse.raise_for_status()
            MyScanStatusjson = MyScanStatusResponse.json()
            MyScanStatus = MyScanStatusjson["current_session"]["status"]

            if MyScanStatus in ["processing", "scheduled"]:
                time.sleep(30)
            elif MyScanStatus == "completed":
                break

        # Obtain scan vulnerabilities
        MyScanResultResponse = requests.get(MyAXURL + f'/scans/{MyScanID}/results', headers=MyRequestHeaders, verify=False)
        MyScanResultResponse.raise_for_status()
        MyScanResultjson = MyScanResultResponse.json()
        MyScanResultID = MyScanResultjson["results"][0]["result_id"]

        # Get vulnerabilities
        MyScanVulnerabilitiesResponse = requests.get(MyAXURL + f'/scans/{MyScanID}/results/{MyScanResultID}/vulnerabilities', headers=MyRequestHeaders, verify=False)
        MyScanVulnerabilitiesResponse.raise_for_status()
        return MyScanVulnerabilitiesResponse.json()

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

@app.route('/scan', methods=['POST'])
def scan_website():
    data = request.json
    target_url = data.get("url")
    if not target_url:
        return jsonify({"error": "URL is required"}), 400
    result = run_scan(target_url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
