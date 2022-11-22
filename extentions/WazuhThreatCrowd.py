#!/usr/bin/env python

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM


try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# ossec.conf configuration:
#  <integration>
#      <name>virustotal</name>
#      <api_key>api_key_here</api_key>
#      <group>syscheck</group>
#      <alert_format>json</alert_format>
#  </integration>

# Global vars

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '/var/ossec/logs/integrations.log'.format(pwd)
socket_addr = '/var/ossec/queue/ossec/queue'.format(pwd)

def main(args):
    debug("# Starting")

    # Read args
    alert_file_location = args[1]
    apikey = args[2]

    debug("# API Key")
    debug(apikey)

    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)

    # Request VirusTotal info
    msg = request_virustotal_info(json_alert,apikey)

    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["foo"][0]["agent"]["name"])

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)

        print(msg)

        f = open(log_file,"a")
        f.write(msg)
        f.close()

def collect(data):
  sha1  = data['resolutions']

  return sha1

def in_database(data, hash):
  result = data['response_code']
  if result == 0:
    return False
  return True

def query_api(hash, apikey):
  params = {'resource': hash}
  headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  Python library-client-VirusTotal"
  }
  response = requests.get('https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=',params=params, headers=headers)
  if response.status_code == 200:
      json_response = response.json()
      data = json_response
      return data
  else:
      alert_output = {}
      alert_output["threatcrowd"] = {}
      alert_output["integration"] = "threatcrowd"

      if response.status_code == 204:
        debug("# Error: VirusTotal Public API request rate limit reached")
        alert_output["threatcrowd"]["error"] = response.status_code
        alert_output["threatcrowd"]["description"] = "Error: Public API request rate limit reached"
        send_event(alert_output)
        exit(0)
      elif response.status_code == 403:
        debug("# Error: threatcrowd credentials, required privileges error")
        alert_output["threatcrowd"]["error"] = response.status_code
        alert_output["threatcrowd"]["description"] = "Error: Check credentials"
        send_event(alert_output)
        exit(0)
      else:
        debug("# Error when conecting ThreatCrowd API")
        alert_output["threatcrowd"]["error"] = response.status_code
        alert_output["threatcrowd"]["description"] = "Error: API request fail"
        send_event(alert_output)
        response.raise_for_status()
        exit(0)

def request_virustotal_info(alert, apikey):
    alert_output = {}

    # If there is no a md5 checksum present in the alert. Exit.
    #if not int("srcip") in alert["foo"]["data"]["srcip"]:
    # return(0)

    # Request info using VirusTotal API
    ip = (alert["foo"][0]["data"]["srcip"])
    data = query_api(ip, apikey)

    # Create alert
    alert_output["threatcrowd"] = {}
    alert_output["integration"] = "threatcrowd"
    alert_output["threatcrowd"]["found"] = 0
    alert_output["threatcrowd"]["malicious"] = 0
    alert_output["threatcrowd"]["source"] = {}
    alert_output["threatcrowd"]["source"]["alert_id"] = alert["foo"][0]["id"]

    # Check if VirusTotal has any info about the hash
    if in_database(data, hash):
      alert_output["threatcrowd"]["found"] = 1

    # Info about the file found in VirusTotal
    if alert_output["threatcrowd"]["found"] == 1:
        sha1 = collect(data)

        #if positives > 0:
        alert_output["threatcrowd"]["malicious"] = 1

        # Populate JSON Output object with VirusTotal request
        alert_output["threatcrowd"]["sha1"] = sha1
        #alert_output["threatcrowd"]["scan_date"] = scan_date
        #alert_output["threatcrowd"]["positives"] = positives
        #alert_output["threatcrowd"]["total"] = total
        #alert_output["threatcrowd"]["permalink"] = permalink


    debug(alert_output)

    return(alert_output)

def send_event(msg, agent = None):
    if not agent:
        string = '1:threatcrowd:{0}'.format(json.dumps(msg))
    else:
        string = (json.dumps(msg))

    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 2:
            msg = '{0} {1} {2}'.format(now, sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else '')
            debug_enabled = (len(sys.argv) > 2 and sys.argv[2] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(msg +'\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
