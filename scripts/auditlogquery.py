#!/var/ossec/framework/python/bin/python3
​
import requests
import yaml
import json
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from socket import socket, AF_UNIX, SOCK_DGRAM
​
def readEScreds():
    user = "admin"
    pw = "admin"
    cert = "/etc/filebeat/certs/wazuh-server/pem"
    url = "https://127.0.0.1"
    creds = {'url':url,'user':user,'pw':pw,'cert':cert}
    return creds
​
def queryES(creds,endpoint='security-auditlog-*/_search',body=False):
    """
    Function to query the security-auditlogs indexed in Elasticsearch
    If the body is empty it will return the most recent events
    Otherwise the body must be a valid Elasticsearch query as a dict type object
    """
    url = creds['url']+'/'+endpoint
    headers = {'Content-Type': "application/json", 'Accept': "application/json"}
    s = requests.Session()
    s.auth = (creds['user'],creds['pw'])
    r = s.get(url, verify=False,data=body,headers=headers)
    return r
​
def send_event(msg):
    socketAddr = '/var/ossec/queue/sockets/queue'
    string = '1:ES_query:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()
​
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--time',help="Time range for query",default="now-1d/d")
    parser.add_argument('-m','--match',help="match_phrase filter as a json string",default='{"audit_trace_indices":"wazuh-alerts-*"}')
    args = parser.parse_args()
    creds = readEScreds()
    query={"query":{"bool": {"must": [{"match_phrase": json.loads(args.match)}],"filter": {"range": {"timestamp":{"gte":args.time}}}}}}
    response = queryES(creds,endpoint='security-auditlog-*/_search',body=json.dumps(query))
    hits = json.loads(response.text)['hits']['total']['value']
    send_event('Event query on Elasticsearch returned {} hits'.format(hits))