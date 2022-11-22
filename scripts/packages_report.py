#!/usr/bin/env python3
​
import csv
import json
from base64 import b64encode
from os.path import join
​
import requests  # To install requests, use: pip3 install requests
import urllib3
​
# Configuration
protocol = 'https'
host = 'localhost'
port = '55000'
user = 'wazuh'
password = 'wazuh'
​
agent_fields = ['name', 'ip']
package_fields = ['name', 'version']
​
output_path = '/tmp'
output_filename = 'packages_list.csv'
​
# Variables
base_url = f'{protocol}://{host}:{port}'
login_url = f'{base_url}/security/user/authenticate'
basic_auth = f'{user}:{password}'.encode()
headers = {'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
​
# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
​
​
# Functions
def get_response(url, headers, verify=False):
    """Get API result"""
    request_result = requests.get(url, headers=headers, verify=verify)
​
    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())
    else:
        raise Exception(f'Error obtaining response: {request_result.json()}')
​
​
def write_csv(data):
    try:
        with open(join(output_path, output_filename), 'w', encoding="utf-8") as outfile:
            writer = csv.DictWriter(outfile, fieldnames=[f'agent_{field}' for field in agent_fields] +
                                                        [f'package_{field}' for field in package_fields])
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        print(f'\nReport created at "{join(output_path, output_filename)}".')
    except Exception as e:
        print(f'Following error was found while writing report at {join(output_path, output_filename)}: {e}. ')
        response = input('Do you want the report to be displayed here? [y/n]: ')
        if response == 'y':
            print(data)
        else:
            print('Exiting...')
​
​
def main():
    result = []
    headers['Authorization'] = f'Bearer {get_response(login_url, headers)["data"]["token"]}'
​
    # Request
    agents = get_response(base_url + f'/agents?wait_for_complete=true&select={",".join(agent_fields)}&'
                                     f'select=status&limit=100000', headers)
    if agents['data']['total_affected_items'] == 0:
        print(f'No agents were found: \n{agents}')
        exit(0)
​
    for agent_data in agents['data']['affected_items']:
        if agent_data['status'] == 'never_connected':
            print(f'Status of "{agent_data["name"]}" agent is "never_connected" so their packages are unknown. '
                  f'Skipping...')
            continue
​
        print(f'Getting packages information for agent {agent_data["id"]}: {agent_data["name"]}')
​
        try:
            packages = get_response(
                base_url + f'/syscollector/{agent_data["id"]}/packages?wait_for_complete=true&limit=100000'
                           f'&select={",".join(package_fields)}',
                headers
            )
        except Exception as e:
            print(f'Could not get package information from Agent {agent_data["name"]} ({agent_data["id"]}). '
                  f'Skipping... {e}')
            continue
​
        try:
            for package_data in packages['data']['affected_items']:
                result.extend([
                    {**{f'agent_{field}': agent_data.get(field, 'unknown') for field in agent_fields},
                     **{f'package_{field}': package_data.get(field, 'unknown') for field in package_fields}}
                ])
        except Exception as e:
            print(f'An error was found while parsing "{agent_data["name"]}" agent packages: {e}. Skipping...')
​
    write_csv(result)
​
​
if __name__ == '__main__':
    main()