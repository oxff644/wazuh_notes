import sys

from itertools import count
import re
from datetime import datetime, timedelta
from opensearchpy import OpenSearch
import logging
from jira import JIRA

import json
from base64 import b64encode
import requests
import urllib3

import csv
################################################
# Test Data

##################
# Connection Wazuh
##################
protocol = 'https'
host = 'siem.local'
port = '55000'
user = ''
password = ''
endpoint = '/agents'
# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#######################
# Connection Opensearch
#######################
OPENSEARCH_URL = "@siem.local:9200"
LOGIN_PASS = ""
INDEX = "wazuh-archives-*"
SIZE = 2000
# Search Time Range
lte = datetime.today()
lteStr = lte.strftime("%Y-%m-%dT23:59:59.000Z")
gte = lte - timedelta(days=3)
gteStr = gte.strftime("%Y-%m-%dT23:59:59.000Z")
query_body = {
    "query": {
        "bool": {
            "must": [
                {
                    "match_all": {}
                }
            ],
            "filter": [
                {
                    "bool": {
                        "should": [
                            {
                                "match_phrase": {
                                    "data.vulnerability.severity": "Critical"
                                }
                            },
                            {
                                "match_phrase": {
                                    "data.vulnerability.severity": "High"
                                }
                            }
                        ],
                        "minimum_should_match": 1
                    }
                },
                {
                    "match_phrase": {
                        "rule.groups": "vulnerability-detector"
                    }
                },
                {
                    "range": {
                        "timestamp": {
                            "gte": gteStr,
                            "lte": lteStr,
                            "format": "strict_date_optional_time"
                        }
                    }
                }
            ],
            "should": [],
            "must_not": []
        }
    }
}

#################
# Connection Jira
#################
jira_server = 'https://company.atlassian.net'
jira_user = ''
jira_password = ''
project = ''
projectID = ''

######################
# Wazuh/Opensearch/JIRA Connect/Get Data Functions
######################


def wazuh_get_response(url, headers, verify=False):
    """Get API result"""
    request_result = requests.get(url, headers=headers, verify=verify)

    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")


def wazuh_form_list():
    # Variables Wazuh
    base_url = f"{protocol}://{host}:{port}"
    login_url = f"{base_url}/security/user/authenticate"
    basic_auth = f"{user}:{password}".encode()
    headers = {'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
    headers['Authorization'] = f'Bearer {wazuh_get_response(login_url, headers)["data"]["token"]}'
    win_srv = []
    # Request
    response = wazuh_get_response(base_url + endpoint, headers)
    # Work with response
    for item in response["data"]["affected_items"]:
        if ("Windows" in item["os"]["name"]) and item["status"] == "active":
            win_srv.append(item["name"])
    # print(json.dumps(response, indent=4, sort_keys=True))
    return(win_srv)


def connect_jira(log, jira_server, jira_user, jira_password):
    '''
    Connect to JIRA. Return None on error
    '''
    try:
        log.info("Connecting to JIRA: %s" % jira_server)
        jira_options = {'server': jira_server}
        jira = JIRA(options=jira_options, basic_auth=(
            jira_user, jira_password))
        # ^--- Note the tuple
        return jira
    except Exception as e:
        log.error("Failed to connect to JIRA: %s" % e)
        return None


def opensearch_get_data(OPENSEARCH_URL, INDEX, LOGIN_PASS, query_body, SIZE):
    client = OpenSearch(
        "https://" + LOGIN_PASS + OPENSEARCH_URL,
        ca_certs=False,
        verify_certs=False,
    )
    result = client.search(index=INDEX, body=query_body, size=SIZE)
    all_hits = result["hits"]["hits"]
    return all_hits

######################
# Create/Update Tickets
######################


def changeStatus(issue, statusDesired):
    statuses = ['Review', 'Owner Review',
                'Patch', 'Return to Review', 'Done']
    statusCurrent = issue.fields.status.description
    statusDesired = 'Patching'
    try:
        ji.transition_issue(issue, statusDesired)
    except:
        for status in statuses:
            if statusDesired != 'Done' and status == 'Done':
                continue
            if statusDesired != statusCurrent:
                try:
                    ji.transition_issue(issue, status)
                except:
                    pass


def updateIssue(issue, description, status, labels, comment=None):
    # update fields
    issue.update(notify=False, description=description,
                 fields={"labels": labels})
    # update status
    changeStatus(issue, status)
    # add comment, if exists
    if comment:
        ji.add_comment(issue, comment)


######################
# Form Data
######################
##
# Form Dict from New Data
##
def newVulnDataSIEM(data):
    newVulnDataSIEMD = {}

    for doc in data:
        source = doc["_source"]
        # Agent Data
        agent = source["agent"]
        agentIP = agent["ip"]
        agentName = agent["name"]
        # Vulnerability Data
        data = source["data"]
        vulnerability = data["vulnerability"]
        package = vulnerability["package"]
        packageName = package["name"]
        condition = package["condition"]
        severity = vulnerability["severity"]
        cve = vulnerability["cve"]
        rationale = vulnerability["rationale"]
        references = vulnerability["references"]
        newAgentData = {
            agentName: {
                "name": agentName,
                "ip": agentIP,
                "packages": {

                }
            }
        }
        newCVEData = {
            "severity": severity,
            "rationale": rationale,
            "condition": condition,
            "references": references
        }

        if agentName not in newVulnDataSIEMD:
            newVulnDataSIEMD.update(newAgentData)

        if packageName not in newVulnDataSIEMD[agentName]["packages"]:
            newVulnDataSIEMD[agentName]["packages"][packageName] = {}

        if cve not in newVulnDataSIEMD[agentName]["packages"][packageName]:
            newVulnDataSIEMD[agentName]["packages"][packageName][cve] = newCVEData
    return newVulnDataSIEMD

##
# Form Dict from Old Jira's Data
##


def oldVulnDataJira():
    oldVulnDataJiraD = {}
    jiraIssuesL = ji.search_issues(
        'project =' + project + ' AND status != Closed AND labels = vulnerable_host AND labels = vulnerability')
    for i in jiraIssuesL:
        summary = i.fields.summary
        # return host from "Multiple vulnerabilities detected for *hostname*"
        sliced = summary[38:]
        oldVulnDataJiraD[sliced] = {"issue": i.key, "packages": {}}
        for issue in i.fields.subtasks:
            # return package from "Vulnerable *packagename* was found on *hostname*"
            str = issue.fields.summary[11:]
            oldPackageName = str.split(' was')[0]
            oldVulnDataJiraD[sliced]["packages"][oldPackageName] = jiraVulnersTableToDict(
                issue.key)
    return oldVulnDataJiraD


def jiraVulnersTableToDict(issueKey):
    print(f'Creating Dict from table markdown from {issueKey}.')
    issue = ji.issue(issueKey)
    oldVulns = []
    oldVulnDict = {"issue": issueKey}
    noNewLines = issue.fields.description.split("\n")
    # remove empty elements
    str_list = list(filter(None, noNewLines))
    # split damn table into nested list
    separateBySymbol = ([re.split("\s?\|\s?", l) for l in str_list[1:]])
    # remove empty elements from nested list created from table
    oldVulns = [[x for x in l if x] for l in separateBySymbol]
    for x in oldVulns:
        if x[4] == "Patched":
            continue
        oldVulnDict[x[0]] = {
            "severity": x[1],
            "rationale": x[2],
            "condition": x[3],
            "status": x[4]
        }
    return oldVulnDict

##
# Prepare Data for Ticket itself
##


def createTable(data, status=None):
    tableHeaders = '| *CVE* | *Severity* | *Rationale* | *Condition* | *Status* |'
    labelsCve = []
    cveCounter = 0
    isUnpathed = False
    issueCritical = ''
    issueHigh = ''
    if status == 2:
        isUnpathed = True
        for cve, cveD in data.items():
            if cveD["condition"] == "Package unfixed":
                continue
            else:
                cveCounter += 1
                labelsCve.append(cve)
                cveTableRow = "\n| {} | {} | {} | {} | {} |".format(
                    cve, cveD['severity'], cveD['rationale'], cveD['condition'], "New")
                if cveD['severity'] == 'High':
                    issueHigh = issueHigh + cveTableRow
                else:
                    issueCritical = issueCritical + cveTableRow
    else:
        for cve, cveD in data.items():
            if not cveD or cve == "issue":
                continue
            if cveD['status'] == ["New", "Persists"]:
                isUnpathed == True
            cveCounter += 1
            labelsCve.append(cve)
            cveTableRow = "\n| {} | {} | {} | {} | {} |".format(
                cve, cveD['severity'], cveD['rationale'], cveD['condition'], cveD['status'])
            if cveD['severity'] == 'High':
                issueHigh = issueHigh + cveTableRow
            else:
                issueCritical = issueCritical + cveTableRow

    if cveCounter == 0:
        return None, None, None

    table = tableHeaders + issueCritical + issueHigh
    if len(table) >= 30000:
        table = tableHeaders + issueCritical

    return table, labelsCve, isUnpathed


def updateVulnersDataTable(hostname, data, status):
    ###################################################################
    # Move ticket to SecReview if hostname not detected in New Dattaset
    if status == 1:
        tableHeaders = '| *CVE* | *Severity* | *Rationale* | *Condition* | *Status* |'
        for packagename, packageD in data['packages'].items():
            labelsPkg = ['vulnerability', 'vulnerable_package',
                         hostname.replace(' ', '_'), packagename.replace(' ', '_')]
            labelsCve = []
            issueDataTable = tableHeaders
            issue = ji.issue(packageD['issue'])
            for cve, cveD in packageD.items():
                # ignore "issue" key
                if cve == "issue":
                    continue
                issueDataTable = issueDataTable + "\n| {} | {} | {} | {} | {} |".format(
                    cve, cveD['severity'], cveD['rationale'], cveD['condition'], "Patched")
                labelsCve.append(cve)
            labelsPkg = labelsPkg + labelsCve
            updateIssue(issue, issueDataTable,
                        'Done', labelsPkg)
    ############################################################
    # Create New tickets if hostname not detected in old Dataset
    elif status == 2:
        issueDataL = []
        labelsHost = []
        for packagename, packageD in data['packages'].items():
            labelsHost.append(packagename)
            labelsPkg = ['vulnerability', 'vulnerable_package',
                         hostname.replace(' ', '_'), packagename.replace(' ', '_')]
            table, labelsCve, isUnpathed = createTable(packageD, status=2)
            if table:
                labelsPkg = labelsPkg + labelsCve
                data = {
                    'project': {'id': projectID},
                    'summary': f'Vulnerable {packagename} was found on {hostname}',
                    'description': table,
                    'labels': labelsPkg,
                    'issuetype': {'name': 'Sub-task'}
                }
                issueDataL.append(data)
        return issueDataL, labelsHost

    ############################################################
    # Update Data in existing tickets if hostname detected in both Datasets
    elif status == 3:
        labelsHost = []
        for packagename, packageD in data.items():
            labelsHost.append(packagename)
            labelsPkg = ['vulnerability', 'vulnerable_package',
                         hostname.replace(' ', '_'), packagename.replace(' ', '_')]
            table, labelsCve, isUnpathed = createTable(packageD)
            if table:
                issue = ji.issue(packageD['issue'])
                labelsPkg = labelsPkg + labelsCve
                if not isUnpathed:
                    status = 'Done'
                else:
                    status = 'Return to Review'
                    updateIssue(issue, table, status, labelsPkg)
        return labelsHost
##
# Compare old and new data
##


def compareCVE(oldCVEsData, newCVEsData):
    updatedPackageData = {
    }

    oldCVESet = set(oldCVEsData)
    newCVESet = set(newCVEsData)
    intersectingCVE = list(
        set(oldCVESet).intersection(newCVESet))

    cveNotInNew = {k: oldCVEsData[k]
                   for k in oldCVESet - newCVESet}
    cveNotInOld = {k: newCVEsData[k]
                   for k in newCVESet - oldCVESet}

    for cve in cveNotInNew:
        print("CVE not in new Dataset for host.")
        if cve == "issue":
            continue
        updatedPackageData[cve] = oldCVEsData[cve]
        updatedPackageData[cve]['status'] = "Patched"

    for cve in cveNotInOld:
        print("CVE not in old Dataset for host.")
        if newCVEsData[cve]["condition"] == "Package unfixed":
            continue
        else:
            updatedPackageData[cve] = newCVEsData[cve]
            updatedPackageData[cve]['status'] = 'New'

    for cve in intersectingCVE:
        print("CVE exists in both Datasets for host.")
        if oldCVEsData[cve]['status'] in ['Patched', 'Ignore']:
            continue
        if oldCVEsData[cve]['status'] == 'New':
            updatedPackageData[cve] = oldCVEsData[cve]
            updatedPackageData[cve]['status'] = 'Persists'

    return updatedPackageData


def comparePackages(oldPackagesData, newPackagesData):
    updatedPackagesData = {
    }

    oldPackagesSet = set(oldPackagesData)
    newPackagesSet = set(newPackagesData)
    intersectingPackages = list(
        set(oldPackagesData).intersection(newPackagesData))

    packageNotInNew = {k: oldPackagesData[k]
                       for k in oldPackagesSet - newPackagesSet}
    packageNotInOld = {k: newPackagesData[k]
                       for k in newPackagesSet - oldPackagesSet}

    for package in packageNotInNew:
        print("Package not in new Dataset.")
        updatedPackage = oldPackagesData[package]

        for cve in updatedPackage:
            if cve == "issue":
                continue
            updatedPackage[cve]['status'] = "Patched"
        updatedPackagesData[package] = updatedPackage

    for package in packageNotInOld:
        print("Package not in old Dataset.")
        updatedPackage = newPackagesData[package]
        cveCounter = 0
        for cve in list(newPackagesData[package]):
            if updatedPackage[cve]["condition"] == "Package unfixed":
                del updatedPackage[cve]
                continue
            cveCounter += 1
            updatedPackage[cve]['status'] = 'New'
        updatedPackagesData[package] = updatedPackage

    for package in intersectingPackages:
        print("Package exists in both Datasets.")
        updatedPackageData = compareCVE(
            oldPackagesData[package], newPackagesData[package])
        updatedPackagesData[package] = updatedPackageData

    return updatedPackagesData


def compareHosts(newVulnDataSIEMD, oldVulnDataJiraD):
    oldVulnDataJiraSet = set(oldVulnDataJiraD)
    newVulnDataSIEMSet = set(newVulnDataSIEMD)
    intersectingHosts = list(
        set(oldVulnDataJiraSet).intersection(newVulnDataSIEMSet))

    hostNotInNew = {k: oldVulnDataJiraD[k]
                    for k in oldVulnDataJiraSet - newVulnDataSIEMSet}
    hostNotInOld = {k: newVulnDataSIEMD[k]
                    for k in newVulnDataSIEMSet - oldVulnDataJiraSet}

    for hostname in hostNotInNew:
        print("Host not in new Dataset.")
        updateVulnersDataTable(
            hostname, oldVulnDataJiraD[hostname], 1)
        issue = ji.issue(oldVulnDataJiraD[hostname]['issue'])
        description = issue.fields.description.split("\n")
        description = (description[0] + '\n' + description[1] + '\n' +
                       f'*Last Updated:* {datetime.today().strftime("%Y-%m-%d")}\n')
        comment = "Host was not found in the latest scan."
        labels = issue.fields.labels
        updateIssue(issue, description, 'Done', labels)

    for hostname in hostNotInOld:
        print("Host not in old Dataset.")
        ip = newVulnDataSIEMD[hostname]['ip']
        issueDataL,  labelsHost = updateVulnersDataTable(
            hostname, newVulnDataSIEMD[hostname], 2,)
        labels = ['vulnerability', 'vulnerable_host',
                  hostname.replace(' ', '_')] + labelsHost
        if issueDataL:
            data = {
                'project': {'id': projectID},
                'summary': f'Multiple vulnerabilities detected for {hostname}',
                'description': f'*Hostname:* {hostname}\n*IP:* {ip}\n*Last Updated:* {datetime.today().strftime("%Y-%m-%d")}\n',
                'issuetype': {'name': 'Vulnerable Host/Package'},
                'labels': labels,
                'priority': {'name': 'High'}
            }
            parent = ji.create_issue(fields=data)
            for idx, issue in enumerate(issueDataL):
                issueDataL[idx]['parent'] = {'key': parent.key}

            ji.create_issues(field_list=issueDataL)

    for hostname in intersectingHosts:
        print("Host exists in both Datasets.")
        updatedPackagesData = comparePackages(
            oldVulnDataJiraD[hostname]['packages'], newVulnDataSIEMD[hostname]['packages'])

        labelsHost = updateVulnersDataTable(
            hostname, updatedPackagesData, 3)

        issue = oldVulnDataJiraD[hostname]['issue']
        ip = newVulnDataSIEMD[hostname]['ip']
        description = f'*Hostname:* {hostname}\n*IP:* {ip}\n*Last Updated:* {datetime.today().strftime("%Y-%m-%d")}\n'
        labels = ['vulnerability', 'vulnerable_host',
                  hostname.replace(' ', '_')] + labelsHost
        data = {
            'issuetype': {'name': 'Vulnerable Host/Package'},
            'labels': labels,
            'priority': {'name': 'High'}
        }
        updateIssue(issue, description, 'Return to Review', labels)


if __name__ == "__main__":
    log = logging.getLogger(__name__)
    ji = connect_jira(log, jira_server, jira_user, jira_password)
    data = opensearch_get_data(
        OPENSEARCH_URL, INDEX, LOGIN_PASS, query_body, SIZE)
    newVulnDataSIEMD = newVulnDataSIEM(data)
    oldVulnDataJiraD = oldVulnDataJira()
    compareHosts(newVulnDataSIEMD, oldVulnDataJiraD)
