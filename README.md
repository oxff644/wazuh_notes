<!-- ABOUT THE PROJECT -->
## About This Repo

The goal of this project is to document common rules and scripts for the use of wazuh and to integrate various open source tools to enhance the functionality of wazuh. Cybersecurity is hard enough, let's work together.:smile:



### Supported Rules and Integrations

Below are the current rules and integrations currently contained within this repo. Integrations, such as Office365, Trend Micro, etc. will have scripts provided within their respective folders for use. Feel free to build upon these scripts and contribute back :smile:
* [basic rules](https://github.com/oxff644/wazuh_notes/tree/main/wazuh_baserule)
* [common scripts](https://github.com/oxff644/wazuh_notes/tree/main/scripts)
* [Sysmon for Windows](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Windows_Sysmon)
* [Sysmon for Linux](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Sysmon%20Linux)
* [Office365](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Office%20365)
* [Microsoft Defender](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Office%20Defender)
* [Sophos](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Sophos)
* [MISP](https://github.com/oxff644/wazuh_notes/tree/main/extentions/MISP)
* [Osquery](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Osquery)
* [Yara](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Yara)
* [Suricata](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Suricata)
* [Packetbeat](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Packetbeat)
* [Falco](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Falco)
* [Modsecurity](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Modsecurity)
* [F-Secure](https://github.com//Wazuh-Rules/tree/main/F-Secure)
* [Domain Stats](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Domain%20Stats)
* [Snyk](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Snyk)
* [Autoruns](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Windows%20Autoruns)
* [Sigcheck](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Windows%20Sysinternals%20Sigcheck)
* [Powershell](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Windows%20Powershell)
* [Crowdstrike](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Crowdstrike)
* [Alienvault](https://github.com/oxff644/wazuh_notes/tree/main/extentions/Domain%20Stats)
* ............
* Tessian - WIP

### Installation

You can either manually download the .xml rule files onto your Wazuh Manager or make use of wazuh_socfortress_rules.sh script

⚠️ USE AT OWN RISK: If you already have custom rules built out, there is a good chance duplicate Rule IDs will exists. This will casue the Wazuh-Manager service to fail! Ensure there are no conflicting Rule IDs and your custom rules are backed up prior to running the wazuh_rules.sh script!

* Become Root User
* Run the Script
> curl -so ~/wazuh_socfortress_rules.sh https://github.com/oxff644/wazuh_notes/blob/main/wazuh_socfortress_rules.sh && bash ~/wazuh_socfortress_rules.sh
