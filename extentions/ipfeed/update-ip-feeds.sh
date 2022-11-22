#!/bin/bash

wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset
/var/ossec/etc/lists/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault

wget https://iplists.firehol.org/files/dshield.netset -O /var/ossec/etc/lists/dshield.netset
/var/ossec/etc/lists/iplist-to-cdblist.py /var/ossec/etc/lists/dshield.netset /var/ossec/etc/lists/blacklist-dshield

wget https://iplists.firehol.org/files/et_compromised.ipset -O /var/ossec/etc/lists/et_compromised.ipset
/var/ossec/etc/lists/iplist-to-cdblist.py /var/ossec/etc/lists/et_compromised.ipset /var/ossec/etc/lists/blacklist-et_compromised
