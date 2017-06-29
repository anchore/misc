#!/usr/bin/env python

import json
import requests
from time import gmtime, strftime
import uuid

url = "https://security-tracker.debian.org/tracker/data/json"
header = "Whitelist created at " + strftime("%Y-%m-%d %H:%M:%S", gmtime())
filetime = strftime("%Y%m%d%H%M%S", gmtime())
debianreleases = ['jessie', 'stretch', 'wheezy', 'buster']
suffix = ".json"
whitelist = {}

def addWhitelist(cve_id):

    whitelist_entry = {}
    whitelist_entry['gate'] = 'ANCHORESEC'
    whitelist_entry['id'] = str(uuid.uuid4())
    whitelist_entry['trigger_id'] = cve_id + "+*"
    return whitelist_entry


for release in debianreleases:
    whitelist[release] = {}
    whitelist[release]['version'] = "1_0"
    whitelist[release]['id'] = str(uuid.uuid4())
    whitelist[release]['name'] = "CVE whitelist for " + release
    whitelist[release]['comment'] = header
    whitelist[release]['items'] = []
    whitelist[release]['cves'] = set()

cvedata = requests.get(url).json()

for packages in cvedata:
    package = packages
    for cves in cvedata[package]:
        cve = cves

        # ignore TEMP CVE identifiers
        if cve.startswith("CVE"):

            for release in debianreleases:
                if release in cvedata[package][cve]['releases'] and 'nodsa' in cvedata[package][cve]['releases'][
                    release]:
                    whitelist[release]['cves'].add(cve)

for release in debianreleases:
    for uniq_cve in whitelist[release]['cves']:
        whitelist[release]['items'].append(addWhitelist(uniq_cve))
    del whitelist[release]['cves']
    if len(whitelist[release]['items']) > 0:
        f = open (release + "-" + filetime + suffix, 'w')
        f.write(json.dumps(whitelist[release]))
        f.close()
