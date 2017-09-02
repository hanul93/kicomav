# -*- coding:utf-8 -*-
# Author: chanlee(pck886@gmail.com)

import requests
import json
import os
import logger

from requests import ConnectionError

API_KEY = 'f65d795af466df04d7e53929fde4d61e6b6fbfc2c274a0989c38c53591aced9e'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
RE_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/rescan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

logger = logger.Klog('Klog').logger

class Virustotal(object):

    def __init__(self, file_path):
        self.basename = os.path.basename(file_path)
        self.params = {'apikey': API_KEY}
        self.files = {'file': (self.basename, open(file_path), 'rb')}
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'gzip, pck886'
        }
        self.resource = ''
        self.scan_name = ''
        self.json_scan = []
        self.json_rescan = []
        self.json_report = []
        self.scan_info = []


    def scan_virustotal(self):
        try:
            res = requests.post(SCAN_URL, files=self.files, params=self.params)

            self.json_scan = res.json()

            self.resource = self.json_scan['resource']

            return self.json_scan['response_code']

        except ConnectionError as e:
            print e
            return None


    def rescan_virustotal(self):
        rescan_result = False

        self.params.update({'resource': self.resource})

        res = requests.post(RE_SCAN_URL, params=self.params)

        if res.status_code == 200:

            self.json_rescan = json.loads(res.text)

            if self.json_rescan:
                rescan_result = self.json_res['response_code']

        return rescan_result

    def report_virustotal(self):
        report_result = False

        self.params.update({'resource': self.resource})
        res = requests.get(REPORT_URL, params=self.params, headers=self.headers)

        logger.info('[REPORT_RESPONSE] : %s' % res.status_code, level='DEBUG')

        if res.status_code == 200:
            self.json_report = json.loads(res.text)

            if self.json_report:
                kaspersky = self.json_report['scans'].get('Kaspersky')
                self.scan_info = kaspersky
                self.scan_name = kaspersky['result']

                report_result = True

            return report_result

        return None