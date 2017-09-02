# -*- coding:utf-8 -*-
# Author: chanlee(pck886@gmail.com)

import logging.handlers
from logging import DEBUG, INFO, ERROR, CRITICAL
import sys


class Klog(object):
    loggers = set()

    def __init__(self, name, logfile='./kicom_pefile_log.log', format="[%(levelname)s|%(filename)s:%(lineno)s] %(asctime)s > %(message)s", level=INFO):
        # Initial construct.
        self.format = format
        self.level = level
        self.name = name

        # Logger configuration.
        self.console_formatter = logging.Formatter(self.format)

        self.console_streamHandler = logging.StreamHandler(sys.stdout)
        self.console_fileHandler = logging.FileHandler(logfile)

        self.console_streamHandler.setFormatter(self.console_formatter)
        self.console_fileHandler.setFormatter(self.console_formatter)

        # Complete logging config.
        self.logger = logging.getLogger(name)
        if name not in self.loggers:
            self.loggers.add(name)
            self.logger.setLevel(self.level)
            self.logger.addHandler(self.console_streamHandler)
            self.logger.addHandler(self.console_fileHandler)