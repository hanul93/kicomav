# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


# -------------------------------------------------------------------------
# Constants for specifying virus removal actions
# Used as return value from scan callback function
# -------------------------------------------------------------------------
K2_ACTION_IGNORE = 0
K2_ACTION_DISINFECT = 1
K2_ACTION_DELETE = 2
K2_ACTION_QUIT = 3

# -------------------------------------------------------------------------
# Constants for specifying virus isolation status
# -------------------------------------------------------------------------
K2_QUARANTINE_MOVE = 0
K2_QUARANTINE_COPY = 1


# -------------------------------------------------------------------------
# Custom exception for plugin unexpected errors
# Used to propagate errors to k2engine for IO_errors counting
# -------------------------------------------------------------------------
class PluginUnexpectedError(Exception):
    """Exception raised when a plugin encounters an unexpected error.

    This exception is raised after logging the error, allowing k2engine
    to catch it and increment the IO_errors counter.
    """

    pass
