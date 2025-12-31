# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import time


# ---------------------------------------------------------------------
# convert_date(t)
# Get the date from the given integer.
# Argument: t - Integer containing year, month, and day
# Return: Year, month, day
# ---------------------------------------------------------------------
def convert_date(t):
    y = ((t & 0xFE00) >> 9) + 1980
    m = (t & 0x01E0) >> 5
    d = t & 0x001F

    return y, m, d


# ---------------------------------------------------------------------
# convert_time(t)
# Get the time from the given integer.
# Argument: t - Integer containing hour, minute, and second
# Return: Hour, minute, second
# ---------------------------------------------------------------------
def convert_time(t):
    h = (t & 0xF800) >> 11
    m = (t & 0x07E0) >> 5
    s = (t & 0x001F) * 2

    return h, m, s


# ---------------------------------------------------------------------
# get_now_date(now=None)
# Convert the current date to a 2-byte date value.
# Argument: now - Current date/time value (optional)
# Return: 2-byte date value
# ---------------------------------------------------------------------
def get_now_date(now=None):
    if not now:
        now = time.gmtime()

    t_y = now.tm_year - 1980
    t_y = (t_y << 9) & 0xFE00
    t_m = (now.tm_mon << 5) & 0x01E0
    t_d = now.tm_mday & 0x001F

    return (t_y | t_m | t_d) & 0xFFFF


# ---------------------------------------------------------------------
# get_time_value(now=None)
# Convert the current time to a 2-byte time value.
# Argument: now - Current date/time value (optional)
# Return: 2-byte time value
# ---------------------------------------------------------------------
def get_now_time(now=None):
    if not now:
        now = time.gmtime()

    t_h = (now.tm_hour << 11) & 0xF800
    t_m = (now.tm_min << 5) & 0x07E0
    t_s = (now.tm_sec // 2) & 0x001F

    return (t_h | t_m | t_s) & 0xFFFF
