# -*- coding:utf-8 -*-

#---------------------------------------------------------------------
# CTIME 클래스
#---------------------------------------------------------------------
class K2CTIME :
    def GetDate(self, t) :
        t_y = 0xFE00
        t_m = 0x01E0
        t_d = 0x001F

        y = (t & t_y) >> 9
        y += 1980
        m = (t & t_m) >> 5
        d = (t & t_d)

        # return '%04d-%02d-%02d' % (y, m, d)
        return (y, m, d)

    def GetTime(self, t) :
        t_h = 0xF800
        t_m = 0x07E0
        t_s = 0x001F

        h = (t & t_h) >> 11
        m = (t & t_m) >> 5
        s = (t & t_s) * 2

        # return '%02d:%02d:%02d' % (h, m, s)
        return (h, m, s)
