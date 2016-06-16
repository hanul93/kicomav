# -*- coding:utf-8 -*-

#---------------------------------------------------------------------
# K2RC4 클래스
#---------------------------------------------------------------------
class K2RC4 :
    def __init__(self) :
        self.S   = []
        self.T   = []
        self.Key = []
        self.K_i = 0
        self.K_j = 0

    def SetKey(self, s_key) :
        for i in range(len(s_key)) :
            self.Key.append(ord(s_key[i]))
        self.__InitRc4__()

    def __InitRc4__(self) :
        # S 초기화
        for i in range(256) :
            self.S.append(i)
            self.T.append(self.Key[i%len(self.Key)])

        # S의 초기 순열 (치환)    
        j = 0
        for i in range(256) :
            j = (j + self.S[i] + self.T[i]) % 256
            self.__Swap__(i, j)

    def __Swap__(self, i, j) :
        temp      = self.S[i]
        self.S[i] = self.S[j]
        self.S[j] = temp

    def GenK(self) :
        # 스트림 생성
        i = self.K_i
        j = self.K_j
        
        i = (i + 1) % 256
        j = (j + self.S[i]) % 256
        self.__Swap__(i, j)
        t = (self.S[i] + self.S[j]) % 256

        self.K_i = i
        self.K_j = j

        return self.S[t]

    def Crypt(self, s_string) :
        Str = []

        for i in range(len(s_string)) :
            Str.append(ord(s_string[i]))
            
        for i in range(len(Str)) :
            Str[i] ^= self.GenK()

        ret_s = ''
        for i in range(len(Str)) :
            ret_s += chr(Str[i])

        return ret_s
