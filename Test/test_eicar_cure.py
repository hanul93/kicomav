# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import unittest
import shutil
import os
import kavcore

class Test_Dummy_Cure(unittest.TestCase):
    def test_kav_dummy(self):
        self.kav = kavcore.Engine() # 엔진 클래스
        self.kav.SetPlugings('plugins') # 플러그인 폴더 설정

        # 엔진 인스턴스 생성1
        self.kav1 = self.kav.CreateInstance()
        self.assertTrue(self.kav1 != None)

        # 엔진 초기화
        ret = self.kav1.init()
        self.assertTrue(ret != False)

        # 악성코드 검사
        self.kav1.scan('eicar.txt')
        ret = self.kav1.get_result()
        self.assertTrue(ret['Files'] == 1)
        self.assertTrue(ret['Infected_files'] == 1)

        # 엔진 종료
        self.kav1.uninit()


if __name__ == '__main__':
    unittest.main()
