import unittest
import shutil
import os

class Test_Eicar_Cure(unittest.TestCase):
    def test_cure(self):
        if os.name == 'nt' :
            cmd = 'c:\\python27\\python kicomav.py eicar.txt'
        else :
            cmd = 'python kicomav.py eicar.txt'
        os.system(cmd)
        ret = False
        try :
            ret = not os.path.exists('eicar.txt')
        except :
            pass
        self.assertTrue(ret)

if __name__ == '__main__':
    unittest.main()
