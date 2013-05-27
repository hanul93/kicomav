import unittest
import shutil
import os

class Test_Eicar_Cure(unittest.TestCase):
    def test_cure(self):
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
