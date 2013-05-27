import unittest
import shutil
import os

class Test_Dummy_Cure(unittest.TestCase):
    def test_cure(self):
        cmd = 'python kicomav.py dummy.txt'
        os.system(cmd)
        ret = False
        try :
            ret = not os.path.exists('dummy.txt')
        except :
            pass
        self.assertTrue(ret)

if __name__ == '__main__':
    unittest.main()
