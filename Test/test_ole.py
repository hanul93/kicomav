import unittest
import shutil
import os
import ole

class Test_OLE_Lib(unittest.TestCase):
    def test_ole(self):
        ret = -1

        try :
            o = ole.OLE('sample.hwp')
            ret = o.parse()
        except :
            pass

        self.assertEqual(ret, 0)

if __name__ == '__main__':
    unittest.main()
