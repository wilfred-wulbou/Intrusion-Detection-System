import unittest
from flow_loader.csv_flow_loader import CSVFlowLoader
import os

class TestCSVFlowLoader(unittest.TestCase):
    def test_tailFile(self):
        test_target = "192.168.10.3-192.168.10.50-3268-56108-6,192.168.10.50,56108,192.168.10.3,3268,6,7/7/2017 8:59,112740690,32,16,6448,1152,403,0,201.5,204.7242047,72,72,72,0,67.41133126,0.425755776,2398738.085,5798697.94,1.64E+07,3,1.13E+08,3636796.452,6848760.823,1.64E+07,3,1.13E+08,7516023.2,8323384.915,1.64E+07,3,1,0,0,0,1024,512,0.283837184,0.141918592,0,403,163.3265306,178.9317127,32016.55782,0,1,0,0,1,0,0,0,0,166.7291667,201.5,72,1024,0,0,0,0,0,0,32,6448,16,1152,377,2079,15,32,359.4285714,11.99801571,380,343,1.61E+07,498804.8203,1.64E+07,1.54E+07,BENIGN\n"
        CSVFILEPATH = "D:\\CIC-IDS-2017\\CICFlowMeter-4.0\\bin\\data\\daily"
        csvfilename = "test.csv"
        csvflowloader = CSVFlowLoader(os.path.join(CSVFILEPATH, csvfilename))
        csvlines = csvflowloader.tailFile()
        for line in csvlines:
            self.assertEquals(line, test_target)
            break