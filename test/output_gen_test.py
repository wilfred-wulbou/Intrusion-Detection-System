import unittest
from output.logfile_generator import OutputGenerator

class TestOutputGenerator(unittest.TestCase):
    def test_logPrediction(self):
        ip = "192.168.1.1"
        port = "443"
        timestamp= "2019-09-27:12:00:01"

        predictionList = [
            {"IP": ip, "Port": port, "Timestamp":timestamp}
        ]
        outGen = OutputGenerator("prediction_log.txt")
        outGen.logPrediction(predictionList)
        outGen.destroy()
        outfile = open("prediction_log.txt", 'r')
        outstr = outfile.readline()
        outstr_target = "IP: %s, Port: %s, Timestamp: %s \n" % (ip,port,timestamp)
        self.assertEquals(outstr, outstr_target)
