"""
This module implements the functionality of generating and appending 
anomaly entries into the prediction_log.txt file.

"""

class OutputGenerator(object):
    def __init__(self, filename):
        self.outFilename = filename
        self.outFile = open(self.outFilename, 'w')
    
    """
    predictionList: list of dict items. Each dict item will have keys = ("IP", "Port", "Timestamp")
    """
    def logPrediction(self, predictionList):
        self.outFile.seek(0,2)
        for predictionItem in predictionList:
            outputStr = "IP: %s, Port: %s, Timestamp: %s \n" % (predictionItem["IP"],predictionItem["Port"], predictionItem["Timestamp"])
            self.outFile.write(outputStr)
    def destroy(self):
        self.outFile.close()
        return True