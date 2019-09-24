
"""
Tests the CSVFlowLoader class by loading the csv file that is currently being
written to by CICFlowMeter and print the output of the new entries being appended to the 
end of the csv file.

"""
import os
from flow_loader.csv_flow_loader import CSVFlowLoader

CSVFILEPATH = "D:\\CIC-IDS-2017\\CICFlowMeter-4.0\\bin\\data\\daily"
csvfilename = "2019-09-25_Flow.csv"

# runTest() : call this function from the main script in root folder of project
def runTest():
    csvflowloader = CSVFlowLoader(os.path.join(CSVFILEPATH, csvfilename))
    csvlines = csvflowloader.tailFile()
    print("BEGIN TEST:")
    for line in csvlines:
        print(line)