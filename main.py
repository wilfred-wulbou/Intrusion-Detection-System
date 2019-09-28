import time
import os
from flow_loader.csv_flow_loader import CSVFlowLoader

CSVFILEPATH = "CICFlowMeter-4.0\\bin\\data\\daily"
csvfilename = "2019-09-29_Flow.csv"
readBuffer=[] 

def runIDS():
    print("Starting IDS...")
    
    try:
        csvloader = CSVFlowLoader(os.path.join(CSVFILEPATH, csvfilename))
        while True:
            for line in csvloader.tailFile():
                print(line)
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
        csvloader.destroy()
    

if __name__ == "__main__":
    runIDS()