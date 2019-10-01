import time
import os
import pandas as pd
from flow_loader.csv_flow_loader import CSVFlowLoader
from mlengine import MLEngine
from output.logfile_generator import OutputGenerator
from prepare_dumps import dump_pipeline
from preprocessing import constants

CSVFILEPATH = "CICFlowMeter-4.0\\bin\\data\\daily"
csvfilename = "2019-09-30_Flow.csv"
mlengine_model_filename = "ml_models\\svm_clf_model.joblib"
output_filename = "prediction_log.txt"
columns = constants.columns
readBuffer=[] 

def runIDS():
    print("Starting IDS...")
    try:
        csvloader = CSVFlowLoader(os.path.join(CSVFILEPATH, csvfilename))
        output_gen = OutputGenerator(output_filename)

        while True:
            for line in csvloader.tailFile():
                prediction = predictLine(line)
                print(prediction)
            # time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
        csvloader.destroy()

# predicts an entry line from a csv file
def predictLine(line, anomaliesOnly=True):
    mlengine = MLEngine(mlengine_model_filename)
    csVals_raw = [list(line.split(","))]
    csVals = pd.DataFrame(csVals_raw, columns=columns)
    return mlengine.predict(csVals)

def prepareDumps():
    if dump_pipeline.createDumps():
        print("Successful creation of pipeline dumps...")
    else:
        print("Error in creation of pipeline dumps...")

if __name__ == "__main__":
    runIDS()
    # prepareDumps()