import time
import os
import subprocess
import datetime
import logging
from subprocess import Popen
import pandas as pd
from flow_loader.csv_flow_loader import CSVFlowLoader
from mlengine import MLEngine
# from output.logfile_generator import OutputGenerator
from prepare_dumps import dump_pipeline
from preprocessing import constants
from preprocessing.constants import PredictLabel

CSVFILEPATH = "CICFlowMeter-4.0\\bin\\data\\daily"
csvfilename = ""
DATACLEAN_PIPELINE_FILEPATH = "preprocessing/joblib_dumps/dataclean_pipeline.joblib"
DATAPREP_PIPELINE_FILEPATH = "preprocessing/joblib_dumps/dataprep_pipeline.joblib"
# MODEL_FILEPATH = "ml_models/svm_clf_model.joblib" 
MODEL_FILEPATH = "ml_models/svm_clf_model_20191016_182601_svm_clf_model.joblib"
output_filename = "prediction_log.txt"
columns = constants.COLUMNS

def runIDS(verbose=False):
    print("Starting IDS...")
    try:
        # Create log file if it does not exist.
        if not os.path.exists(r'logs\idslogs\ids.log'):
            file = open(os.path.join(r'logs\idslogs','ids.log'), 'w')
            file.close()
        logging.basicConfig(filename=os.path.join(r'logs\idslogs','ids.log'), level=logging.INFO)
        csvloader = CSVFlowLoader(os.path.join(CSVFILEPATH, csvfilename))
        mlengine = MLEngine(MODEL_FILEPATH, DATACLEAN_PIPELINE_FILEPATH, DATAPREP_PIPELINE_FILEPATH)
        # output_gen = OutputGenerator(output_filename)
        while True:
            for flowline in csvloader.tailFile():
                csValsArray = [list(flowline.split(","))]
                csValsDF = pd.DataFrame(csValsArray, columns=columns)

                # Actual detection and printing results out in stdout.
                if mlengine.predict(csValsDF)[0] == PredictLabel.ANOMALY.value:
                    print("ANOMALY: %s" % (parsePredictionDF(csValsDF)))
                    logging.info("ANOMALY: %s" % (parsePredictionDF(csValsDF)))
                else:
                    if verbose:
                        print("BENIGN: %s" % (parsePredictionDF(csValsDF)))
    except KeyboardInterrupt:
        print("Exiting...")
        csvloader.destroy()

def parsePredictionDF(dataframe):
    src_ip = dataframe["Src IP"].values[0]
    src_port = dataframe["Src Port"].values[0]
    dst_ip = dataframe["Dst IP"].values[0]
    dst_port = dataframe["Dst Port"].values[0]
    timestamp = dataframe["Timestamp"].values[0]
    return "%s %s:%s => %s:%s" % (timestamp,src_ip, src_port, dst_ip, dst_port)

def prepareDumps():
    if dump_pipeline.createDumps():
        print("Successful creation of pipeline dumps...")
    else:
        print("Error in creation of pipeline dumps...")

def startup():
    # Check network flow csv file if it exists, if not create one.
    curdirname = os.getcwd() # current working directory
    # Generates a filename of the format 'YYYY-MM-DD_Flow.csv'
    global csvfilename
    csvfilename = "%s_Flow.csv" % (datetime.datetime.today().strftime('%Y-%m-%d'))
    isFileExist = os.path.exists(os.path.join(curdirname, r'CICFlowMeter-4.0\bin\data\daily', csvfilename))
    # If network flow csv file does not exist create new one
    if isFileExist == False:
        file = open(os.path.join(curdirname, r'CICFlowMeter-4.0\bin\data\daily', csvfilename), 'w')
        file.close()
    # Start CICFlowMeter
    p = Popen(os.path.join(curdirname, r"CICFlowMeter-4.0\bin\startIDS.bat"), stdout=subprocess.PIPE)
if __name__ == "__main__":
    startup()
    runIDS(verbose=True)
    # prepareDumps()