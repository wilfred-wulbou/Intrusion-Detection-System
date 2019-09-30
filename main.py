import time
import os
import pandas as pd
from flow_loader.csv_flow_loader import CSVFlowLoader
from mlengine import MLEngine
from output.logfile_generator import OutputGenerator
from prepare_dumps import dump_pipeline

CSVFILEPATH = "CICFlowMeter-4.0\\bin\\data\\daily"
csvfilename = "2019-09-30_Flow.csv"
mlengine_model_filename = "ml_models\\svm_clf_model.joblib"
output_filename = "prediction_log.txt"
columns = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
       'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
       'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
       'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
       'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
       'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
       'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
       'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
       'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']
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
def predictLine(line):
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