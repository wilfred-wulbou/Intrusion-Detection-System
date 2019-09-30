import os
import pandas as pd
from sklearn.externals import joblib
from sklearn.model_selection import train_test_split
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from preprocessing.data_preprocessor import AttributesRemover

ISCX2017_PATH = "D:\\CIC-IDS-2017\\TrafficLabelling"
CSVFILENAME = "Monday-WorkingHours.pcap_ISCX.csv"

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

## Load the IDS Monday Data data
def load_iscx_data(iscx2017_path=ISCX2017_PATH, csvfilename=CSVFILENAME ):
    csv_path = os.path.join(iscx2017_path,csvfilename )
    return pd.read_csv(csv_path)

def dump():
    dataset = load_iscx_data()

    # Prepare dataset to match CIC-FlowMeter generated dataset
    dataset = dataset.drop(" Fwd Header Length.1", axis=1)
    dataset.columns = columns

    #  Train Test Split
    train_set, test_set = train_test_split(dataset, test_size=0.8, random_state=42)
    
    # Prepare IDS Dataset    
    # Removing columns ['Flow ID','Src IP','Src Port','Dst IP','Protocol','Timestamp',
    #                   'Flow Byts/s','Flow Pkts/s', 'Label'] 
    ids_pipeline = Pipeline([
        ('attribs_remover', AttributesRemover()),
        ('standard_scaler', StandardScaler()),
    ])

    ids_pipeline.fit(train_set)
    joblib.dump(ids_pipeline, 'preprocessing/joblib_dumps/ids_pipeline.joblib')

def createDumps():
    load_iscx_data()
    dump()
    return True