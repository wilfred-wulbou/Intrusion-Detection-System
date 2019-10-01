import os
import pandas as pd
from sklearn.externals import joblib
from sklearn.model_selection import train_test_split
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from preprocessing.data_preprocessor import AttributesRemover
from preprocessing import constants

ISCX2017_PATH = "D:\\CIC-IDS-2017\\TrafficLabelling"
CSVFILENAME = "Monday-WorkingHours.pcap_ISCX.csv"

columns = constants.columns

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