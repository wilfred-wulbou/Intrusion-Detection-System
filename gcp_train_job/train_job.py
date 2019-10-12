# This file is for training on AI Platform with scikit-learn.

# [START setup]
import os
import sys
import subprocess
import datetime
import pandas as pd
import sklearn
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.svm import OneClassSVM
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix

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

# Fill in your Cloud Storage bucket name
BUCKET_NAME = 'ids_data_bucket2'
data_dir = 'gs://ids_data_bucket2/ids_datasets'
iris_data_filename = "Monday-WorkingHours.pcap_ISCX.csv"

# Switch for either local train or cloud ml enginne train.
localTrain = True

# [START load-into-pandas]
# iris_data_filename = 'iris_data.csv'
# iris_target_filename = 'iris_target.csv'

## Download dataset files from google storage bucket.
def downloadDatasets():
    # gsutil outputs everything to stderr so we need to divert it to stdout.
    subprocess.check_call(['gsutil', 'cp', os.path.join(data_dir,
                                                        iris_data_filename),
                        iris_data_filename], stderr=sys.stdout)
## Load the IDS Monday Data data
def load_iscx_data(csvfilename):
    return pd.read_csv(csvfilename)

def loadData():
    if localTrain:
        return load_iscx_data(os.path.join('D:\CIC-IDS-2017\TrafficLabelling', iris_data_filename))
    else:
        downloadDatasets()
        return load_iscx_data(iris_data_filename)

# Downloade datasets from Cloud Storage bucket and load them.
dataset = loadData()
# test_dataset = load_iscx_data(csvfilename="Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

# Prepare dataset to match CIC-FlowMeter generated dataset
def prepToCICFormat(df):
    dataframe = df.drop(" Fwd Header Length.1", axis=1)
    dataframe.columns = columns
    return dataframe

dataset = prepToCICFormat(dataset)
# [END load-into-pandas]

# [START train-and-save-model]
train_set, test_set = train_test_split(dataset, test_size=0.8, random_state=42)

# Data Preprocessing
class AttributesRemover(BaseEstimator, TransformerMixin):
    def __init__(self, columns=['Flow ID','Src IP','Src Port','Dst IP','Protocol','Timestamp','Label']):
        self.columns=columns
    def fit(self, X, y=None):
        return self # nothing else to do
    def transform(self, X, y=None):
        # return X.drop(columns=self.columns, axis=1)
        # workaround for google's ml ai engine which does not support drop() with
        # column keyword argument. It uses scikit-learn version = 0.20 and not 0.21
        return X.drop(self.columns, axis=1)
        
# CustomDataCleaner removes NaN,-Infinity, & +Infinity values from columns 'Flow Pkts/s' & 'Flow Byts/s'
# and also fixes the datatype of both columns.
class CustomDataCleaner(TransformerMixin):
    def __init__(self, *args, **kwargs):
        pass
    def fit(self, X, y=None):
        return self
    def transform(self, X, y=None):
        X = X.astype({'Flow Pkts/s':np.float64,'Flow Byts/s':np.float64})
        # Remove nan and inf values in df
        return X[~X.isin([np.nan, np.inf, -np.inf]).any(1)]
    
# source: https://stackoverflow.com/questions/46162855/fit-transform-takes-2-positional-arguments-but-
# 3-were-given-with-labelbinarize  
# Fixes bug in LabelBinarizer.. 
class MyLabelEncoder(TransformerMixin):
    def __init__(self, *args, **kwargs):
        self.encoder = LabelEncoder(*args, **kwargs)
    def fit(self, x, y=0):
        self.encoder.fit(x)
        return self
    def transform(self, x, y=0):
        return self.encoder.transform(x)
    
class AnomalyLabelEncoder(TransformerMixin):
    def __init__(self, *args, **kwargs):
        pass
    def fit(self, X, y=None):
        return self
    def transform(self, X, y=None):
        return ((X * 0) - 1)
    
class BenignLabelEncoder(TransformerMixin):
    def __init__(self, *args, **kwargs):
        pass
    def fit(self, X, y=None):
        return self
    def transform(self, X, y=None):
        return ((X * 0) + 1)
    
# Prepare IDS Dataset   
dataclean_pipeline = Pipeline([
    ('data_cleaner', CustomDataCleaner()),
])

prepdata_pipeline = Pipeline([
    ('attribs_remover', AttributesRemover()),
    ('standard_scaler', StandardScaler()),
])

ids_label_pipeline = Pipeline([
    ('label_encoder', MyLabelEncoder()),
    ('benign_encoder', BenignLabelEncoder()),
])

ids = train_set.copy()
ids = dataclean_pipeline.fit_transform(ids)
ids_label = ids["Label"].copy()

ids_tf = prepdata_pipeline.fit_transform(ids)
ids_label_enc = ids_label_pipeline.fit_transform(ids_label)

# Fitting the data
svm_clf = OneClassSVM(gamma = 0.001, kernel = 'rbf', nu=0.001)
svm_clf.fit(ids_tf)

# Save Monday dataset trained model
model_filename = "svm_clf_model.joblib"
joblib.dump(svm_clf, model_filename)

# [END train-and-save-model]

# [START upload-model]
def uploadDatasets():
    # Upload the saved model file to Cloud Storage
    gcs_model_path = os.path.join('gs://', BUCKET_NAME,
        datetime.datetime.now().strftime('ids_svm_%Y%m%d_%H%M%S'), model_filename)
    subprocess.check_call(['gsutil', 'cp', model_filename, gcs_model_path],
        stderr=sys.stdout)

# Upload saved  model
if localTrain == False:
    uploadDatasets()
# [END upload-model]