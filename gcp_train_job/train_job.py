## Train Job 2

# Fill in your Cloud Storage bucket name
BUCKET_NAME = 'ids_data_bucket2'
cloud_data_dir = 'gs://ids_data_bucket2/ids_datasets'
# local_dir = 'D:\CIC-IDS-2017\TrafficLabelling'
local_dir = "./public_html/ids_dataset/TrafficLabelling/"
iscx_filename = "Monday-WorkingHours.pcap_ISCX.csv"

import pandas as pd
import sklearn
import numpy as np
import joblib
import sys
import subprocess
import datetime
import os
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

class DatasetProperties(object):
    def __init__(self, data_dir, filename, bucket_name=None, *args):
        # Fill in your Cloud Storage bucket name
        self.bucket_name = bucket_name
        self.dir = data_dir
        self.filename = filename
        self.dataset = None

class TrainTask(object):
    def __init__(self, datasetprop, localTrain):
        self.datasetprop = datasetprop
        self.localTrain = localTrain
        
    def create_train_test_df(self, dataframe, test_size=0.2):
        train_set, test_set = train_test_split(dataframe, test_size=test_size, random_state=42)
        return train_set, test_set

    ## Download dataset files from google storage bucket.
    def downloadDatasets(self, data_dir, filename):
        subprocess.check_call(
            ['gsutil', 'cp', os.path.join(data_dir,filename),filename], 
            stderr=sys.stdout)

    # Prepare dataset to match CIC-FlowMeter generated dataset
    def prepToCICFormat(self, df):
        dataframe = df.drop(" Fwd Header Length.1", axis=1)
        dataframe.columns = columns
        return dataframe

    def loadDatasets(self, data_dir, filename, localTrain=False):
        if localTrain:
            raw_dataset =  pd.read_csv(os.path.join(data_dir, filename))
            return self.prepToCICFormat(raw_dataset)
        else:
            self.downloadDatasets(data_dir, filename)
            raw_dataset = pd.read_csv(filename)
            return self.prepToCICFormat(raw_dataset)

    def train_and_evaluate(self):
        data_dir = self.datasetprop.dir
        filename = self.datasetprop.filename
        self.dataset = self.loadDatasets(data_dir, filename, self.localTrain)
        # train_set, test_set = self.create_train_test_df(self.dataset)
        train_set = self.dataset # using te full dataset

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
        
        train_x = train_set.copy()
        train_x = dataclean_pipeline.fit_transform(train_x)
        train_y = train_x["Label"].copy()

        train_x_prepared = prepdata_pipeline.fit_transform(train_x)
        train_y_prepared = ids_label_pipeline.fit_transform(train_y)

        # test_x = test_set.copy()
        # test_x = dataclean_pipeline.transform(test_x)
        # test_y = test_x["Label"].copy()

        # test_x_prepared = prepdata_pipeline.transform(test_x)
        # test_y_prepared = ids_label_pipeline.transform(test_y)

        # PredefinedSplit
        # my_test_fold = []
        # for _ in range(len(cleanset_prepared)):
        #     my_test_fold.append(-1)
        # for _ in range(len(anomalyset_prepared)):
        #     my_test_fold.append(0)
            
        # param_grid = [{'gamma': [0.05,0.1,0.2,0.001,0.02,0.03], 
        #             'kernel': ['rbf',], 
        #             'nu':[0.01,0.05,0.1,0.03,0.3,0.07]
        #             }]
        # estimator = OneClassSVM()

        # grid_search = GridSearchCV(estimator, 
        #                         param_grid, 
        #                         cv=PredefinedSplit(test_fold=my_test_fold),
        #                         scoring='f1_micro'
        #                         )
        # grid_search.fit(np.concatenate((cleanset_prepared,anomalyset_prepared),axis=0), 
        #                 np.concatenate((cleanset_label_prepared,anomalyset_label_prepared),axis=0)
        #             )

        # Print the cv scores.
        # cvres = grid_search.cv_results_
        # for mean_score, params in zip(cvres["mean_test_score"], cvres["params"]):
        #     print(mean_score, params)

        # return grid_search
        estimator = OneClassSVM(gamma=0.2, kernel='rbf', nu=0.07)

        # estimator = OneClassSVM(gamma=0.001, kernel='rbf', nu=0.001) # hyperparams are for test purpose 
        estimator.fit(train_x_prepared)
        return estimator

    def save_model(self, model):
        # Save Monday dataset trained model
        model_filename = "svm_clf_model.joblib"
        joblib.dump(model, model_filename)

        if not self.localTrain:
            # Upload the saved model file to Cloud Storage
            gcs_model_path = os.path.join('gs://', BUCKET_NAME,
                datetime.datetime.now().strftime('svm_clf_model_%Y%m%d_%H%M%S'), model_filename)
            subprocess.check_call(['gsutil', 'cp', model_filename, gcs_model_path],
                stderr=sys.stdout)


if __name__ == "__main__":
    # Train locally on machine
    localTrain = False
    data_dir = ""
    if localTrain:
        print("LocalTrain == True")
        data_dir = local_dir
    else:
        print("LocalTrain == False")
        data_dir = cloud_data_dir

    task = TrainTask(DatasetProperties(data_dir,iscx_filename,BUCKET_NAME),localTrain=localTrain)
    model = task.train_and_evaluate()

    # Saved the grid search model
    task.save_model(model)