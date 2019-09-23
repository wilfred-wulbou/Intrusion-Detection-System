from sklearn.externals import joblib
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler

from preprocessing.data_preprocessor import AttributesRemover

ISCX2017_PATH = "D:\\CIC-IDS-2017\\MachineLearningCVE"
CSVFILENAME = "Monday-WorkingHours.pcap_ISCX.csv"

## Load the IDS Monday Data data
def load_iscx_data(iscx2017_path=ISCX2017_PATH, csvfilename = CSVFILENAME ):
    csv_path = os.path.join(iscx2017_path,csvfilename )
    return pd.read_csv(csv_path)

def dump():
    dataset = load_iscx_data()

    # Train Test Split
    train_set, test_set = train_test_split(dataset, test_size=0.2, random_state=42)
    ids = train_set.drop(" Label", axis=1)

    # Prepare IDS Dataset    
    # Removing columns 'Flow Bytes/s' and ' Flow Packets/s' because they contain 'Infinity' values.

    ids_pipeline = Pipeline([
        ('attribs_remover', AttributesRemover()),
        ('standard_scaler', StandardScaler()),
    ])
    ids_pipeline.fit(ids)

    joblib.dump(ids_pipeline, 'preprocessing/joblib_dumps/ids_pipeline.joblib')