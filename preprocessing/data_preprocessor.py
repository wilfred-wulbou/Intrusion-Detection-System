import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.base import BaseEstimator, TransformerMixin

# from sklearn.externals import joblib
import joblib

# Data Preprocessing
class AttributesRemover(BaseEstimator, TransformerMixin):
    def __init__(self, columns=['Flow ID','Src IP','Src Port','Dst IP','Protocol','Timestamp','Label']):
        self.columns=columns
    def fit(self, X, y=None):
        return self # nothing else to do
    def transform(self, X, y=None):
        return X.drop(columns=self.columns, axis=1)

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

# IDSPipeline loads the saved pipeline from file.
class IDSPipelineLoader(object):
    def __init__(self, pipeline_filename):
        self.ids_pipeline = joblib.load(pipeline_filename)
    def getPipeline(self):
        return self.ids_pipeline