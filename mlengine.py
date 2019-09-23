# Load saved svm_clf model
from sklearn.externals import joblib
from sklearn.svm import OneClassSVM
from preprocessing.data_preprocessor import IDSPipelineLoader, AttributesRemover

PIPELINE_FILEPATH = "preprocessing/joblib_dumps/ids_pipeline.joblib"
MODEL_FILEPATH = "ml_models/svm_clf_model.joblib"

class MLEngine(object):
    def __init__(self, model_filename=MODEL_FILEPATH):
        # Load the ml model (svm & lof)
        self.mlmodel = joblib.load(model_filename)

        # Load the ids pipeline
        idsPipelineLoader = IDSPipelineLoader(PIPELINE_FILEPATH)
        self.ids_pipeline = idsPipelineLoader.getPipeline()

    def predict(self, data):
        prep_data = self.ids_pipeline.transform(data)
        return self.mlmodel.predict(prep_data)
        