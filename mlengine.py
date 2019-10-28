# Load saved svm_clf model
# from sklearn.externals import joblib
import joblib
from sklearn.svm import OneClassSVM
from preprocessing.data_preprocessor import IDSPipelineLoader, AttributesRemover

# PIPELINE_FILEPATH = "preprocessing/joblib_dumps/ids_pipeline.joblib"
DATACLEAN_PIPELINE_FILEPATH = "preprocessing/joblib_dumps/dataclean_pipeline.joblib"
DATAPREP_PIPELINE_FILEPATH = "preprocessing/joblib_dumps/dataprep_pipeline.joblib"
# MODEL_FILEPATH = "ml_models/svm_clf_model.joblib" 
MODEL_FILEPATH = "ml_models/svm_clf_model_20191016_182601_svm_clf_model.joblib"

class MLEngine(object):
    def __init__(
        self, 
        model_filename=MODEL_FILEPATH, 
        dataclean_pipeline_filename=DATACLEAN_PIPELINE_FILEPATH, 
        dataprep_pipeline_filename=DATAPREP_PIPELINE_FILEPATH
        ):
        # Load the ml model (svm & lof)
        self.mlmodel = joblib.load(model_filename)

        # Load the ids pipeline
        dataclean_PipelineLoader = IDSPipelineLoader(DATACLEAN_PIPELINE_FILEPATH)
        dataprep_PipelineLoader =  IDSPipelineLoader(DATAPREP_PIPELINE_FILEPATH)

        self.dataclean_pipeline = dataclean_PipelineLoader.getPipeline()
        self.dataprep_pipeline = dataprep_PipelineLoader.getPipeline()

    def predict(self, data):
        clean_data = self.dataclean_pipeline.transform(data)
        prep_data = self.dataprep_pipeline.transform(clean_data)
        return self.mlmodel.predict(prep_data)
        