import unittest
from mlengine import MLEngine
import pandas as pd
from preprocessing import constants

class TestMLEngine(unittest.TestCase):
    # def test_upper(self):
    #     self.assertEqual(MLEngine ("ml_models/svm_clf_model.joblib"), 'Loaded')

    def test_predict(self):
        columns = constants.columns

        mlengine = MLEngine()
        resultSet = [-1,1]
        # inputData = [[49188,4,2,0,12,0,6,6,6,0,0,0,0,0,14000,3500,4,0,4,4,4,4,0,4,4,0,0,0,0,0,0,0,0,0,40,0,500000,0,6,6,6,0,0,0,0,0,0,1,1,0,0,0,9,6,0,40,0,0,0,0,0,0,2,12,0,0,329,-1,1,20,0,0,0,0,0,0,0,0]]
        inputData  = [['192.168.91.225-13.107.4.52-65026-80-6','192.168.91.225',65026,'13.107.4.52',80,6,'30/09/2019 07:34:49 PM',19002,2,5,111.0,1009.0,111.0,0.0,55.5,78.48885271170677,1009.0,0.0,201.8,451.2385178594576,58941.164087990735,368.3822755499421,3167.0,3013.9242857112386,7587.0,135.0,543.0,543.0,0.0,543.0,543.0,19002.0,4750.5,2930.5069527301926,8265.0,1358.0,0,0,0,0,40,124,105.25207872855488,263.1301968213872,0.0,1009.0,140.0,353.2708390375375,124800.28571428571,0,1,0,0,0,0,0,0,2.0,160.0,55.5,201.8,0,0,0,0,0,0,2,111,5,1009,-1,115,1,0,0,0,0,0,0,0,0,0,'No Label']]
        prep_inputData = pd.DataFrame(inputData, columns=columns)
        prediction = mlengine.predict(prep_inputData)
        # print(prediction)
        self.assertIn(prediction[0], resultSet)

# if __name__ == '__main__':
#     unittest.main()