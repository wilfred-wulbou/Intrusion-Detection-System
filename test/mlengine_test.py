import unittest
from mlengine import MLEngine
import pandas as pd

class TestMLEngine(unittest.TestCase):
    # def test_upper(self):
    #     self.assertEqual(MLEngine ("ml_models/svm_clf_model.joblib"), 'Loaded')

    def test_predict(self):
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