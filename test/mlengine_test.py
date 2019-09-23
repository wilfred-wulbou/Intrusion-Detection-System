import unittest
from mlengine import MLEngine

class TestMLEngine(unittest.TestCase):
    # def test_upper(self):
    #     self.assertEqual(MLEngine ("ml_models/svm_clf_model.joblib"), 'Loaded')

    def test_predict(self):
        mlengine = MLEngine("ml_models/svm_clf_model.joblib")
        resultSet = [1,-1]
        inputData = "49188,4,2,0,12,0,6,6,6,0,0,0,0,0,3000000,500000,4,0,4,4,4,4,0,4,4,0,0,0,0,0,0,0,0,0,40,0,500000,0,6,6,6,0,0,0,0,0,0,1,1,0,0,0,9,6,0,40,0,0,0,0,0,0,2,12,0,0,329,-1,1,20,0,0,0,0,0,0,0,0,BENIGN"
        self.assertIn(mlengine.predict(inputData), resultSet)

# if __name__ == '__main__':
#     unittest.main()