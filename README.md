# ml_ids
## Overview
Machine learning based Intrusion Detection System (IDS)

## Description
A machine learning-based Intrusion Detection System for detecting network intrusions. Based on Scikit-Learn's [Novelty](https://scikit-learn.org/stable/modules/outlier_detection.html) Detection algorithms of One-Class SVM and Local Outlier Factor (LOF).

## Requirements
Java SE Runtime Environment 1.8\
Python 3.6\
Scikit-Learn 0.21.2\
Pandas 0.24.2 \

## Usage
Install the required packages and dependencies with

```cmd
pip install -r requirements.txt
```

Then run the IDS using 

```cmd
python main.py
```
After the script runs, CICFlowMeter will also start, click on 'Load' to load the interfaces, then click 'Start' to start the capture and generation of flows.



## Acknowledgements
### CICFlowMeter
#### CICFlowMeter
https://github.com/ISCX/CICFlowMeter

A network flow meter created by researchers from the Canadian Institute of Cybersecurity (CIC)

#### Research papers
Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun and Ali A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features", In the proceeding of the 3rd International Conference on Information System Security and Privacy, SCITEPRESS, Porto, Portugal, 2017

Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, Ali A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", In Proceedings of the 2nd International Conference on Information Systems Security and Privacy(ICISSP) , pages 407-414, Rome , Italy, 2016

## License
[MIT](https://choosealicense.com/licenses/mit/)