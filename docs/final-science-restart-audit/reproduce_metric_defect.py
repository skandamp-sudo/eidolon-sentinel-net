"""Synthetic metric-only reproduction: no dataset predictions or model training."""
import json
import numpy as np
from sentinel_net.detection.evaluation import ClassificationReport

truth = np.array(['benign'] * 4 + ['ddos'] * 4)
predicted = np.array(['benign', 'benign', 'benign', 'ddos', 'benign', 'benign', 'ddos', 'ddos'])
r = ClassificationReport.from_predictions(truth, predicted)
expected = {'benign': {'fpr': 2/4, 'fnr': 1/4}, 'ddos': {'fpr': 1/4, 'fnr': 2/4}}
observed = {k: {m: float(r.per_class[k][m]) for m in ('fpr','fnr')} for k in expected}
assert r.confusion_matrix.tolist() == [[3, 1], [2, 2]]
assert observed['benign'] != expected['benign']
assert observed['ddos'] == expected['ddos']
print(json.dumps({'fixture':'synthetic eight-row confusion-matrix check','class_order':r.class_names,'confusion_matrix':r.confusion_matrix.tolist(),'support':{'benign':4,'ddos':4},'expected_one_vs_rest':expected,'reported':observed,'defect_reproduced':True,'models_trained':False},indent=2))
