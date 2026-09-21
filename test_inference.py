import numpy as np
from pathlib import Path
from sentinel_net.evaluation.adapters import CICIDSAdapter
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.classifier import XGBoostClassifier
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.audit import TREE_MODEL_FEATURES
from sentinel_net.pipeline import PcapPipeline
from sentinel_net.features.schema import FEATURE_SCHEMA

CICIDS_DIR = Path.home() / 'Datasets' / 'CICIDS2017'
SEED = 42

print('Loading CICIDS2017...')
X, labels, _ = CICIDSAdapter.load_all(CICIDS_DIR)

pp = FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES, random_state=SEED)
X_pp = pp.fit_transform(X)

clf = XGBoostClassifier(n_estimators=100, max_depth=6, random_state=SEED)
clf.train(X_pp, labels)

anom = AnomalyDetector(n_estimators=100, random_state=SEED)
benign_mask = labels == 'benign'
anom.train(X_pp[benign_mask])

print('Processing demo PCAP...')
result = PcapPipeline().process(Path('data/demo_traffic.pcap'))
fv_X = np.array([fv.values for fv in result.feature_vectors], dtype=np.float64)
fv_pp = pp.transform(fv_X)

preds = clf.predict(fv_pp)
scores = clf.predict_scores(fv_pp)
anomaly_scores = anom.score(fv_pp)

unique, counts = np.unique(preds, return_counts=True)
print('\nClassification distribution:')
for lbl, cnt in zip(unique, counts):
    print(f'  {lbl}: {cnt}')

print('\nTop prediction probabilities for each class:')
for cls_name, cls_scores in sorted(scores.items()):
    print(f'  {cls_name:20s}: max={cls_scores.max():.4f}, mean={cls_scores.mean():.4f}')
