"""SC-1/SC-2 regressions; only synthetic preprocessing, no model training."""
import json
import os
import subprocess
import sys
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sentinel_net.detection.audit import LINEAR_MODEL_FEATURES, TREE_MODEL_FEATURES
from sentinel_net.detection.dataset import DatasetBuilder
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.features.schema import FEATURE_SCHEMA

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'experiments/manifests/final-science-partition.json'


def sample():
    scenarios = ['b', 'a', 'c', 'b', 'd']
    return np.arange(260).reshape(5, 52), np.array(['benign'] * 5), scenarios


def manifest():
    return {'version': 1, 'partitions': {'train': ['b', 'a'], 'validation': ['c'], 'test': ['d']}}


def test_explicit_assignment_order_counts_and_identity():
    x, y, s = sample()
    m = manifest()
    identity = {'dataset': 'fixture', 'sha256': 'a' * 64}
    m['dataset_identity'] = identity
    m['expected_row_counts'] = {'train': 3, 'validation': 1, 'test': 1}
    r = DatasetBuilder().explicit_manifest_split(x, y, s, m, dataset_identity=identity)
    np.testing.assert_array_equal(r.X_train, x[[0, 1, 3]])
    assert r.train_scenario_ids == ['b', 'a']
    assert r.provenance['partition_origin'] == 'EXPLICIT_MANIFEST'
    assert r.provenance['row_counts'] == m['expected_row_counts']
    assert r.provenance['random_state'] is None
    identity['dataset'] = 'changed'
    assert r.provenance['dataset_identity']['dataset'] == 'fixture'


@pytest.mark.parametrize('defect', ['missing_key', 'extra_key', 'overlap', 'duplicate', 'omitted', 'unknown', 'empty', 'wrong_type', 'identity', 'counts', 'version', 'rows'])
def test_manifest_rejects_invalid_inputs(defect):
    x, y, s = sample()
    m = manifest()
    if defect == 'missing_key': del m['partitions']['validation']
    if defect == 'extra_key': m['partitions']['extra'] = []
    if defect == 'overlap': m['partitions']['test'].append('a')
    if defect == 'duplicate': m['partitions']['train'].append('a')
    if defect == 'omitted': m['partitions']['train'].remove('a')
    if defect == 'unknown': m['partitions']['test'] = ['unknown']
    if defect == 'empty': m['partitions']['validation'] = []
    if defect == 'wrong_type': m['partitions']['train'] = 'ab'
    if defect == 'identity': m['dataset_identity'] = {'sha256': 'x'}
    if defect == 'counts': m['expected_row_counts'] = {'train': 2, 'validation': 1, 'test': 1}
    if defect == 'version': m['version'] = 2
    if defect == 'rows': y = y[:-1]
    with pytest.raises(ValueError):
        DatasetBuilder().explicit_manifest_split(x, y, s, m)


def test_optional_empty_validation_and_identity_mismatch():
    x, y, s = sample(); m = manifest()
    m['partitions']['train'].append('c'); m['partitions']['validation'] = []
    r = DatasetBuilder().explicit_manifest_split(x, y, s, m, required_partitions=('train', 'test'))
    assert r.X_val is None and r.provenance['row_counts']['validation'] == 0
    m['dataset_identity'] = {'sha256': 'a'}
    with pytest.raises(ValueError):
        DatasetBuilder().explicit_manifest_split(x, y, s, m, dataset_identity={'sha256': 'b'}, required_partitions=('train', 'test'))


def test_fresh_processes_both_modes():
    code = '''import json,numpy as np
from pathlib import Path
from sentinel_net.detection.dataset import DatasetBuilder
m=json.loads(Path('experiments/manifests/final-science-partition.json').read_text())
s=sorted(sum(m['partitions'].values(),[]));x=np.arange(len(s)*52).reshape(len(s),52);y=np.array(['benign']*len(s))
# Miniature fixture preserves assignments/identity; full row counts tested separately.
m.pop('expected_row_counts')
b=DatasetBuilder()
a=b.explicit_manifest_split(x,y,s,m,dataset_identity=m['dataset_identity'])
g=b.scenario_aware_split(x,y,s,random_state=42,dataset_identity=m['dataset_identity'])
print(json.dumps({'explicit':a.provenance,'generated':g.provenance},sort_keys=True))'''
    results = [json.loads(subprocess.check_output([sys.executable, '-c', code], cwd=ROOT,
               env={**os.environ, 'PYTHONHASHSEED': seed}, text=True))
               for seed in ('0', '1', '2', 'random')]
    assert all(r == results[0] for r in results)
    archived = json.loads(MANIFEST.read_text())['partitions']
    for k, p in [('train', 'train_scenarios'), ('validation', 'val_scenarios'), ('test', 'test_scenarios')]:
        assert results[0]['explicit'][p] == archived[k]
    assert results[0]['generated']['partition_origin'] == 'GENERATED_DETERMINISTIC'


MISSING = [15, 16, 17, 18, 23, 33, 44, 48, 49, 50, 51]
@pytest.mark.parametrize('subset', [TREE_MODEL_FEATURES, LINEAR_MODEL_FEATURES], ids=['tree', 'linear'])
@pytest.mark.parametrize('dropped,constant', [([15], [19]), ([2, 15, 23], [19, 24]), ([], [19]), ([], []), ([], [1, 4, 19]), (MISSING, [19, 45])])
def test_fitted_metadata_and_numeric_identity(subset, dropped, constant, tmp_path):
    x = np.random.RandomState(42).normal(size=(32, 52))
    x[:, dropped] = np.nan
    x[:, constant] = 7
    p = FeaturePreprocessor(feature_subset=subset)
    z = p.fit_transform(x)
    expected = [n for n in subset if FEATURE_SCHEMA.index(n) not in dropped]
    assert p.output_feature_names == expected
    assert p.n_features_out == z.shape[1] == len(expected)
    assert p.constant_features == [n for n in expected if FEATURE_SCHEMA.index(n) in constant]
    # Identical numeric recipe used before SC-2; no labels or classifier involved.
    before = Pipeline([('imputer', SimpleImputer(strategy='median')), ('scaler', StandardScaler())])
    selected = x[:, [FEATURE_SCHEMA.index(n) for n in subset]].copy()
    selected[np.isinf(selected)] = np.nan
    np.testing.assert_array_equal(z, before.fit_transform(selected))
    path = tmp_path / 'pp.joblib'; p.save(path); q = FeaturePreprocessor.load(path)
    assert (q.output_feature_names, q.n_features_out, q.constant_features) == (p.output_feature_names, p.n_features_out, p.constant_features)
    np.testing.assert_array_equal(z, q.transform(x))


def test_legacy_stale_metadata_read_without_artifact_mutation(tmp_path):
    x = np.tile(np.arange(8.)[:, None], (1, 52)); x[:, 15] = np.nan; x[:, 19] = 7
    p = FeaturePreprocessor(); z = p.fit_transform(x)
    p._constant_features = ['pkt_size_p90']  # Serialized pre-SC-2 cache.
    path = tmp_path / 'legacy.joblib'; joblib.dump(p, path); raw = path.read_bytes()
    q = FeaturePreprocessor.load(path)
    assert q.constant_features == ['iat_mean'] and q.n_features_out == 51
    assert q._constant_features == ['pkt_size_p90']  # No in-place migration.
    np.testing.assert_array_equal(z, q.transform(x))
    assert path.read_bytes() == raw


def test_unfitted_schema_unavailable():
    p = FeaturePreprocessor()
    with pytest.raises(RuntimeError): _ = p.n_features_out
    with pytest.raises(RuntimeError): _ = p.output_feature_names
    assert p.constant_features == []


def test_locked_manifest_matches_archived_assignment():
    import hashlib
    m = json.loads(MANIFEST.read_text())
    historical_path = ROOT / m['historical_reference']
    h = json.loads(historical_path.read_text())
    assert hashlib.sha256(historical_path.read_bytes()).hexdigest() == m['historical_reference_sha256']
    for key, old_key in [('train', 'train'), ('validation', 'val'), ('test', 'test')]:
        assert m['partitions'][key] == h[old_key + '_scenarios']
        assert m['expected_row_counts'][key] == h[old_key + '_rows']
    assert len(m['dataset_identity']['files']) == 8
