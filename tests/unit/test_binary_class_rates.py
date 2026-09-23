"""SC-3 reporting-only regression fixtures; no training or dataset predictions."""
import numpy as np
import pytest
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

from sentinel_net.detection.evaluation import AnomalyReport, ClassificationReport


@pytest.mark.parametrize('names', [('benign','ddos'), ('z_benign','a_ddos'), ('ddos','benign')])
def test_asymmetric_binary_orientation(names):
    first, second = names
    y = np.array([first]*4 + [second]*4)
    p = np.array([first]*3 + [second] + [first]*2 + [second]*2)
    r = ClassificationReport.from_predictions(y,p)
    assert r.per_class[first]['fpr'] == .5
    assert r.per_class[first]['fnr'] == .25
    assert r.per_class[second]['fpr'] == .25
    assert r.per_class[second]['fnr'] == .5
    if names == ('benign','ddos'):
        assert r.confusion_matrix.tolist() == [[3,1],[2,2]]
        operational_fp = np.mean(p[y == 'benign'] != 'benign')
        assert operational_fp == r.per_class['benign']['fnr'] == .25
        assert operational_fp != r.per_class['benign']['fpr']


@pytest.mark.parametrize('y,p', [
    (['a','a','b','b'],['a','a','b','b']),
    (['a','a','b','b'],['b','b','a','a']),
    (['a','a','b','b'],['a','a','a','a']),
    (['a','a','a'],['a','b','b']),  # b has zero actual support, but is predicted.
    (['a','a','a'],['a','a','a']),
    (['a','a','b','b','c','c'],['a','b','c','b','a','c']),
])
def test_edge_cases_rates_and_aggregate_invariance(y,p):
    y,p = np.array(y),np.array(p)
    r = ClassificationReport.from_predictions(y,p)
    np.testing.assert_array_equal(r.confusion_matrix,confusion_matrix(y,p))
    assert r.accuracy == accuracy_score(y,p)
    for average in ('macro','weighted'):
        precision,recall,f1,_ = precision_recall_fscore_support(y,p,average=average,zero_division=0)
        assert getattr(r,'precision_'+average) == precision
        assert getattr(r,'recall_'+average) == recall
        assert getattr(r,'f1_'+average) == f1
    # Independent boolean-count oracle, including zero-denominator convention.
    for label in r.class_names:
        positives = y == label; predicted = p == label
        fp = np.sum(~positives & predicted); fn = np.sum(positives & ~predicted)
        assert r.per_class[label]['fpr'] == (fp / np.sum(~positives) if np.any(~positives) else 0.)
        assert r.per_class[label]['fnr'] == (fn / np.sum(positives) if np.any(positives) else 0.)


def test_anomaly_report_unchanged_orientation():
    r = AnomalyReport.from_scores(np.array([0]*4+[1]*4),np.array([.1,.1,.1,.9,.1,.1,.9,.9]),.5)
    assert r.fpr_at_threshold == .25
    assert r.recall_at_threshold == .5
    assert r.precision_at_threshold == pytest.approx(2/3)
    assert r.f1_at_threshold == pytest.approx(4/7)
