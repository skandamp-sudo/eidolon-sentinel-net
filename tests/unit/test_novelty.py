import pytest
import numpy as np
from sentinel_net.evaluation.novelty import (
    Phase8Protocol,
    ProtocolViolation,
    LeaveOneAttackOut,
    NoveltyRanking,
    SupervisedAnomalyFusion,
    MultiOperatingPointAnalysis,
    CategorizedFPAnalysis,
    validate_result_category
)

# 1. validate_result_category
def test_validate_result_category_real_data():
    assert validate_result_category("REAL_DATA") == "REAL_DATA"

def test_validate_result_category_simulated():
    assert validate_result_category("SIMULATED") == "SIMULATED"

def test_validate_result_category_synthetic():
    assert validate_result_category("SYNTHETIC") == "SYNTHETIC"

def test_validate_result_category_documentation_only():
    assert validate_result_category("DOCUMENTATION_ONLY") == "DOCUMENTATION_ONLY"

def test_validate_result_category_not_applicable():
    assert validate_result_category("NOT_APPLICABLE") == "NOT_APPLICABLE"

def test_validate_result_category_invalid_raises():
    with pytest.raises(ValueError, match="Invalid result_category"):
        validate_result_category("INVALID")

# 2. Phase8Protocol State Machine
def test_protocol_initial_state():
    p = Phase8Protocol("test")
    assert p.state == "DATA_LOADED"
    assert p.experiment_id == "test"
    assert p.random_seed == 42

def test_protocol_register_split_success():
    p = Phase8Protocol("test")
    p.register_split(["A"], ["B"], ["C"], 10, 5, 5)
    assert p.state == "SPLIT_CREATED"

def test_protocol_register_split_disjoint_train_val_overlap():
    p = Phase8Protocol("test")
    with pytest.raises(ProtocolViolation):
        p.register_split(["A", "B"], ["B"], ["C"], 10, 5, 5)

def test_protocol_register_split_disjoint_train_test_overlap():
    p = Phase8Protocol("test")
    with pytest.raises(ProtocolViolation):
        p.register_split(["A"], ["B"], ["A"], 10, 5, 5)

def test_protocol_register_split_disjoint_val_test_overlap():
    p = Phase8Protocol("test")
    with pytest.raises(ProtocolViolation):
        p.register_split(["A"], ["B"], ["B"], 10, 5, 5)

def test_protocol_lock_training_success():
    p = Phase8Protocol("test")
    p.register_split(["A"], ["B"], ["C"], 10, 5, 5)
    p.lock_training({"atk": 1})
    assert p.state == "TRAIN_LOCKED"

def test_protocol_lock_training_out_of_order():
    p = Phase8Protocol("test")
    with pytest.raises(ProtocolViolation):
        p.lock_training({"atk": 1})

def test_protocol_lock_validation_success():
    p = Phase8Protocol("test")
    p.register_split(["A"], ["B"], ["C"], 10, 5, 5)
    p.lock_training({"atk": 1})
    p.lock_validation({"atk": 1})
    assert p.state == "VALIDATION_LOCKED"

def test_protocol_lock_threshold_success():
    p = Phase8Protocol("test")
    p.state = "VALIDATION_LOCKED"
    p.lock_threshold(0.5, "default")
    assert p.state == "THRESHOLD_LOCKED"
    assert p._threshold == 0.5
    assert p._threshold_source == "default"

def test_protocol_lock_threshold_invalid_source():
    p = Phase8Protocol("test")
    p.state = "VALIDATION_LOCKED"
    with pytest.raises(ValueError):
        p.lock_threshold(0.5, "invalid")

def test_protocol_lock_test_success():
    p = Phase8Protocol("test")
    p.state = "THRESHOLD_LOCKED"
    p.lock_test({"atk": 1})
    assert p.state == "FINAL_TEST_LOCKED"

def test_protocol_record_evaluation_success():
    p = Phase8Protocol("test")
    p.state = "FINAL_TEST_LOCKED"
    p.record_evaluation({"acc": 1.0})
    assert p.state == "EVALUATED"
    assert p._metrics == {"acc": 1.0}

def test_protocol_write_artifact_success():
    p = Phase8Protocol("test")
    p.state = "EVALUATED"
    p.write_artifact("dummy_path")
    assert p.state == "ARTIFACT_WRITTEN"

def test_protocol_assert_no_threshold_change():
    p = Phase8Protocol("test")
    p.state = "FINAL_TEST_LOCKED"
    with pytest.raises(ProtocolViolation):
        p.assert_no_threshold_change()

def test_protocol_assert_no_retraining():
    p = Phase8Protocol("test")
    p.state = "EVALUATED"
    with pytest.raises(ProtocolViolation):
        p.assert_no_retraining()

def test_protocol_to_manifest():
    p = Phase8Protocol("test", random_seed=99)
    manifest = p.to_manifest()
    assert manifest["experiment_id"] == "test"
    assert manifest["random_seed"] == 99
    assert manifest["state"] == "DATA_LOADED"

# 3. LeaveOneAttackOut
def test_loao_init():
    loao = LeaveOneAttackOut(random_seed=123)
    assert loao.random_seed == 123
    assert loao.MIN_SAMPLES == 50

def test_loao_get_eligible_families_empty():
    loao = LeaveOneAttackOut()
    labels = np.array(["benign", "benign"])
    scenarios = np.array(["sc1", "sc1"])
    e, i = loao.get_eligible_families(labels, scenarios)
    assert not e
    assert not i

def test_loao_get_eligible_families_above_threshold():
    loao = LeaveOneAttackOut()
    labels = np.array(["attack1"] * 50 + ["benign"] * 10)
    scenarios = np.array(["sc1"] * 60)
    e, i = loao.get_eligible_families(labels, scenarios)
    assert e == ["attack1"]
    assert not i

def test_loao_get_eligible_families_below_threshold():
    loao = LeaveOneAttackOut()
    labels = np.array(["attack1"] * 49 + ["benign"] * 10)
    scenarios = np.array(["sc1"] * 59)
    e, i = loao.get_eligible_families(labels, scenarios)
    assert not e
    assert i == ["attack1"]

def test_loao_build_folds_counts():
    loao = LeaveOneAttackOut(random_seed=42)
    labels = np.array(["attack1"]*60 + ["attack2"]*10 + ["benign"]*100)
    scenarios = np.array(["sc1"]*60 + ["sc2"]*10 + ["sc3"]*100)
    folds = loao.build_folds(labels, scenarios)
    assert len(folds) == 2
    f1 = [f for f in folds if f.held_out_family == "attack1"][0]
    f2 = [f for f in folds if f.held_out_family == "attack2"][0]
    assert f1.feasible is True
    assert f2.feasible is False
    assert f2.result_category == "NOT_APPLICABLE"

def test_loao_build_folds_scenario_disjointness():
    loao = LeaveOneAttackOut(random_seed=42)
    labels = np.array(["attack1"]*60 + ["benign"]*60 + ["benign"]*60)
    scenarios = np.array(["sc1"]*60 + ["sc2"]*60 + ["sc3"]*60)
    folds = loao.build_folds(labels, scenarios)
    f = folds[0]
    ts = set(f.train_scenarios)
    vs = set(f.val_scenarios)
    es = set(f.test_scenarios)
    assert not ts & vs
    assert not ts & es
    assert not vs & es
    assert f.test_scenarios == ["sc1"]

def test_loao_get_fold_data():
    loao = LeaveOneAttackOut(random_seed=42)
    X = np.arange(180)
    labels = np.array(["attack1"]*60 + ["benign"]*60 + ["benign"]*60)
    scenarios = np.array(["sc1"]*60 + ["sc2"]*60 + ["sc3"]*60)
    folds = loao.build_folds(labels, scenarios)
    f = folds[0]
    X_tr, y_tr, X_val, y_val, X_te, y_te = loao.get_fold_data(X, labels, scenarios, f)
    assert len(X_tr) + len(X_val) + len(X_te) == 180
    assert len(y_tr) == len(X_tr)
    assert len(y_val) == len(X_val)
    assert len(y_te) == len(X_te)

def test_loao_verify_no_leakage_true():
    loao = LeaveOneAttackOut()
    f = type("Fold", (), {"held_out_family": "attack1"})()
    assert loao.verify_no_leakage(f, np.array(["benign", "attack2"])) is True

def test_loao_verify_no_leakage_false():
    loao = LeaveOneAttackOut()
    f = type("Fold", (), {"held_out_family": "attack1"})()
    assert loao.verify_no_leakage(f, np.array(["benign", "attack1"])) is False

# 4. NoveltyRanking
def test_novelty_ranking_distribution_stats_empty():
    nr = NoveltyRanking()
    res = nr._distribution_stats(np.array([]))
    assert res["mean"] == 0.0
    assert res["max"] == 0.0

def test_novelty_ranking_distribution_stats():
    nr = NoveltyRanking()
    res = nr._distribution_stats(np.array([1.0, 2.0, 3.0]))
    assert res["mean"] == 2.0
    assert res["min"] == 1.0
    assert res["max"] == 3.0
    assert res["median"] == 2.0

def test_novelty_ranking_analyze_separable():
    nr = NoveltyRanking()
    res = nr.analyze(np.array([0.1, 0.2]), np.array([0.8, 0.9]))
    assert res.roc_auc == 1.0
    assert res.pr_auc > 0.0
    assert res.score_separation > 0.5
    assert res.n_benign == 2
    assert res.n_attack == 2

def test_novelty_ranking_analyze_not_separable():
    nr = NoveltyRanking()
    res = nr.analyze(np.array([0.9, 0.8]), np.array([0.1, 0.2]))
    assert res.roc_auc == 0.0
    assert res.score_separation < 0.0

def test_novelty_ranking_analyze_one_class():
    nr = NoveltyRanking()
    res = nr.analyze(np.array([0.1, 0.2]), np.array([]))
    assert res.roc_auc == 0.0 # ValueError caught

# 5. SupervisedAnomalyFusion
def test_saf_init():
    saf = SupervisedAnomalyFusion()
    assert saf._fitted is False
    assert saf.tau_known is None

def test_saf_fit_thresholds():
    saf = SupervisedAnomalyFusion()
    y_true = np.array(["benign", "atk", "benign", "atk"])
    sp = np.array(["benign", "atk", "benign", "benign"])
    sc = np.array([0.9, 0.8, 0.9, 0.2])
    ano = np.array([0.1, 0.3, 0.2, 0.9])
    res = saf.fit_thresholds(y_true, sp, sc, ano)
    assert saf._fitted is True
    assert "tau_known" in res

def test_saf_predict_not_fitted():
    saf = SupervisedAnomalyFusion()
    with pytest.raises(RuntimeError):
        saf.predict(np.array([]), np.array([]), np.array([]))

def test_saf_predict_known_attack():
    saf = SupervisedAnomalyFusion()
    saf.tau_known = 0.8
    saf.tau_anomaly = 0.8
    saf.tau_benign = 0.2
    saf._fitted = True
    preds = saf.predict(np.array(["atk"]), np.array([0.9]), np.array([0.1]))
    assert preds[0] == "KNOWN_ATTACK"

def test_saf_predict_novel_anomaly():
    saf = SupervisedAnomalyFusion()
    saf.tau_known = 0.8
    saf.tau_anomaly = 0.8
    saf.tau_benign = 0.2
    saf._fitted = True
    preds = saf.predict(np.array(["benign"]), np.array([0.9]), np.array([0.85]))
    assert preds[0] == "NOVEL_ANOMALY"

def test_saf_predict_benign():
    saf = SupervisedAnomalyFusion()
    saf.tau_known = 0.8
    saf.tau_anomaly = 0.8
    saf.tau_benign = 0.2
    saf._fitted = True
    preds = saf.predict(np.array(["benign"]), np.array([0.9]), np.array([0.1]))
    assert preds[0] == "BENIGN"

def test_saf_predict_uncertain():
    saf = SupervisedAnomalyFusion()
    saf.tau_known = 0.8
    saf.tau_anomaly = 0.8
    saf.tau_benign = 0.2
    saf._fitted = True
    preds = saf.predict(np.array(["benign"]), np.array([0.9]), np.array([0.5]))
    assert preds[0] == "UNCERTAIN"

def test_saf_evaluate():
    saf = SupervisedAnomalyFusion()
    saf.tau_known = 0.8; saf.tau_anomaly = 0.8; saf.tau_benign = 0.2
    y_true = np.array(["benign", "atk", "novel", "benign"])
    preds = np.array(["BENIGN", "KNOWN_ATTACK", "NOVEL_ANOMALY", "NOVEL_ANOMALY"])
    res = saf.evaluate(y_true, preds, {"atk"})
    assert res["tp_known_attack"] == 1
    assert res["tp_novel_anomaly"] == 1
    assert res["tn_benign"] == 1
    assert res["fp_novel"] == 1
    assert res["n_total"] == 4

# 6. MultiOperatingPointAnalysis
def test_mopa_analyze_normal():
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    res = MultiOperatingPointAnalysis.analyze(y, scores, 0.5, 0.5)
    assert res["roc_auc"] == 1.0
    assert "default" in res
    assert "validation_optimal" in res

def test_mopa_analyze_one_class():
    y = np.array([0, 0, 0])
    scores = np.array([0.1, 0.2, 0.3])
    res = MultiOperatingPointAnalysis.analyze(y, scores, 0.5)
    assert res["roc_auc"] == 0.0

def test_mopa_analyze_curves():
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    res = MultiOperatingPointAnalysis.analyze(y, scores, 0.5)
    assert len(res["roc_curve"]["fpr"]) > 0
    assert res["pr_auc"] > 0.0

def test_mopa_recall_at_fpr():
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    res = MultiOperatingPointAnalysis.analyze(y, scores, 0.5)
    assert res["recall_at_1pct_fpr"]["target_fpr"] == 0.01
    assert res["recall_at_5pct_fpr"]["target_fpr"] == 0.05

# 7. CategorizedFPAnalysis
def test_cfpa_analyze_basic():
    scores = np.array([0.8, 0.1])
    y_true = np.array(["benign", "benign"])
    preds = np.array([1, 0])
    scen = np.array(["sc1", "sc2"])
    res = CategorizedFPAnalysis.analyze(scores, y_true, preds, scen, 0.5)
    assert res["total_false_positives"] == 1
    assert res["total_benign"] == 2
    assert res["fpr"] == 0.5
    assert res["threshold"] == 0.5

def test_cfpa_analyze_scenarios():
    scores = np.array([0.8, 0.8])
    y_true = np.array(["benign", "benign"])
    preds = np.array([1, 1])
    scen = np.array(["sc1", "sc1"])
    res = CategorizedFPAnalysis.analyze(scores, y_true, preds, scen, 0.5)
    assert res["by_scenario"]["sc1"]["false_positives"] == 2
    assert res["by_scenario"]["sc1"]["total_benign"] == 2
    assert res["by_scenario"]["sc1"]["fp_rate"] == 1.0

def test_cfpa_analyze_score_ranges():
    scores = np.array([0.45, 0.55, 0.65, 0.85])
    y_true = np.array(["benign", "benign", "benign", "benign"])
    preds = np.array([1, 1, 1, 1])
    scen = np.array(["s"]*4)
    res = CategorizedFPAnalysis.analyze(scores, y_true, preds, scen, 0.4)
    r = res["by_score_range"]
    assert r["0.4-0.5"] == 1
    assert r["0.5-0.6"] == 1
    assert r["0.6-0.7"] == 1
    assert r["0.7-1.0"] == 1
