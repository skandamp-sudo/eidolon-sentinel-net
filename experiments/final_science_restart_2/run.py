"""Fixed-manifest scientific run; no source edits or approved-registry publication."""
import json,hashlib,subprocess,time,sys,warnings
from pathlib import Path
from dataclasses import asdict
import numpy as np
from sklearn.metrics import average_precision_score
from sentinel_net.evaluation.adapters import CICIDSAdapter
from sentinel_net.detection.dataset import DatasetBuilder
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.audit import TREE_MODEL_FEATURES,LINEAR_MODEL_FEATURES
from sentinel_net.detection.classifier import XGBoostClassifier,RandomForestBaseline,LogisticRegressionBaseline
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.evaluation import ClassificationReport,AnomalyReport
from sentinel_net.detection.threshold_optimizer import ThresholdOptimizer
from sentinel_net.detection.inference import DetectionPipeline
from sentinel_net.detection.thresholds import ThresholdConfig
from sentinel_net.deployment.bundle import write_candidate,_load_directory,versions
from sentinel_net.features.schema import FEATURE_SCHEMA
O=Path('experiments/final_science_restart_2');O.mkdir(exist_ok=True)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def normalize(x):
 if isinstance(x,dict):return {str(k):normalize(v) for k,v in x.items()}
 if isinstance(x,(list,tuple)):return [normalize(v) for v in x]
 if isinstance(x,np.ndarray):return normalize(x.tolist())
 if isinstance(x,np.generic):return normalize(x.item())
 if isinstance(x,float) and not np.isfinite(x):return None
 return x
def save(n,x):(O/n).write_text(json.dumps(normalize(x),indent=2,allow_nan=False)+'\n')
def log(x):print(x,flush=True)
b=json.loads(Path('docs/sci-corr-2-scientific-integrity.json').read_text());assert all(sha(p)==h for p,h in b['sha256'].items())
mp=Path('experiments/manifests/final-science-partition.json');assert sha(mp)==b['split_manifest_sha256'];m=json.loads(mp.read_text())
identity={'dataset_id':'CICIDS2017','files':{n:sha(Path.home()/'Datasets/CICIDS2017'/n) for n in m['dataset_identity']['files']}};assert identity==m['dataset_identity']
assert Path('docs/final-science-restart-2-audit/preflight.json').exists()
config={'seed':42,'run_label':'SINGLE-SEED REPRODUCIBILITY RUN','source_revision':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'harness_sha256':sha(__file__),'dataset':identity,'split_manifest_sha256':sha(mp),'dependencies':versions(),'threshold_protocol':'Existing validation F1 grid plus validation-benign quantiles for 1%/5% operating points; all exploratory due to narrow validation. No test selection.','macro_label_policy':'ClassificationReport default union of true/predicted labels; zero-support absent labels listed separately, not meaningful recall.','novelty_protocol':'Fixed original partitions only. C2 absent from train already. DDoS separate preprocessing excludes all DDoS training rows; Isolation Forest benign-only. Families absent from fixed test not evaluated.','robustness_protocol':'Existing perturbations on first 10000 test rows in deterministic adapter input order, seed42; unavailable NaN must remain missing. No retuning.'}
models={'XGBoost':XGBoostClassifier(n_estimators=100,max_depth=6,random_state=42),'RandomForest':RandomForestBaseline(n_estimators=100,random_state=42),'LogisticRegression':LogisticRegressionBaseline(max_iter=1000,random_state=42)}
iforest=AnomalyDetector(n_estimators=100,random_state=42)
config['estimators']={n:v._model.get_params(deep=True) for n,v in models.items()};config['estimators']['IsolationForest']=iforest._model.get_params(deep=True)
save('locked-config.json',config)
log('Loading adapter, fixed partition only')
x,y,s=CICIDSAdapter.load_all(Path.home()/'Datasets/CICIDS2017');split=DatasetBuilder().explicit_manifest_split(x,y,s.tolist(),m,dataset_identity=identity);del x,y,s
save('split-used.json',split.provenance)
pp=FeaturePreprocessor(feature_subset=TREE_MODEL_FEATURES);xt=pp.fit_transform(split.X_train);xv=pp.transform(split.X_val)
assert xt.shape[1]==pp.n_features_out==len(pp.output_feature_names)==41
pp.save(O/'tree-preprocessor.joblib')
training={}
for name in ('XGBoost','RandomForest'):
 log('TRAIN '+name);start=time.monotonic();models[name].train(xt,split.y_train);models[name].save(O/(name+'.joblib'));training[name]={'seconds':time.monotonic()-start,'parameters':models[name]._model.get_params(deep=True),'classes':models[name].supported_classes,'rows':len(xt),'features':pp.output_feature_names};save('training-progress.json',training);log('SAVED '+name)
log('TRAIN IsolationForest benign-only');start=time.monotonic();iforest.train(xt[split.y_train=='benign']);iforest.save(O/'IsolationForest.joblib');training['IsolationForest']={'seconds':time.monotonic()-start,'parameters':iforest._model.get_params(deep=True),'rows':int(np.sum(split.y_train=='benign')),'features':pp.output_feature_names};del xt
linear=FeaturePreprocessor(feature_subset=LINEAR_MODEL_FEATURES);xl=linear.fit_transform(split.X_train);assert xl.shape[1]==linear.n_features_out==40
linear.save(O/'linear-preprocessor.joblib');log('TRAIN LogisticRegression');start=time.monotonic();models['LogisticRegression'].train(xl,split.y_train);models['LogisticRegression'].save(O/'LogisticRegression.joblib');training['LogisticRegression']={'seconds':time.monotonic()-start,'parameters':models['LogisticRegression']._model.get_params(deep=True),'classes':models['LogisticRegression'].supported_classes,'rows':len(xl),'features':linear.output_feature_names,'n_iter':models['LogisticRegression']._model.n_iter_};del xl
save('training.json',training);log('Training complete; selecting validation-only thresholds')
vs=iforest.score(xv);search=ThresholdOptimizer(objective='f1').search((split.y_val!='benign').astype(int),vs)
thresholds={'validation_f1':search.optimal_threshold,'default':.5,**{f'validation_benign_fpr_{rate}':float(np.quantile(vs[split.y_val=='benign'],1-rate,method='higher')) for rate in (.01,.05)}}
save('threshold-lock.json',{'status':'EXPLORATORY','selection':asdict(search),'thresholds':thresholds,'validation_counts':{'benign':int(sum(split.y_val=='benign')),'other':int(sum(split.y_val=='other'))}})
config_hash=sha(O/'locked-config.json');candidate=write_candidate(DetectionPipeline(pp,iforest,models['XGBoost'],ThresholdConfig(anomaly_threshold=search.optimal_threshold)),O/'candidate',name='final-science-xgboost',version='2026.09.23-seed42',training_seed=42,dataset_identifier='CICIDS2017-fixed-historical-partition',dataset_hash=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest(),training_configuration_hash=config_hash,code_revision=config['source_revision'])
save('candidate-identity.json',{'path':str(candidate),'manifest_sha256':sha(candidate/'manifest.json'),'split_manifest_sha256':sha(mp),'training_config_sha256':config_hash,'status':'CANDIDATE NOT APPROVED NOT PUBLISHED','component_sha256':{p.name:sha(p) for p in candidate.iterdir() if p.is_file()}})
log('Thresholds and candidate locked; evaluating TEST')
xte=pp.transform(split.X_test);metrics={}
for name,model in models.items():
 z=linear.transform(split.X_test) if name=='LogisticRegression' else xte
 prediction=model.predict(z);report=asdict(ClassificationReport.from_predictions(split.y_test,prediction));benign=split.y_test=='benign';wrong=prediction[benign]!='benign';keys,counts=np.unique(prediction[benign][wrong],return_counts=True)
 report['test_rows']=len(prediction);report['benign_to_malicious']={'support':int(sum(benign)),'predicted_benign':int(sum(~wrong)),'predicted_non_benign':int(sum(wrong)),'rate':float(np.mean(wrong)),'by_predicted_class':dict(zip(keys,counts))}
 conf=np.max(np.column_stack(list(model.predict_scores(z).values())),axis=1);report['model_confidence_score']={'calibrated':False,'quantiles':np.quantile(conf,[0,.25,.5,.75,.95,1]),'benign_fp_quantiles':np.quantile(conf[benign][wrong],[0,.5,.95,1]) if sum(wrong) else None}
 metrics[name]=report;save('supervised.json',metrics);log('TEST saved '+name)
ts=iforest.score(xte);anomaly={k:asdict(AnomalyReport.from_scores((split.y_test!='benign').astype(int),ts,v)) for k,v in thresholds.items()};anomaly['average_precision']=average_precision_score(split.y_test!='benign',ts);save('anomaly.json',anomaly)
loaded=_load_directory(candidate,approved=False)
# Loader returns pipeline: compare fixed first TRAIN vector, never retrain.
if isinstance(loaded,tuple):loaded=loaded[0]
z=pp.transform(split.X_train[:1]);zl=loaded.preprocessor.transform(split.X_train[:1]);assert np.array_equal(z,zl)
assert all(np.array_equal(v,loaded.classifier.predict_scores(zl)[k]) for k,v in models['XGBoost'].predict_scores(z).items());assert np.array_equal(iforest.score(z),loaded.anomaly_detector.score(zl));save('candidate-parity.json',{'exact':True,'vector':'first TRAIN row','source_candidate_manifest_sha256':sha(candidate/'manifest.json')})
log('Primary evaluation and candidate parity complete')
