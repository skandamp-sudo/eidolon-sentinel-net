"""Predeclared supplementary experiments with the same fixed partition."""
import json,hashlib
from dataclasses import asdict
from pathlib import Path
import numpy as np
from sentinel_net.evaluation.adapters import CICIDSAdapter,UNSWAdapter
from sentinel_net.detection.dataset import DatasetBuilder
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.classifier import XGBoostClassifier
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.evaluation import ClassificationReport,AnomalyReport
from sentinel_net.evaluation.unidirectional import SimulatedUnidirectionalAblation
from sentinel_net.evaluation.robustness import RobustnessEvaluator,timing_jitter,packet_size_noise,flow_duration_perturbation,directional_imbalance,missing_metadata
from sklearn.metrics import average_precision_score
O=Path('experiments/final_science_restart_2')
def cv(v):
 if isinstance(v,dict):return {str(k):cv(x) for k,x in v.items()}
 if isinstance(v,(list,tuple)):return [cv(x) for x in v]
 if isinstance(v,np.ndarray):return cv(v.tolist())
 if isinstance(v,np.generic):return cv(v.item())
 if isinstance(v,float) and not np.isfinite(v):return None
 return v
def save(n,r):(O/n).write_text(json.dumps(cv(r),indent=2,allow_nan=False)+'\n')
def log(v):print(v,flush=True)
assert (O/'candidate-parity.json').exists()
m=json.loads(Path('experiments/manifests/final-science-partition.json').read_text());identity={'dataset_id':'CICIDS2017','files':{n:hashlib.sha256((Path.home()/'Datasets/CICIDS2017'/n).read_bytes()).hexdigest() for n in m['dataset_identity']['files']}};assert identity==m['dataset_identity']
log('Loading fixed data for supplementary experiments')
x,y,s=CICIDSAdapter.load_all(Path.home()/'Datasets/CICIDS2017');r=DatasetBuilder().explicit_manifest_split(x,y,s.tolist(),m,dataset_identity=identity);del x,y,s
pp=FeaturePreprocessor.load(O/'tree-preprocessor.joblib');model=XGBoostClassifier.load(O/'XGBoost.joblib');detector=AnomalyDetector.load(O/'IsolationForest.joblib')
novelty={}
for family in ('c2','ddos'):
 if family=='c2':q=pp;d=detector
 else:
  keep=r.y_train!=family;q=FeaturePreprocessor();z=q.fit_transform(r.X_train[keep]);d=AnomalyDetector(n_estimators=100,random_state=42);d.train(z[r.y_train[keep]=='benign']);del z
  q.save(O/'novelty-ddos-preprocessor.joblib');d.save(O/'novelty-ddos-iforest.joblib')
 mask=np.isin(r.y_test,['benign',family]);labels=(r.y_test[mask]==family).astype(int);scores=d.score(q.transform(r.X_test[mask]));vs=d.score(q.transform(r.X_val[r.y_val=='benign']))
 rates={str(a):float(np.quantile(vs,1-a,method='higher')) for a in (.01,.05)}
 novelty[family]={'label':'HELD-OUT ATTACK-FAMILY EVALUATION','model':'IsolationForest only','status':'LIMITED / EXPERIMENTAL','train_family_support_excluded':int(sum(r.y_train==family)),'training_benign_support':int(sum(r.y_train=='benign')),'test_family_support':int(sum(labels)),'test_benign_support':int(sum(labels==0)),'ranking':asdict(AnomalyReport.from_scores(labels,scores,.5)),'average_precision':average_precision_score(labels,scores),'validation_benign_support':len(vs),'operating_points':{k:{'threshold':t,'validation_achieved_fpr':float(np.mean(vs>=t)),'test':asdict(AnomalyReport.from_scores(labels,scores,t))} for k,t in rates.items()}}
 save('novelty.json',novelty);log('Novelty '+family+' saved')
for family in ('brute_force','reconnaissance','exfiltration','other'):novelty[family]={'status':'NOT EVALUATED — INSUFFICIENT SUPPORT','reason':'No samples of this family in the mandatory fixed TEST partition; scenarios not moved','train_support':int(sum(r.y_train==family)),'test_support':int(sum(r.y_test==family))}
save('novelty.json',novelty)
log('One-way full TEST')
base=model.predict(pp.transform(r.X_test));sim=SimulatedUnidirectionalAblation();uni=sim.simulate_unidirectional(r.X_test);uni[np.isnan(r.X_test)]=np.nan;pred=model.predict(pp.transform(uni));a=ClassificationReport.from_predictions(r.y_test,base);b=ClassificationReport.from_predictions(r.y_test,pred)
one={'label':'SIMULATED UNIDIRECTIONAL TELEMETRY LOSS','rows':len(base),'features_zeroed_where_available':sim.features_zeroed,'unavailable_NaNs_preserved':True,'full':asdict(a),'one_way':asdict(b),'macro_f1_delta':b.f1_macro-a.f1_macro,'accuracy_delta':b.accuracy-a.accuracy,'prediction_change_rate':float(np.mean(base!=pred))};save('one-way.json',one);del uni
z=r.X_test[:10000];labels,counts=np.unique(r.y_test[:10000],return_counts=True);rob={'scope':'first 10000 TEST rows in adapter order; limited prefix, not representative full-test robustness','support':dict(zip(labels,counts)),'seed':42,'NaNs_preserved':True,'experiments':{}}
functions={'timing_jitter':lambda x:timing_jitter(x,.1,42),'packet_size_noise':lambda x:packet_size_noise(x,.1,42),'duration_perturbation':lambda x:flow_duration_perturbation(x,.2,42),'directional_imbalance':directional_imbalance,'metadata_dropout':lambda x:missing_metadata(x,.2,42)}
for name,fn in functions.items():
 v=fn(z);v[np.isnan(z)]=np.nan;rob['experiments'][name]=RobustnessEvaluator().evaluate_perturbation(z,v,model,pp,name).to_dict();log('Robustness '+name+' saved')
save('robustness.json',rob)
features=UNSWAdapter.get_feature_matrix();save('unsw-compatibility.json',{'conclusion':'EXTERNAL-DATASET DIRECT EVALUATION NOT METHODOLOGICALLY VALID','counts':{k:sum(f.availability.name==k for f in features) for k in ('DIRECT','DERIVED','PROXY','MISSING','STRUCTURAL_ZERO')},'features':[{'name':f.sentinel_name,'availability':f.availability.name,'source_columns':f.source_columns,'unit_conversion':f.unit_conversion,'justification':f.justification} for f in features],'direct_transfer_evaluated':False})
log('Supplementary complete')
