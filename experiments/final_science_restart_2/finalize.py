"""Assemble measured artifacts only after primary/supplementary runs and gates."""
import csv,hashlib,json,platform,subprocess,shutil
from importlib.metadata import version
from pathlib import Path
from datetime import datetime,timezone
O=Path('experiments/final_science_restart_2');D=Path('docs');V=D/'final-science-restart-2-audit'
def read(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,x):Path(p).write_text(json.dumps(x,indent=2,allow_nan=False)+'\n')
b=read(D/'sci-corr-2-scientific-integrity.json');assert all(sha(p)==h for p,h in b['sha256'].items())
for n in ['supervised.json','anomaly.json','novelty.json','one-way.json','robustness.json','unsw-compatibility.json','candidate-parity.json','training.json']:assert (O/n).exists(),n
assert '906 passed' in (V/'backend.txt').read_text();assert '90 passed' in (V/'frontend.txt').read_text()
assert all(v == 0 for v in read(V/'gate-exit-codes.json').values())
assert read(O/'candidate-parity.json')['exact'] is True
archive=V/'previous-stop';archive.mkdir(exist_ok=True);archive_hashes={}
for p in D.glob('final-science-*'):
 if p.is_file():
  target=archive/p.name
  if not target.exists():shutil.copyfile(p,target)
  archive_hashes[p.name]=sha(target)
save(archive/'archive-sha256.json',archive_hashes)
pre=read(V/'preflight.json');ident=read(V/'identity.json');config=read(O/'locked-config.json');training=read(O/'training.json');metrics=read(O/'supervised.json');anomaly=read(O/'anomaly.json');novelty=read(O/'novelty.json');one=read(O/'one-way.json');rob=read(O/'robustness.json');unsw=read(O/'unsw-compatibility.json');ci=read(O/'candidate-identity.json')
resolved={'estimators':training,'XGBoost_native':read(O/'XGBoost-native-config.json'),'locked_recipe_sha256':sha(O/'locked-config.json'),'NaN_parameter_encoding':'XGBoost missing=null in Python get_params export represents numpy.nan; native configuration records its own resolved representation','scope':'Actual parameters; training durations/n_iter are recorded measurements, not tuned settings'}
save(O/'resolved-training-configuration.json',resolved)
components={str(p.relative_to(O)):sha(p) for p in O.glob('*.joblib')}
components.update({str(p.relative_to(O)):sha(p) for p in (O/'candidate').iterdir() if p.is_file()})
scientific_manifest={'name':'final-science-fixed-split-seed42','version':'2026.09.23-seed42','status':'CANDIDATE','approved':False,'published':False,'source_revision':config['source_revision'],'scientific_baseline':b['baseline_id'],'dataset':config['dataset'],'split_manifest_sha256':config['split_manifest_sha256'],'training_configuration_sha256':sha(O/'resolved-training-configuration.json'),'locked_recipe_sha256':sha(O/'locked-config.json'),'adapter_file_order':read(O/'adapter-file-order.json'),'preprocessing_sha256':{'tree':sha(O/'tree-preprocessor.joblib'),'linear':sha(O/'linear-preprocessor.joblib')},'schema_version':'2.0.0','schema_file_sha256':b['sha256']['src/sentinel_net/features/schema.py'],'component_sha256':components,'deployment_component_manifest_sha256':ci['manifest_sha256'],'primary_harness_sha256':sha(O/'run.py'),'resume_harness_sha256':sha(O/'resume.py'),'supplementary_protocol_sha256':sha(O/'supplementary-protocol.json'),'supplementary_harness_sha256':sha(O/'supplementary.py')}
manifest_path=O/'scientific-candidate-manifest.json'
if manifest_path.exists():assert read(manifest_path)==scientific_manifest
else:
 with manifest_path.open('x') as f:json.dump(scientific_manifest,f,indent=2);f.write('\n')
for relative in components:
 (O/relative).chmod(0o444)
manifest_path.chmod(0o444)
candidate={'scientific_manifest_path':str(manifest_path),'scientific_manifest_sha256':sha(manifest_path),**scientific_manifest}
classes=sorted(set().union(*(set(x) for x in pre['classes'].values())))
for name,r in metrics.items():
 r['all_project_classes']={k:r['per_class'].get(k,{'support':0,'precision':None,'recall':None,'f1-score':None,'fpr':None,'fnr':None,'status':'No actual or predicted support in this test report'}) for k in classes}
 r['macro_policy']='Union of true/predicted classes, matching ClassificationReport default; absent class rows shown separately, not added to aggregate denominator.'
 r['no_actual_support_warning']='Recall/FNR values with support zero are conventions, not measured class performance.'
save(D/'final-science-metrics.json',{'phase':'FINAL-SCIENCE-RESTART-2','claim_category':'MEASURED','run_policy':'SINGLE-SEED REPRODUCIBILITY RUN','candidate':candidate,'partition_counts':pre['split']['row_counts'],'class_distributions':pre['classes'],'preprocessing':pre['preprocessing'],'supervised':metrics,'anomaly':anomaly,'threshold_protocol':read(O/'threshold-lock.json'),'candidate_parity':read(O/'candidate-parity.json'),'confidence_semantics':'MODEL CONFIDENCE SCORE; no formal calibration established','evaluation_scope':'Established raw classifier.predict metrics after preprocessing; runtime unknown-label confidence gating and severity/event enrichment are not classifier accuracy metrics. Candidate reload parity covers the evaluated preprocessing/classifier/anomaly core.'})
save(D/'final-science-environment.json',{'phase':'FINAL-SCIENCE-RESTART-2','completed_at':datetime.now(timezone.utc).isoformat(),'python':platform.python_version(),'platform':platform.platform(),'dependencies':{**config['dependencies'], **{name:version(name) for name in ['pandas','pyarrow','joblib']}},'source':ident,'preflight':pre,'adapter_file_order':read(O/'adapter-file-order.json'),'actual_training_configuration':resolved,'resume_provenance':read(O/'resume-provenance.json'),'protected_files_match':23,'protected_sha256':b['sha256'],'candidate':candidate,'scope':'Dataset already flow-aggregated; this evaluates the adapter representation, not current packet segmentation accuracy'})
save(D/'final-science-split-manifest-used.json',{'file_sha256':config['split_manifest_sha256'],'manifest':read('experiments/manifests/final-science-partition.json'),'executed_provenance':read(O/'split-used.json'),'generated_split_used':False})
save(D/'final-science-novelty.json',{'claim_category':'LIMITED / EXPERIMENTAL','fixed_partition_only':True,'protocol':read(O/'supplementary-protocol.json')['novelty'],'results':novelty})
save(D/'final-science-robustness.json',{'claim_category':'SIMULATED','unidirectional':one,'perturbations':rob,'limitations':'Available feature perturbations preserve original NaNs; one-way zeroing is not physical flow reconstruction; prefix robustness is limited and not representative population accuracy.'})
with (D/'final-science-confusion-matrix.csv').open('w') as f:
 w=csv.writer(f,lineterminator="\n");w.writerow(['model','true_class','predicted_class','count'])
 for name,r in metrics.items():
  for i,a in enumerate(r['class_names']):
   for j,c in enumerate(r['class_names']):w.writerow([name,a,c,r['confusion_matrix'][i][j]])
with (D/'final-science-class-metrics.csv').open('w') as f:
 w=csv.writer(f,lineterminator="\n");w.writerow(['model','class','precision','recall','f1','support','one_vs_rest_fpr','one_vs_rest_fnr','interpretation'])
 for name,r in metrics.items():
  for k,v in r['all_project_classes'].items():w.writerow([name,k,v['precision'],v['recall'],v['f1-score'],v['support'],v['fpr'],v['fnr'],'NO ACTUAL SUPPORT: recall/FNR not meaningful' if not v['support'] else 'MEASURED'])
historical=read('experiments/metrics/model_performance.json');comparison=[]
for name,r in metrics.items():
 for key in ['accuracy','precision_macro','recall_macro','f1_macro','precision_weighted','recall_weighted','f1_weighted']:
  old=historical[name][key];comparison.append({'model':name,'metric':key,'historical':old,'current':r[key],'delta':r[key]-old,'comparable':'NOT DIRECTLY COMPARABLE','reason':'Same recorded scenario assignment and recipe; historical candidate/data/environment identity not equivalently bound. Current explicit partition and corrected reporting baseline are fully identified; no improvement/regression inference.'})
hnov=read('experiments/phase8/metrics/novelty_ranking.json')
for family in ('c2','ddos'):
 if family in hnov:
  comparison.append({'model':'IsolationForest '+family,'metric':'ROC-AUC','historical':hnov[family]['roc_auc'],'current':novelty[family]['ranking']['roc_auc'],'delta':novelty[family]['ranking']['roc_auc']-hnov[family]['roc_auc'],'comparable':'NO','reason':'Different evaluation cohort/protocol; current experiment preserves mandatory primary scenario partition.'})
save(D/'final-science-historical-comparison.json',{'comparisons':comparison,'historical_reports_modified':False})
x=metrics['XGBoost'];fp=x['benign_to_malicious'];threshold=read(O/'threshold-lock.json');primary=anomaly['validation_f1']
report=['# FINAL-SCIENCE-RESTART-2 scientific report','','**SINGLE-SEED REPRODUCIBILITY RUN**. All metrics below identify a fixed explicit CICIDS2017 scenario partition and the exact local candidate. No automatic approval/publication occurred. F3/F4/F5 contextual evidence is excluded from ML inputs and metrics.','','## Measured primary results','','| Model | Test rows | Accuracy | Macro precision | Macro recall | Macro F1 | Weighted precision | Weighted recall | Weighted F1 |','|---|---:|---:|---:|---:|---:|---:|---:|---:|']
for n,r in metrics.items():report.append('| '+n+' | '+str(r['test_rows'])+' | '+' | '.join(f"{r[k]:.6f}" for k in ['accuracy','precision_macro','recall_macro','f1_macro','precision_weighted','recall_weighted','f1_weighted'])+' |')
report += ['','Macro averages use the union of true/predicted labels under the existing report API, which can include predicted classes with zero true support. Full zero-support rows are retained in the CSV; their recall convention is not an observed performance estimate.','','## XGBoost per-class results','','| Class | Support | Precision | Recall | F1 | One-vs-rest FPR | One-vs-rest FNR |','|---|---:|---:|---:|---:|---:|---:|']
for k,v in x['all_project_classes'].items():
 vals=[v['precision'],v['recall'],v['f1-score'],v['fpr'],v['fnr']]
 report.append(f"| {k} | {int(v['support'])} | "+' | '.join('Unavailable' if a is None else f'{a:.6f}' for a in vals)+' |')
report += ['', '## Historical comparison', '', '| Model / metric | Historical | Current | Delta | Comparable? | Reason |', '|---|---:|---:|---:|---|---|']
for row in comparison:
 report.append(f"| {row['model']} / {row['metric']} | {row['historical']:.6f} | {row['current']:.6f} | {row['delta']:+.6f} | {row['comparable']} | {'Different fixed-test cohort' if row['comparable']=='NO' else 'Historical identity not equivalently bound'} |")
report += ['', '## Anomaly operating points — exploratory', '', '| Protocol | Threshold | Precision | Recall | F1 | Test FPR |', '|---|---:|---:|---:|---:|---:|']
for name, value in anomaly.items():
 if isinstance(value, dict):
  report.append('| '+name+' | '+' | '.join(f"{value[k]:.6f}" for k in ['threshold','precision_at_threshold','recall_at_threshold','f1_at_threshold','fpr_at_threshold'])+' |')
report += ['', '## Held-out attack-family evaluation — limited', '', '| Family | Train rows excluded | Test attack rows | ROC-AUC | PR-AUC | Validation target FPR | Achieved validation FPR | Test FPR | Test recall |', '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
for family in ('c2','ddos'):
 value=novelty[family]
 for target, point in value['operating_points'].items():
  report.append(f"| {family} | {value['train_family_support_excluded']} | {value['test_family_support']} | {value['ranking']['roc_auc']:.6f} | {value['ranking']['pr_auc']:.6f} | {target} | {point['validation_achieved_fpr']:.6f} | {point['test']['fpr_at_threshold']:.6f} | {point['test']['recall_at_threshold']:.6f} |")
report += ['', '## Perturbation sensitivity — simulated, first 10,000 test rows', '', '| Perturbation | Changed predictions | Prediction-change percentage |', '|---|---:|---:|']
for name, value in rob['experiments'].items():
 report.append(f"| {name} | {value['classification_changed_count']} | {value['classification_changed_pct']:.4f}% |")
report += ['', '## XGBoost confidence and dominant confusions', '', 'MODEL CONFIDENCE SCORE quantiles (min, 25%, 50%, 75%, 95%, max): `'+json.dumps(x['model_confidence_score']['quantiles'])+'`. No calibration established.', '']
for label in ('benign','c2','ddos'):
 i=x['class_names'].index(label)
 errors={name:count for name,count in zip(x['class_names'],x['confusion_matrix'][i]) if name != label and count}
 report.append('- '+label+' misclassifications: `'+json.dumps(errors)+'`.')
report += ['','Zero-support recall/FNR: NOT MEANINGFUL. **NO PRIMARY-TEST RECONNAISSANCE SUPPORT.** Exfiltration has only 36 training examples and zero test support: meaningful exfiltration accuracy is not established.','','## Requested 37-point disposition','',
'1. **Dataset identity — MEASURED.** Eight independently rehashed CICIDS2017 parquet files, 2,313,810 rows. Exact file hashes/schemas, row-level adapter mapping, scenario and label counts are in the environment artifact.',
'2. **Split identity — VERIFIED ENGINEERING PROPERTY.** Manifest SHA-256 `'+config['split_manifest_sha256']+'`. Only explicit_manifest_split was used; exact assignment/identity/coverage/no overlap/counts validated.',
'3. **Partition counts — MEASURED.** TRAIN 1,760,688; VALIDATION 155,820; TEST 397,302.',
'4. **Class distributions — MEASURED.** `'+json.dumps(pre['classes'],sort_keys=True)+'`.',
'5. **Real-data preprocessing — VERIFIED.** 11 all-missing canonical columns retained as NaN before imputation; TRAIN-only fitting yields tree 41 / linear 40 surviving columns. Names, actual width and n_features_out agree. is_icmp is constant. Ordered names and all mappings are recorded.',
'6. **Candidate identity.** Scientific manifest `'+str(manifest_path)+'`, SHA-256 `'+sha(manifest_path)+'`. CANDIDATE, NOT APPROVED, NOT PUBLISHED. It binds all supervised artifacts and anomaly/preprocessor artifacts, with a loader-compatible XGBoost deployment component bundle. Fixed TRAIN-vector loaded-candidate parity passes.',
'7. **Training configuration.** Seed42, fixed partition, established XGBoost100/depth6, RF100, LR lbfgs/max_iter1000, IF100 benign-only. Complete get_params, fitted classes/features, timings and native resolved XGBoost configuration are recorded, not just these shorthand settings. Actual config SHA-256 `'+sha(O/'resolved-training-configuration.json')+'`. Random Forest restarted after an interrupted unsaved fit; saved XGBoost retained unchanged. No successful runs averaged or test-driven tuning.',
'8. **XGBoost aggregate results — MEASURED.** See table; primary supervised architecture, not a claim of calibrated attack probability. Established metrics use raw classifier.predict; runtime confidence-based unknown labels and severity/event enrichment are not included in classifier accuracy.',
'9. **Random Forest aggregate results — MEASURED.** See table; baseline evaluated under the same partition.',
'10. **Logistic Regression aggregate results — MEASURED.** See table; linear feature subset retained. Training iteration/warning evidence is in training.json and resume.log; no retuning after evaluation.',
'11. **XGBoost per-class metrics — MEASURED.** See table and full CSV with support; no zero-recall class hidden.',
'12. **Confusion matrix.** Full matrices for all models are in final-science-confusion-matrix.csv. XGBoost rows: `'+json.dumps({'labels':x['class_names'],'matrix':x['confusion_matrix']})+'`.',
f"13. **BENIGN-TO-MALICIOUS FALSE-POSITIVE RATE — MEASURED.** {fp['predicted_non_benign']} / {fp['support']} = {fp['rate']:.8f}; predicted benign {fp['predicted_benign']}. False positives by class: `{json.dumps(fp['by_predicted_class'])}`.",
'14. **Per-class FPR/FNR.** SCI-CORR-2 one-versus-rest reporting is used unchanged. Operational benign-to-malicious rate is benign FNR, not benign one-versus-rest FPR. Zero-denominator conventions require support qualification.',
'15. **C2 — MEASURED with limitations.** Support 1,437; no C2 in supervised training. Its supervised metrics/confusions remain visible above. Anomaly family ranking/operating points are in novelty JSON; F3 periodicity is entirely separate.',
'16. **DDoS — MEASURED.** Support 128,014; supervised metrics above. Separate held-out-family anomaly result excludes all ddos rows from supplementary preprocessing and trains IF on benign only. No F3 rate/entropy contribution.',
'17. **Reconnaissance.** NO PRIMARY-TEST RECONNAISSANCE SUPPORT. No scenario moved to manufacture support; not evaluated in supplementary fixed-test novelty.',
'18. **Exfiltration.** 36 TRAIN / 0 TEST support. No meaningful accuracy claim; directional asymmetry evidence is unrelated to supervised support.',
f"19. **Isolation Forest ranking — MEASURED.** Primary binary ROC-AUC {primary['roc_auc']:.6f}; trapezoidal PR-AUC {primary['pr_auc']:.6f}; average precision {anomaly['average_precision']:.6f}. PR area and average precision are distinct definitions.",
'20. **Threshold protocol — LIMITED / EXPERIMENTAL.** Validation benign153,677/other2,143 is narrow. Existing validation-only F1 grid and fixed 1%/5% validation-benign quantiles were locked before test inference. All threshold-dependent results are EXPLORATORY; achieved test FPR may differ from nominal validation target. No test threshold selection. Thresholds and precision/recall/F1/FPR are in metrics JSON.',
'21. **Held-out attack-family evaluation — LIMITED / EXPERIMENTAL.** C2 and DDoS IF ranking only, preserving original partitions. C2 train exclusion count0 because already absent; DDoS excluded193,756 from supplementary preprocessing. Other families have no fixed TEST support and are NOT EVALUATED—INSUFFICIENT SUPPORT. No zero-day accuracy claim.',
f"22. **SIMULATED UNIDIRECTIONAL TELEMETRY LOSS.** Full TEST macro-F1 {one['full']['f1_macro']:.6f} → {one['one_way']['f1_macro']:.6f}, absolute signed delta {one['macro_f1_delta']:+.6f}. Affected available fields `{one['features_zeroed_where_available']}` zeroed, original NaNs preserved. Other aggregate fields are not reconstructed, so this is controlled ablation, not physical diode or natural one-way flow validation.",
'23. **Robustness — SIMULATED/LIMITED.** Five established perturbations at their stated seed/magnitudes on the predeclared first10,000 TEST rows only, support `'+json.dumps(rob['support'])+'`. Original NaNs restored after perturbation to preserve missingness; this does not alter fitted preprocessing. Results are prefix-specific sensitivity, not population robustness or causal feature importance. Jitter may produce nonphysical IATs and independent feature edits need not preserve cross-feature consistency; these are vector perturbations, not reconstructed traffic.',
'24. **UNSW compatibility.** EXTERNAL-DATASET DIRECT EVALUATION NOT METHODOLOGICALLY VALID. Adapter categories: `'+json.dumps(unsw['counts'])+'`. Missing canonical fields and rate/IAT proxies have non-equivalent source semantics; no zero-fill or direct-transfer metric. Full mapping in supplementary artifact.',
'25. **Historical comparison.** Current and historical values/deltas are recorded only after measurement. Candidate/data/environment identities are not equivalently verifiable for historical runs, and Phase8 novelty cohorts differ: NOT DIRECTLY COMPARABLE. No improvement/regression claim.',
'26. **F3/F4/F5 — VERIFIED ENGINEERING PROPERTY.** Deterministic positive, legitimate, malformed-input and bounded-state fixtures; F3 7/7, F4 8/8, F5 12/12 parity pass in post-evaluation regression. No population-level precision/recall for those heuristics.',
'27. **What can be claimed.** The measured fixed-split results, qualified anomaly ranking/operating points, simulated telemetry-removal outcomes and separate tested engineering properties. See final-science-claims.md.',
'28. **What cannot be claimed.** Perfect detection, universal zero-day detection, calibrated attack probability, production readiness/Gbps guarantee, physical diode/BPF verification, population heuristic accuracy, JA4, encrypted DNS visibility or TLS/QUIC payload decryption.',
'29. **Candidate recommendation: SUITABLE FOR OPERATOR REVIEW as a scientific candidate, not deployment approval.** Review must consider absent C2 training, zero-support classes, measured errors, limited anomaly validation and existing operational constraints. Nothing automatically approved or published.',
'30. **Backend total.** 906 passed, 43 warnings in 107.33 seconds. Full source unchanged; no new runtime tests added.',
'31. **Frontend total.** 90 passed across 6 files.',
'32. **TypeScript/build.** Both PASS.',
'33. **SCI-CORR-2 integrity.** 23/23 byte-identical throughout checks; exact hashes in environment. No scientific or product source edited.',
'34. **Parity and lifecycle.** Core, F3, F4, F5, frozen bundle/inference, auth/event contract, model loader, replay, sensor lifecycle and SCI-CORR1/2/3 regression tests pass in the full suite.',
'35. **Remaining limitations.** Single seed, flow-table adapter representation, no statistical significance/uncertainty claim; corrected runtime segmentation is not directly validated by CICFlowMeter tables. Primary absent-class support, narrow validation, simulated one-way, prefix robustness and protocol coverage remain explicit. Historical scientific stop evidence preserved.',
'36. **Git recommendation.** Suggested message: `docs(science): record fixed-split final revalidation and candidate provenance`. Review/commit harnesses, configuration, manifests and reports as a scientific evaluation record. Store binary candidates in trusted artifact storage; do not automatically add large binaries to Git or publish a deployment. No commit/push performed.',
'37. **Next phase.** Scientific results and candidate are available for operator review and separately authorized final SIH hardening. This task stops; no F6, presentation or product work begun.','','GO FOR FINAL SIH HARDENING']
(D/'final-science-report.md').write_text('\n'.join(report)+'\n')
claims=['# Current scientific claims','','## WHAT WE CAN CLAIM','',f"- **MEASURED:** On the fixed 397,302-row CICIDS2017 test partition, XGBoost accuracy is {x['accuracy']:.6f} and macro-F1 {x['f1_macro']:.6f}; single seed, explicit macro label policy and candidate identity.",f"- **MEASURED:** Benign-to-malicious false-positive rate is {fp['rate']:.8f} ({fp['predicted_non_benign']}/{fp['support']}).",f"- **MEASURED:** Primary Isolation Forest ROC-AUC is {primary['roc_auc']:.6f}, trapezoidal PR-AUC {primary['pr_auc']:.6f}; anomaly score is not probability.",'- **LIMITED / EXPERIMENTAL:** Held-out-family anomaly ranking and validation-derived operating points apply only to the stated fixed cohorts; narrow validation does not establish a global operating threshold.','- **SIMULATED:** One-way telemetry removal and prefix perturbation experiments measure controlled sensitivity, not hardware performance or adversarial robustness.','- **VERIFIED ENGINEERING PROPERTY:** Protected-source integrity, frozen candidate reload parity and full engineering regression pass; F3/F4/F5 fixture/parity coverage is not population accuracy.','','## WHAT WE CANNOT CLAIM','','- **NOT VERIFIED:** Universal zero-day detection, perfect detection, production readiness, arbitrary Gbps, physical data diode, native real BPF capture.','- **NOT VERIFIED:** Meaningful primary-test reconnaissance/exfiltration recall with zero support; C2 supervised learning with no C2 training examples.','- **NOT VERIFIED:** Calibrated attack probabilities or population-level precision/recall for F3/F4/F5 contextual heuristics.','- **NOT IMPLEMENTED / UNAVAILABLE:** JA4, encrypted DNS content, TLS/QUIC payload decryption.','- **NOT VERIFIED:** Cross-dataset transfer accuracy to incompatible UNSW representation.','','Candidate is suitable for operator scientific review only. No approval/publication or follow-on phase performed.']
(D/'final-science-claims.md').write_text('\n'.join(claims)+'\n')
print('Final artifacts assembled',sha(manifest_path))
