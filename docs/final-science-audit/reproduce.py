"""Read-only reproducer; no classifier training, source edits or report overwrite."""
import json, os, subprocess, sys
import numpy as np
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.features.schema import FEATURE_SCHEMA
x=np.tile(np.arange(8,dtype=float)[:,None],(1,52))
x[:,15]=np.nan
x[:,19]=7
p=FeaturePreprocessor()
z=p.fit_transform(x)
result={'preprocessing':{'rows':8,'input_columns':52,'dropped':FEATURE_SCHEMA[15],'actual_constant':FEATURE_SCHEMA[19],'reported_constants':p.constant_features,'reported_width':p.n_features_out,'actual_width':z.shape[1],'actual_names_width':len(p.output_feature_names)}}
code='''import json,numpy as np
from sentinel_net.detection.dataset import DatasetBuilder
s=['Benign-Monday','Botnet-Friday','Bruteforce-Tuesday','DDoS-Friday','DoS-Wednesday','Infiltration-Thursday','Portscan-Friday','WebAttacks-Thursday']
r=DatasetBuilder().scenario_aware_split(np.zeros((8,52)),np.array(['benign']*8),s,random_state=42)
print(json.dumps(r.provenance))'''
result['split_by_pythonhashseed']={seed:json.loads(subprocess.check_output([sys.executable,'-c',code],env={**os.environ,'PYTHONHASHSEED':seed},text=True)) for seed in ('0','1','2')}
print(json.dumps(result,indent=2))
