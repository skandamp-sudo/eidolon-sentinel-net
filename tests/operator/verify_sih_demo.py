"""Opt-in integration: requires free 8010/5174 and installed Playwright/Chrome.
No dependencies are installed. Only owned launcher processes receive signals.
"""
from pathlib import Path
import subprocess,signal,time,os,socket,json,sys,tempfile,stat,argparse
root=Path(__file__).resolve().parents[2];os.chdir(root)
parser=argparse.ArgumentParser()
parser.add_argument('--live-interface')
args=parser.parse_args()
mode_args=['--interface',args.live_interface] if args.live_interface else []
artifacts=Path(tempfile.mkdtemp(prefix='sih-operator-verification-'))
sys.path.insert(0,str(root))
from scripts.run_sih_demo import free_port
credential_path=root/'.sentinel-demo.local'
original=credential_path.read_bytes() if credential_path.exists() else None
results=[]
for iteration in (1,2):
 log=artifacts/f'launch-{iteration}.txt'
 before_workspaces=set(Path(tempfile.gettempdir()).glob('sentinel-one-command-*'))
 with log.open('w') as output:
  child=subprocess.Popen(['./run-sih-demo.sh','--no-browser',*mode_args],stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
  try:
   deadline=time.monotonic()+120
   while '[PASS] Frontend reachable' not in log.read_text():
    assert child.poll() is None, 'Launcher failed'
    assert time.monotonic()<deadline,'Readiness timeout'
    time.sleep(.2)
   if original is None: original=credential_path.read_bytes()
   assert stat.S_IMODE(credential_path.stat().st_mode)==0o600
   run=subprocess.run(['node','tests/operator/verify_sih_browser.cjs',*([args.live_interface] if args.live_interface else [])],capture_output=True,text=True,timeout=110 if args.live_interface else 45)
   assert run.returncode==0,run.stdout+run.stderr
   report=json.loads(run.stdout.strip());report['iteration']=iteration
   deadline=time.monotonic()+5
   while ('\nLIVE PASSIVE READY' if args.live_interface else '\nDEMO READY') not in log.read_text():
    assert time.monotonic()<deadline,'Browser confirmation timeout'
    time.sleep(.2)
   assert (root/'.sentinel-demo.local').read_bytes()==original
   report['stable_credential']=True
  finally:
   child.send_signal(signal.SIGINT)
   child.wait(timeout=80)
  assert child.returncode==0
  assert set(Path(tempfile.gettempdir()).glob('sentinel-one-command-*')) <= before_workspaces
  for port in (8010,5174):free_port(port)
  key=original.decode().strip().split('=',1)[1]
  assert key not in log.read_text()
  report['ctrl_c_ports_released']=True;report['no_key_in_stdout_stderr']=True
  results.append(report)
  print(json.dumps(report),flush=True)
for port in (8010,5174):
 with socket.socket() as listener:
  listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  listener.bind(('127.0.0.1',port));listener.listen()
  run=subprocess.run(['./run-sih-demo.sh','--no-browser',*mode_args],capture_output=True,text=True,timeout=10)
  assert run.returncode==1 and f'Port {port} unavailable' in run.stdout
  assert listener.fileno()!=-1
  assert original.decode().strip().split('=',1)[1] not in run.stdout+run.stderr
  print(f'PASS occupied {port}: fail closed; existing listener preserved',flush=True)
(artifacts/'results.json').write_text(json.dumps(results,indent=2)+'\n')

print('Verification artifacts:',artifacts)
