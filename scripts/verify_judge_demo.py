"""Real offline replay/REST/WS/export validation. Never seeds stored records."""
import argparse
import asyncio
from collections import Counter
import functools
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
from unittest.mock import patch
from fastapi.testclient import TestClient
from scripts.judge_demo import ROOT, PCAP, verify_assets
from sentinel_net.api.main import create_app
from sentinel_net.config import get_config
from sentinel_net.demo_replay import DemoReplayConfig, run_replay
from sentinel_net.sensor.lifecycle import SensorLifecycle


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def stable(outputs, events):
    # Preserve membership by mapping UUIDs to unique endpoint tuples, never erase it.
    ids={}
    for e in events:
        label=canonical([e[k] for k in ('src_ip','src_port','dst_ip','dst_port','protocol')])
        assert label not in ids.values(), 'Ambiguous flow identity'
        ids[e['id']]=label
        ids[e['flow_id']]='flow:'+label
    replay_ids={e.get('replay_file_identifier') for e in events if e.get('replay_file_identifier')}
    assert len(replay_ids) <= 1
    ids.update({x:'verified-judge-pcap-replay' for x in replay_ids})
    def walk(v):
        if isinstance(v,list):return [walk(x) for x in v]
        if not isinstance(v,dict):return ids.get(v,v) if isinstance(v,str) else v
        result={}
        for k,x in v.items():
            if k in ('investigation_id','correlation_id','explanation_id'):
                result[k]='derived-from-random-anchor-and-members'
            elif k in ('first_seen','last_seen','created_at','generation_timestamp') or (k=='timestamp' and ('event_schema_version' in v or v.get('clock') in ('processing_time','event_timestamp_unspecified'))):
                result[k]='runtime-clock'
            else:result[k]=walk(x)
        return result
    return sorted((walk(x) for x in outputs),key=canonical)


@patch('socket.socket.connect', side_effect=AssertionError('Network connect forbidden in offline validation'))
@patch('socket.getaddrinfo', side_effect=AssertionError('DNS resolution forbidden in offline validation'))
def run_once(registry, interrupted, *_network_guards):
    workspace=Path(tempfile.mkdtemp(prefix='sentinel-judge-verification-'))
    key=secrets.token_urlsafe(32)
    # Isolate environment config as well as SQLite state.
    for name in list(os.environ):
        if name.startswith('SENTINEL_'):del os.environ[name]
    os.environ.update(SENTINEL_DATABASE_PATH=str(workspace/'events.db'),SENTINEL_API_KEY=key)
    get_config.cache_clear()
    model=verify_assets(registry)
    app=create_app()
    headers={'X-API-Key':key}
    started=time.monotonic()
    with TestClient(app) as client, client.websocket_connect('/api/v1/ws/events') as ws:
        app.state.model_identity=model.deployment_identity
        app.state.deployment_detection=model
        lifecycle=SensorLifecycle()
        app.state.sensor_lifecycle=lifecycle
        ws.send_json({'type':'auth','api_key':key});assert ws.receive_json()=={'type':'auth_ok'}
        async def replay():
            task=asyncio.create_task(run_replay(DemoReplayConfig(PCAP,'runtime/1.0.0',model_registry=registry,realtime=interrupted),app.state.db,app.state.event_bus,lifecycle,app.state.sensor_metrics,detection=model))
            if interrupted:
                deadline=time.monotonic()+10
                while app.state.sensor_metrics.packets_observed < 5:
                    assert time.monotonic()<deadline
                    await asyncio.sleep(.01)
                lifecycle.request_shutdown()
            return await task
        result=client.portal.call(replay)
        events=client.portal.call(functools.partial(app.state.db.get_events,limit=1000))
        assert len(events)==result['events_persisted']==result['total_detections']
        delivered=[]
        while len(delivered)<len(events):
            msg=ws.receive_json()
            if msg['type']=='event':delivered.append(msg['data'])
        assert sorted(delivered,key=lambda x:x['id'])==sorted(events,key=lambda x:x['id'])
        exports=[]
        for e in events:
            endpoint='/api/v1/events/'+e['id']
            assert client.get(endpoint,headers=headers).json()==e
            response=client.get(endpoint+'/export',headers=headers)
            assert response.status_code==200
            assert hashlib.sha256(response.content).hexdigest()==response.headers['x-content-sha256']
            assert response.content==client.get(endpoint+'/investigation',headers=headers).content
            exports.append(response.json())
        assert client.get('/api/v1/events',headers={'X-API-Key':'incorrect'}).status_code==401
        assert client.portal.call(app.state.db.health_check)
        stats=app.state.sensor_metrics.snapshot()
        assert not stats['processing_errors'] and not stats['source_errors']
        assert result['parsed_packets']==result['total_packets']
        assert lifecycle.state.value==('stopped' if interrupted else 'replay_complete')
        report={'summary':{k:v for k,v in result.items() if k!='pcap_file'},'lifecycle':lifecycle.state.value,'rest_ws_export_verified':len(events),'wall_seconds':round(time.monotonic()-started,3)}
        report['classifications']=dict(Counter(e['threat_type'] for e in events))
        report['evidence']={family:dict(Counter(s['signal_type'] for e in events for s in e[family+'_evidence'])) for family in ('behavioral','dns','tls','quic')}
        report['stable_event_sha256']=hashlib.sha256(canonical(stable(events,events)).encode()).hexdigest()
        report['stable_export_sha256']=hashlib.sha256(canonical(stable(exports,events)).encode()).hexdigest()
        report['correlation_membership_counts']=dict(Counter(len(v['events']) for v in exports))
        report['timeline_item_counts']=dict(Counter(len(v['timeline']) for v in exports))
        report['anomaly_scores']=sorted(set(e['anomaly_score'] for e in events))
        report['classifier_scores']=sorted(set(e['classification_score'] for e in events))
        return report, stable(events,events),stable(exports,events)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--registry',required=True,type=Path);args=parser.parse_args()
    reports=[]; first=None
    for i in range(3):
        report,events,exports=run_once(args.registry,False)
        if first is None:first=(events,exports)
        if (events,exports)!=first:
            Path('/tmp/judge-first.json').write_text(canonical(first))
            Path('/tmp/judge-second.json').write_text(canonical((events,exports)))
        assert (events,exports)==first, 'Stable replay output changed'
        reports.append(report)
        print(f'PASS fresh replay {i+1}: {report["summary"]["events_persisted"]} events',flush=True)
    interrupted,_,_=run_once(args.registry,True)
    assert interrupted['summary']['completion']=='cancelled' and interrupted['summary']['total_packets']<191
    recovery,events,exports=run_once(args.registry,False)
    assert (events,exports)==first
    output={'three_fresh_runs':reports,'interruption':interrupted,'clean_recovery':recovery,'offline_guard':'Python socket.connect and getaddrinfo fail on use during all five real replay/API/export runs; ASGI transport remains in-process.', 'normalization':'Event/flow UUIDs map to unique ordered endpoint/protocol tuples. Single replay-session UUID maps to verified PCAP identity. Explanation/investigation/correlation IDs and runtime event/creation/explanation/correlation timestamps are normalized. Capture clocks, scores, evidence and correlation membership remain exact.'}
    (ROOT/'docs/judge-demo-validation/replay.json').write_text(json.dumps(output,indent=2)+'\n')
    selected=[e for e in first[0] if e['dns_status']=='PARSED' or e['tls_status']=='COMPLETE' or e['quic_status']=='COMPLETE' or any(s['signal_type'] in ('PORT_FANOUT','C2_PERIODICITY_EVIDENCE') for s in e['behavioral_evidence'])]
    (ROOT/'docs/judge-demo-validation/selected-events.json').write_text(json.dumps(selected,indent=2)+'\n')
    print('PASS interruption drain, REST availability and clean recovery')

if __name__=='__main__':main()
