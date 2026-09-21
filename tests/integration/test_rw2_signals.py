"""Real OS signals with the CLI handler and service, without capture privileges."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest
from tests.unit.test_rw1_correctness import detector
from tests.unit.test_sensor_runtime_model import save_pipeline


@pytest.mark.parametrize('sig', [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize('busy', [False, True])
def test_cli_signal_drains_idle_and_busy_service(tmp_path, detector, sig, busy):
    model = save_pipeline(tmp_path/'registry', detector)
    ready, result = tmp_path/'ready', tmp_path/'result.json'
    script = r'''
import asyncio,json,signal,sys,time
from pathlib import Path
import uvicorn
from sentinel_net.cli import SensorServer
from sentinel_net.config import SentinelConfig
from sentinel_net.sensor.service import SensorService
from tests.unit.test_sensor_service import FakeCapture
from tests.unit.test_rw1_correctness import parsed
async def main():
    model,db,ready,result,busy=sys.argv[1:]
    service=SensorService(SentinelConfig(database_path=db,capture_interface='test0',sensor_model='runtime/1.0.0',model_registry=Path(model).parent.parent),
        interface_validator=lambda _:None,capture_factory=FakeCapture)
    server=SensorServer(uvicorn.Config('sentinel_net.api.main:app'),service)
    signal.signal(signal.SIGINT,server.handle_exit)
    signal.signal(signal.SIGTERM,server.handle_exit)
    await service.start()
    if busy=='yes':
        for i in range(50): service.capture.emit(parsed(time.time(),sport=1000+i))
    Path(ready).touch()
    while not server.should_exit: await asyncio.sleep(.01)
    await service.quiesce()
    count=await service.db.get_event_count()
    await service.stop()
    Path(result).write_text(json.dumps({'state':service.lifecycle.state.value,'count':count,
        'processed':service.metrics.packets_processed,'active':service.metrics.flows_active,
        'worker_alive':service.pipeline.alive,'connected':service.db.is_connected}))
asyncio.run(main())
'''
    process = subprocess.Popen([sys.executable, '-c', script, str(model), str(tmp_path/'signal.db'),
                               str(ready), str(result), 'yes' if busy else 'no'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic()+20
        while not ready.exists() and process.poll() is None and time.monotonic()<deadline:
            time.sleep(.02)
        assert ready.exists(), process.communicate(timeout=1)[1]
        process.send_signal(sig)
        _, err = process.communicate(timeout=15)
        assert process.returncode == 0, err
        report = json.loads(result.read_text())
        assert report == {'state':'stopped','count':50 if busy else 0,
                          'processed':50 if busy else 0,'active':0,'worker_alive':False,'connected':False}
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
