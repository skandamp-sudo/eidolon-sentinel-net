"""Sensor state machine and lifecycle management."""
from __future__ import annotations
import enum
import logging
import signal
import threading

logger = logging.getLogger(__name__)


class SensorState(enum.Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    FAILED = "failed"
    REPLAYING = "replaying"
    REPLAY_COMPLETE = "replay_complete"
    STOPPING = "stopping"
    ERROR = "error"


_VALID_TRANSITIONS = {
    SensorState.STOPPED: {SensorState.STARTING},
    SensorState.STARTING: {SensorState.RUNNING, SensorState.REPLAYING, SensorState.ERROR, SensorState.FAILED, SensorState.STOPPING},
    SensorState.RUNNING: {SensorState.STOPPING, SensorState.ERROR, SensorState.DEGRADED, SensorState.FAILED},
    SensorState.DEGRADED: {SensorState.STOPPING, SensorState.FAILED},
    SensorState.FAILED: {SensorState.STOPPING},
    SensorState.REPLAYING: {SensorState.REPLAY_COMPLETE, SensorState.STOPPING, SensorState.ERROR},
    SensorState.REPLAY_COMPLETE: {SensorState.STOPPED, SensorState.STARTING},
    SensorState.STOPPING: {SensorState.STOPPED, SensorState.ERROR, SensorState.FAILED},
    SensorState.ERROR: {SensorState.STOPPED, SensorState.STARTING},
}


class SensorLifecycle:
    """Manages the sensor state machine and signal handling."""
    
    def __init__(self):
        self._state = SensorState.STOPPED
        self._lock = threading.Lock()
        self._error_message: str = ""
        self._shutdown_event = threading.Event()
    
    @property
    def state(self) -> SensorState:
        """Current sensor state."""
        with self._lock:
            return self._state
            
    @property
    def error_message(self) -> str:
        """Error message if state is ERROR."""
        with self._lock:
            return self._error_message
    
    def transition(self, new_state: SensorState, error: str = "") -> None:
        """Transition to a new state."""
        with self._lock:
            if new_state not in _VALID_TRANSITIONS.get(self._state, set()):
                raise ValueError(f"Invalid transition from {self._state} to {new_state}")
                
            self._state = new_state
            if new_state in (SensorState.ERROR, SensorState.FAILED):
                self._error_message = error
                
            logger.info(f"Sensor state transitioned to {new_state.value}")
    
    def request_shutdown(self) -> None:
        """Request a graceful shutdown."""
        self._shutdown_event.set()
        logger.info("Shutdown requested")
    
    @property
    def shutdown_requested(self) -> bool:
        """Whether a shutdown has been requested."""
        return self._shutdown_event.is_set()
    
    def install_signal_handlers(self) -> None:
        """Install SIGINT and SIGTERM handlers to request shutdown."""
        def handler(signum, frame):
            logger.info(f"Received signal {signum}, requesting shutdown")
            self.request_shutdown()
            
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
