"""Central operational policy. Thresholds are not trained or probabilistic."""

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class IntelligenceConfig(BaseModel):
    enabled: bool = True
    window_sec: int = Field(default=60, ge=5, le=3600)
    bucket_sec: int = Field(default=1, ge=1, le=60)
    max_keys: int = Field(default=1024, ge=3, le=10000)
    max_members: int = Field(default=64, ge=2, le=1024)
    max_sessions: int = Field(default=32, ge=6, le=256)
    min_sessions: int = Field(default=6, ge=6, le=256)
    syn_rate: float = Field(default=1000, gt=0, allow_inf_nan=False)
    udp_rate: float = Field(default=1000, gt=0, allow_inf_nan=False)
    udp_flow_rate: float = Field(default=100, gt=0, allow_inf_nan=False)
    flow_rate: float = Field(default=100, gt=0, allow_inf_nan=False)
    packet_rate: float = Field(default=2000, gt=0, allow_inf_nan=False)
    unique_sources: int = Field(default=32, ge=2)
    entropy_bits: float = Field(default=3, gt=0, allow_inf_nan=False)
    min_entropy_observations: int = Field(default=32, ge=2)
    periodicity_cv: float = Field(default=0.1, ge=0, le=1)
    concentration_ratio: float = Field(default=0.8, gt=0, le=1)
    port_fanout: int = Field(default=60, ge=2)
    host_fanout: int = Field(default=32, ge=2)
    directional_ratio: float = Field(default=10, gt=1, allow_inf_nan=False)
    directional_bytes: int = Field(default=1048576, ge=1)
    min_directional_flows: int = Field(default=3, ge=2)
    policy_mode: Literal["informational", "enrich_ml", "behavioral_alert"] = "enrich_ml"

    @model_validator(mode="after")
    def coherent_bounds(self):
        if self.window_sec % self.bucket_sec or self.window_sec // self.bucket_sec > 120:
            raise ValueError("Window must use an integral number of at most 120 buckets")
        if self.min_sessions > self.max_sessions:
            raise ValueError("Minimum sessions must fit the bounded session history")
        return self
