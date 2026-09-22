"""Operational bounds and contextual heuristics, never model probabilities."""

from pydantic import BaseModel, Field, model_validator


class DNSConfig(BaseModel):
    enabled: bool = True
    window_sec: int = Field(default=60, ge=5, le=3600)
    bucket_sec: int = Field(default=1, ge=1, le=60)
    max_keys: int = Field(default=512, ge=3, le=4096)
    max_members: int = Field(default=128, ge=2, le=512)
    max_transactions: int = Field(default=1024, ge=1, le=8192)
    transaction_ttl_sec: int = Field(default=10, ge=1, le=60)
    max_observations: int = Field(default=1024, ge=1, le=8192)
    entropy_bits: float = Field(default=3.5, gt=0, le=6, allow_inf_nan=False)
    entropy_min_label: int = Field(default=20, ge=8, le=63)
    long_label: int = Field(default=40, ge=8, le=63)
    long_query: int = Field(default=100, ge=20, le=253)
    min_queries: int = Field(default=20, ge=4)
    unique_domains: int = Field(default=16, ge=4)
    unique_subdomains: int = Field(default=16, ge=4)
    query_rate: float = Field(default=0.3, gt=0, allow_inf_nan=False)
    high_entropy_ratio: float = Field(default=0.7, gt=0, le=1)
    long_label_ratio: float = Field(default=0.7, gt=0, le=1)
    nxdomain_ratio: float = Field(default=0.5, gt=0, le=1)
    min_responses: int = Field(default=10, ge=2)
    txt_ratio: float = Field(default=0.8, gt=0, le=1)

    @model_validator(mode="after")
    def coherent(self):
        if self.window_sec % self.bucket_sec or self.window_sec // self.bucket_sec > 120:
            raise ValueError("DNS windows require at most 120 integral buckets")
        if max(self.unique_domains, self.unique_subdomains) > self.max_members:
            raise ValueError("Unique thresholds must fit the identity cap")
        return self
