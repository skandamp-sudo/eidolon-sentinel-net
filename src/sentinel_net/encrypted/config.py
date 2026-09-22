from pydantic import BaseModel, Field, model_validator


class EncryptedConfig(BaseModel):
    enabled: bool = True
    max_connections: int = Field(default=256, ge=1, le=2048)
    max_direction_bytes: int = Field(default=32768, ge=1024, le=65536)
    handshake_ttl_sec: int = Field(default=10, ge=1, le=60)
    connection_ttl_sec: int = Field(default=60, ge=5, le=300)
    max_samples: int = Field(default=64, ge=2, le=256)
    tls_ports: tuple[int, ...] = (443, 8443, 853)
    quic_ports: tuple[int, ...] = (443, 4433, 853)

    @model_validator(mode="after")
    def bounds(self):
        if self.handshake_ttl_sec > self.connection_ttl_sec:
            raise ValueError("Handshake TTL must fit connection TTL")
        for ports in (self.tls_ports, self.quic_ports):
            if len(ports) > 16 or any(p < 1 or p > 65535 for p in ports):
                raise ValueError("At most 16 valid ports per transport")
        return self
