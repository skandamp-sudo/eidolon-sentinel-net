"""Inference-only entry point into the approved local registry."""

from pathlib import Path
from sentinel_net.deployment.bundle import load_bundle, ModelLoadError


def load_runtime_model(identity: str | None, *, registry: Path = Path("models/registry")):
    return load_bundle(registry, identity)
