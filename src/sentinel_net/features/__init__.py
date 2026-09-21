"""
Feature extraction module for EIDOLON // SENTINEL-NET.

Provides FeatureExtractor for converting ObservedFlow records into
FeatureVector records with a canonical, stable feature schema.
"""

from sentinel_net.features.extractor import FeatureExtractor
from sentinel_net.features.schema import FEATURE_COUNT, FEATURE_SCHEMA

__all__ = ["FeatureExtractor", "FEATURE_SCHEMA", "FEATURE_COUNT"]
