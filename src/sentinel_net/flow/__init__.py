"""
Flow aggregation module for EIDOLON // SENTINEL-NET.

Provides FlowAggregator for grouping ParsedPacket streams into
ObservedFlow records based on canonical 5-tuple conversation keys.
"""

from sentinel_net.flow.aggregator import FlowAggregator, FlowAggregatorConfig

__all__ = ["FlowAggregator", "FlowAggregatorConfig"]
