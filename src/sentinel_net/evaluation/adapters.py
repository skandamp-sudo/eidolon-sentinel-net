import pandas as pd
import numpy as np
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Callable, Any, Optional

from sentinel_net.features.schema import FEATURE_SCHEMA
from sentinel_net.detection.dataset import LabelMapper

class FeatureAvailability(Enum):
    DIRECT = "DIRECT"
    DERIVED = "DERIVED"
    PROXY = "PROXY"
    MISSING = "MISSING"
    STRUCTURAL_ZERO = "STRUCTURAL_ZERO"

@dataclass
class FeatureMapping:
    sentinel_name: str
    source_columns: list[str]
    transformation: Callable[[pd.DataFrame], pd.Series]
    unit_conversion: Optional[str]
    availability: FeatureAvailability
    justification: str
    missing_behavior: str

class CICIDSAdapter:
    @staticmethod
    def get_feature_matrix() -> list[FeatureMapping]:
        def _get_protocol(df):
            return df['Protocol'].astype(float)
        
        def _get_ip_version(df):
            return pd.Series(np.nan, index=df.index)

        matrix = [
            FeatureMapping("duration_sec", ["Flow Duration"], lambda df: df["Flow Duration"].astype(float) / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("total_packets", ["Total Fwd Packets", "Total Backward Packets"], lambda df: df["Total Fwd Packets"] + df["Total Backward Packets"], None, FeatureAvailability.DERIVED, "Sum of forward and backward packets", "N/A"),
            FeatureMapping("total_bytes", ["Fwd Packets Length Total", "Bwd Packets Length Total"], lambda df: df["Fwd Packets Length Total"] + df["Bwd Packets Length Total"], None, FeatureAvailability.DERIVED, "Sum of forward and backward bytes", "N/A"),
            FeatureMapping("packets_per_sec", ["Flow Packets/s"], lambda df: df["Flow Packets/s"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("bytes_per_sec", ["Flow Bytes/s"], lambda df: df["Flow Bytes/s"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("forward_packets", ["Total Fwd Packets"], lambda df: df["Total Fwd Packets"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("reverse_packets", ["Total Backward Packets"], lambda df: df["Total Backward Packets"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("forward_bytes", ["Fwd Packets Length Total"], lambda df: df["Fwd Packets Length Total"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("reverse_bytes", ["Bwd Packets Length Total"], lambda df: df["Bwd Packets Length Total"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("fwd_rev_packet_ratio", ["Total Fwd Packets", "Total Backward Packets"], lambda df: df["Total Fwd Packets"] / np.maximum(df["Total Backward Packets"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("fwd_rev_byte_ratio", ["Fwd Packets Length Total", "Bwd Packets Length Total"], lambda df: df["Fwd Packets Length Total"] / np.maximum(df["Bwd Packets Length Total"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("pkt_size_mean", ["Packet Length Mean"], lambda df: df["Packet Length Mean"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("pkt_size_std", ["Packet Length Std"], lambda df: df["Packet Length Std"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("pkt_size_min", ["Packet Length Min"], lambda df: df["Packet Length Min"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("pkt_size_max", ["Packet Length Max"], lambda df: df["Packet Length Max"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("pkt_size_median", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("pkt_size_p25", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("pkt_size_p75", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("pkt_size_p90", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("iat_mean", ["Flow IAT Mean"], lambda df: df["Flow IAT Mean"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("iat_std", ["Flow IAT Std"], lambda df: df["Flow IAT Std"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("iat_min", ["Flow IAT Min"], lambda df: df["Flow IAT Min"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("iat_max", ["Flow IAT Max"], lambda df: df["Flow IAT Max"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("iat_median", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("fwd_iat_mean", ["Fwd IAT Mean"], lambda df: df["Fwd IAT Mean"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("fwd_iat_std", ["Fwd IAT Std"], lambda df: df["Fwd IAT Std"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("fwd_iat_min", ["Fwd IAT Min"], lambda df: df["Fwd IAT Min"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("fwd_iat_max", ["Fwd IAT Max"], lambda df: df["Fwd IAT Max"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("rev_iat_mean", ["Bwd IAT Mean"], lambda df: df["Bwd IAT Mean"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("rev_iat_std", ["Bwd IAT Std"], lambda df: df["Bwd IAT Std"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("rev_iat_min", ["Bwd IAT Min"], lambda df: df["Bwd IAT Min"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("rev_iat_max", ["Bwd IAT Max"], lambda df: df["Bwd IAT Max"] / 1_000_000, "microseconds to seconds", FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("syn_count", ["SYN Flag Count"], lambda df: df["SYN Flag Count"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("syn_ack_count", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("ack_count", ["ACK Flag Count"], lambda df: df["ACK Flag Count"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("fin_count", ["FIN Flag Count"], lambda df: df["FIN Flag Count"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("rst_count", ["RST Flag Count"], lambda df: df["RST Flag Count"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("psh_count", ["PSH Flag Count"], lambda df: df["PSH Flag Count"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("syn_ratio", ["SYN Flag Count", "Total Fwd Packets", "Total Backward Packets"], lambda df: df["SYN Flag Count"] / np.maximum(df["Total Fwd Packets"] + df["Total Backward Packets"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("ack_ratio", ["ACK Flag Count", "Total Fwd Packets", "Total Backward Packets"], lambda df: df["ACK Flag Count"] / np.maximum(df["Total Fwd Packets"] + df["Total Backward Packets"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("fin_ratio", ["FIN Flag Count", "Total Fwd Packets", "Total Backward Packets"], lambda df: df["FIN Flag Count"] / np.maximum(df["Total Fwd Packets"] + df["Total Backward Packets"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("rst_ratio", ["RST Flag Count", "Total Fwd Packets", "Total Backward Packets"], lambda df: df["RST Flag Count"] / np.maximum(df["Total Fwd Packets"] + df["Total Backward Packets"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("psh_ratio", ["PSH Flag Count", "Total Fwd Packets", "Total Backward Packets"], lambda df: df["PSH Flag Count"] / np.maximum(df["Total Fwd Packets"] + df["Total Backward Packets"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("protocol", ["Protocol"], _get_protocol, None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("ip_version", [], _get_ip_version, None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("is_tcp", ["Protocol"], lambda df: (df["Protocol"] == 6).astype(float), None, FeatureAvailability.DERIVED, "Derived from protocol", "N/A"),
            FeatureMapping("is_udp", ["Protocol"], lambda df: (df["Protocol"] == 17).astype(float), None, FeatureAvailability.DERIVED, "Derived from protocol", "N/A"),
            FeatureMapping("is_icmp", ["Protocol"], lambda df: (df["Protocol"] == 1).astype(float), None, FeatureAvailability.DERIVED, "Derived from protocol", "N/A"),
            FeatureMapping("payload_bytes_total", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("forward_payload_bytes", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("reverse_payload_bytes", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
            FeatureMapping("payload_ratio", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not in CICFlowMeter", "np.nan"),
        ]
        return matrix

    @staticmethod
    def get_label_mapping() -> dict[str, str]:
        return LabelMapper.for_cicids2017().mapping

    @staticmethod
    def load_all(data_dir: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        dfs = []
        for p in data_dir.glob("*.parquet"):
            df = pd.read_parquet(p)
            scenario = p.name.replace("-no-metadata.parquet", "").replace(".parquet", "")
            df["_scenario"] = scenario
            dfs.append(df)
            
        full_df = pd.concat(dfs, ignore_index=True)
        
        matrix = CICIDSAdapter.get_feature_matrix()
        X_df = pd.DataFrame(index=full_df.index)
        for m in matrix:
            X_df[m.sentinel_name] = m.transformation(full_df).astype(np.float64)
            
        X = X_df[list(FEATURE_SCHEMA)].to_numpy(dtype=np.float64)
        
        mapper = LabelMapper.for_cicids2017()
        labels = np.array([mapper.map(str(lbl)) for lbl in full_df["Label"]])
        scenarios = full_df["_scenario"].to_numpy()
        
        return X, labels, scenarios


class UNSWAdapter:
    @staticmethod
    def get_feature_matrix() -> list[FeatureMapping]:
        def _get_protocol(df):
            mapping = {"tcp": 6, "udp": 17, "icmp": 1}
            return df["proto"].map(lambda x: mapping.get(str(x).lower(), 0)).astype(float)
            
        matrix = [
            FeatureMapping("duration_sec", ["dur"], lambda df: df["dur"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("total_packets", ["spkts", "dpkts"], lambda df: df["spkts"] + df["dpkts"], None, FeatureAvailability.DERIVED, "Sum of forward and backward", "N/A"),
            FeatureMapping("total_bytes", ["sbytes", "dbytes"], lambda df: df["sbytes"] + df["dbytes"], None, FeatureAvailability.DERIVED, "Sum of forward and backward", "N/A"),
            FeatureMapping("packets_per_sec", ["spkts", "dpkts", "dur"], lambda df: (df["spkts"] + df["dpkts"]) / np.maximum(df["dur"], 1e-6), None, FeatureAvailability.DERIVED, "Calculated from packets and duration", "N/A"),
            FeatureMapping("bytes_per_sec", ["rate"], lambda df: df["rate"], None, FeatureAvailability.PROXY, "Rate is a close proxy to bytes/sec", "N/A"),
            FeatureMapping("forward_packets", ["spkts"], lambda df: df["spkts"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("reverse_packets", ["dpkts"], lambda df: df["dpkts"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("forward_bytes", ["sbytes"], lambda df: df["sbytes"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("reverse_bytes", ["dbytes"], lambda df: df["dbytes"], None, FeatureAvailability.DIRECT, "Direct measure", "N/A"),
            FeatureMapping("fwd_rev_packet_ratio", ["spkts", "dpkts"], lambda df: df["spkts"] / np.maximum(df["dpkts"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("fwd_rev_byte_ratio", ["sbytes", "dbytes"], lambda df: df["sbytes"] / np.maximum(df["dbytes"], 1), None, FeatureAvailability.DERIVED, "Ratio calculation", "N/A"),
            FeatureMapping("pkt_size_mean", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available in combined direction", "np.nan"),
            FeatureMapping("pkt_size_std", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("pkt_size_min", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("pkt_size_max", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("pkt_size_median", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("pkt_size_p25", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("pkt_size_p75", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("pkt_size_p90", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("iat_mean", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available in combined direction", "np.nan"),
            FeatureMapping("iat_std", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("iat_min", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("iat_max", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("iat_median", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("fwd_iat_mean", ["sinpkt"], lambda df: df["sinpkt"], None, FeatureAvailability.PROXY, "Close to fwd iat mean", "N/A"),
            FeatureMapping("fwd_iat_std", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("fwd_iat_min", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("fwd_iat_max", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("rev_iat_mean", ["dinpkt"], lambda df: df["dinpkt"], None, FeatureAvailability.PROXY, "Close to rev iat mean", "N/A"),
            FeatureMapping("rev_iat_std", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("rev_iat_min", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("rev_iat_max", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("syn_count", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("syn_ack_count", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("ack_count", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("fin_count", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("rst_count", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("psh_count", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("syn_ratio", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("ack_ratio", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("fin_ratio", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("rst_ratio", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("psh_ratio", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("protocol", ["proto"], _get_protocol, None, FeatureAvailability.DIRECT, "Direct with encoding", "N/A"),
            FeatureMapping("ip_version", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("is_tcp", ["proto"], lambda df: (df["proto"].str.lower() == 'tcp').astype(float), None, FeatureAvailability.DERIVED, "Derived from protocol", "N/A"),
            FeatureMapping("is_udp", ["proto"], lambda df: (df["proto"].str.lower() == 'udp').astype(float), None, FeatureAvailability.DERIVED, "Derived from protocol", "N/A"),
            FeatureMapping("is_icmp", ["proto"], lambda df: (df["proto"].str.lower() == 'icmp').astype(float), None, FeatureAvailability.DERIVED, "Derived from protocol", "N/A"),
            FeatureMapping("payload_bytes_total", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("forward_payload_bytes", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("reverse_payload_bytes", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
            FeatureMapping("payload_ratio", [], lambda df: pd.Series(np.nan, index=df.index), None, FeatureAvailability.MISSING, "Not available", "np.nan"),
        ]
        return matrix

    @staticmethod
    def get_label_mapping() -> dict[str, str]:
        return LabelMapper.for_unsw_nb15().mapping

    @staticmethod
    def load_all(data_dir: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        train_path = data_dir / "UNSW_NB15_training-set.csv"
        test_path = data_dir / "UNSW_NB15_testing-set.csv"
        
        dfs = []
        if train_path.exists():
            df_train = pd.read_csv(train_path, encoding='latin-1')
            df_train["_scenario"] = "train"
            dfs.append(df_train)
        if test_path.exists():
            df_test = pd.read_csv(test_path, encoding='latin-1')
            df_test["_scenario"] = "test"
            dfs.append(df_test)
            
        full_df = pd.concat(dfs, ignore_index=True)
        
        matrix = UNSWAdapter.get_feature_matrix()
        X_df = pd.DataFrame(index=full_df.index)
        for m in matrix:
            X_df[m.sentinel_name] = m.transformation(full_df).astype(np.float64)
            
        X = X_df[list(FEATURE_SCHEMA)].to_numpy(dtype=np.float64)
        
        mapper = LabelMapper.for_unsw_nb15()
        # Vectorized label extraction from attack_cat
        raw_cats = full_df['attack_cat'].fillna('').astype(str).str.strip()
        binary_labels = full_df.get('label', pd.Series(0, index=full_df.index))
        # Where attack_cat is empty or 'Normal', use binary label to decide
        raw_labels_arr = np.where(
            (raw_cats == '') | (raw_cats == 'Normal') | (raw_cats == 'nan'),
            np.where(binary_labels == 0, 'Normal', 'Generic'),
            raw_cats
        )
        labels = np.array([mapper.map(str(lbl)) for lbl in raw_labels_arr])
        
        # Use train/test partition as scenario (not row 'id')
        scenarios = full_df['_scenario'].to_numpy()
        
        return X, labels, scenarios


def get_cicids_availability_summary() -> dict[str, int]:
    matrix = CICIDSAdapter.get_feature_matrix()
    summary = {}
    for m in matrix:
        summary[m.availability.name] = summary.get(m.availability.name, 0) + 1
    return summary


def get_unsw_availability_summary() -> dict[str, int]:
    matrix = UNSWAdapter.get_feature_matrix()
    summary = {}
    for m in matrix:
        summary[m.availability.name] = summary.get(m.availability.name, 0) + 1
    return summary
