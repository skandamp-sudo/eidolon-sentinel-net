"""
Offline PCAP file replay.

CRITICAL SECURITY REQUIREMENT: This module reads packet capture files from disk.
It has NO capability to capture live traffic, send packets, or interact with any network interface.
"""
import asyncio
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncGenerator

from scapy.utils import PcapReader

from sentinel_net.models.types import ParsedPacket
from sentinel_net.ingestion.parser import extract_raw_packet, parse_packet

logger = logging.getLogger(__name__)

@dataclass
class PcapReplayConfig:
    pcap_path: Path
    realtime: bool = False
    batch_size: int = 1000

class PcapReplay:
    """
    Offline PCAP replay class for structurally passive packet ingestion.
    """
    def __init__(self, config: PcapReplayConfig):
        self.config = config
        
        # Validate path
        path_str = str(self.config.pcap_path)
        if not os.path.exists(path_str):
            raise FileNotFoundError(f"PCAP file not found: {path_str}")
            
        if not os.path.isfile(path_str):
            raise IsADirectoryError(f"Path is not a file: {path_str}")
            
        if not os.access(path_str, os.R_OK):
            raise PermissionError(f"File is not readable: {path_str}")
            
        if not (path_str.endswith(".pcap") or path_str.endswith(".pcapng")):
            raise ValueError(f"File does not have a .pcap or .pcapng extension: {path_str}")
            
        self._packet_count = 0
        self._parsed_count = 0
        self._skipped_count = 0
        self._file_size_bytes = os.path.getsize(path_str)
        
    @property
    def packet_count(self) -> int:
        return self._packet_count
        
    @property
    def parsed_count(self) -> int:
        return self._parsed_count
        
    @property
    def skipped_count(self) -> int:
        return self._skipped_count
        
    @property
    def file_size_bytes(self) -> int:
        return self._file_size_bytes

    async def replay(self) -> AsyncGenerator[ParsedPacket, None]:
        """
        Asynchronously replay packets from the PCAP file.
        
        Yields:
            ParsedPacket: Successfully parsed IP packets.
        """
        logger.info(f"Starting PCAP replay from {self.config.pcap_path}")
        
        last_pkt_time = None
        current_time_offset = time.time()
        
        with PcapReader(str(self.config.pcap_path)) as reader:
            for scapy_pkt in reader:
                self._packet_count += 1
                
                # Handle realtime delays if requested
                if self.config.realtime and hasattr(scapy_pkt, 'time'):
                    pkt_time = float(scapy_pkt.time)
                    if last_pkt_time is not None:
                        time_diff = pkt_time - last_pkt_time
                        if time_diff > 0:
                            await asyncio.sleep(time_diff)
                    last_pkt_time = pkt_time
                
                raw_pkt = extract_raw_packet(scapy_pkt)
                parsed_pkt = parse_packet(raw_pkt)
                
                if parsed_pkt is None:
                    self._skipped_count += 1
                else:
                    self._parsed_count += 1
                    yield parsed_pkt
                    
                # Yield control to event loop every batch_size packets
                if self._packet_count % self.config.batch_size == 0:
                    await asyncio.sleep(0)
                    
                # Log progress
                if self._packet_count % 10000 == 0:
                    logger.info(f"Processed {self._packet_count} packets...")
                    
        logger.info(f"Finished PCAP replay. Total: {self._packet_count}, Parsed: {self._parsed_count}, Skipped: {self._skipped_count}")

    def replay_sync(self) -> list[ParsedPacket]:
        """
        Synchronously read and parse all packets from the PCAP file.
        
        Returns:
            list[ParsedPacket]: List of successfully parsed IP packets.
        """
        results = []
        with PcapReader(str(self.config.pcap_path)) as reader:
            for scapy_pkt in reader:
                self._packet_count += 1
                raw_pkt = extract_raw_packet(scapy_pkt)
                parsed_pkt = parse_packet(raw_pkt)
                
                if parsed_pkt is None:
                    self._skipped_count += 1
                else:
                    self._parsed_count += 1
                    results.append(parsed_pkt)
                    
        return results
