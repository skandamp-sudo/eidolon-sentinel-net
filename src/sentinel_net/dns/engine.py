"""Single-owner, bounded passive DNS evidence using F3 event-time buckets."""

import math
from collections import Counter, OrderedDict
from copy import deepcopy

from sentinel_net.dns.parser import observe_packet
from sentinel_net.explainability.attack_mapping import ATTACKMapper
from sentinel_net.intelligence.window import BoundedWindow


class DNSWindowMetrics:
    """Reuse F3 mechanics without mixing its counters or identity namespaces."""

    def __init__(self, metrics):
        self.metrics = metrics

    def __getattr__(self, method):
        def apply(name, *args):
            target = name.replace("intelligence_", "dns_")
            if target == "dns_keys":
                target = "dns_state_keys"
            return getattr(self.metrics, method)(target, *args)

        return apply


def lexical(qname):
    labels = qname.split(".") if qname else []
    text = "".join(labels)

    def entropy(value):
        return (
            -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())
            if value
            else 0.0
        )

    return {
        "qname_length": len(qname),
        "label_count": len(labels),
        "longest_label": max(map(len, labels), default=0),
        "character_entropy": entropy(text),
        "max_label_entropy": max(map(entropy, labels), default=0.0),
        "digit_ratio": sum(c.isdigit() for c in text) / max(len(text), 1),
        "alphabetic_ratio": sum(c.isalpha() for c in text) / max(len(text), 1),
        "hexadecimal_ratio": sum(c in "0123456789abcdef" for c in text) / max(len(text), 1),
        "unique_characters": len(set(text)),
        "repeated_labels": len(labels) - len(set(labels)),
        "subdomain_depth_proxy": max(0, len(labels) - 2),
        "sample_characters": len(text),
        "entropy_scope": "lowercase ASCII characters; dots excluded; bits/character",
        "label_statistics": [{"length": len(label), "entropy": entropy(label)} for label in labels],
    }


def conversation(src, dst, sport, dport, protocol):
    return (tuple(sorted(((src, sport or 0), (dst, dport or 0)))), protocol)


class DNSIntelligence:
    def __init__(self, config, metrics):
        self.config, self.metrics = config, metrics
        self.window = BoundedWindow(config, DNSWindowMetrics(metrics))
        self.transactions, self.observations = OrderedDict(), OrderedDict()

    def _put(self, cache, key, value, cap, gauge):
        if key not in cache and len(cache) >= cap:
            cache.popitem(last=False)
            self.metrics.increment("dns_evictions")
        cache[key] = value
        cache.move_to_end(key)
        self.metrics.set_gauge(gauge, len(cache))
        self.metrics.observe_peak(gauge + "_peak", len(cache))

    def _advance(self, timestamp):
        tick = self.window.advance(timestamp)
        watermark = self.window.watermark
        for cache, ttl, gauge in (
            (self.transactions, self.config.transaction_ttl_sec, "dns_transactions"),
            (self.observations, self.config.window_sec, "dns_observations"),
        ):
            for key, item in list(cache.items()):
                if item["timestamp"] < watermark - ttl:
                    del cache[key]
                    self.metrics.increment("dns_expirations")
            self.metrics.set_gauge(gauge, len(cache))
        return tick

    def _correlate(self, packet, message, client, server, client_port):
        signature = tuple((q["name"], q["qtype"], q["qclass"]) for q in message["questions"])
        if not signature:
            return "RESPONSE_ONLY" if message["qr"] else "QUERY_ONLY", False, False
        key = (
            client,
            server,
            client_port,
            packet.src_port if message["qr"] else packet.dst_port,
            packet.protocol,
            message["transaction_id"],
            signature,
        )
        old = self.transactions.get(key)
        paired = bool(
            old
            and old["qr"] != message["qr"]
            and abs(packet.timestamp - old["timestamp"]) <= self.config.transaction_ttl_sec
        )
        nxdomain = (message["rcode"] == 3) if message["qr"] else bool(old and old.get("nxdomain"))
        if paired:
            del self.transactions[
                key
            ]  # One conservative match; never reuse one response indefinitely.
            self.metrics.set_gauge("dns_transactions", len(self.transactions))
        elif packet.timestamp >= self.window.watermark - self.config.transaction_ttl_sec:
            self._put(
                self.transactions,
                key,
                {
                    "timestamp": packet.timestamp,
                    "qr": message["qr"],
                    "nxdomain": message["rcode"] == 3,
                },
                self.config.max_transactions,
                "dns_transactions",
            )
        return (
            "PAIRED" if paired else ("RESPONSE_ONLY" if message["qr"] else "QUERY_ONLY"),
            paired,
            nxdomain,
        )

    def observe_packet(self, packet):
        if not self.config.enabled:
            return
        tick = self._advance(packet.timestamp)
        messages = observe_packet(packet)
        key = conversation(
            packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol
        )
        for message in messages:
            self.metrics.increment("dns_messages_observed")
            status = message["status"]
            self.metrics.increment(
                {
                    "PARSED": "dns_messages_parsed",
                    "MALFORMED": "dns_malformed",
                    "TRUNCATED": "dns_truncated",
                }.get(status, "dns_unavailable")
            )
            record = {
                "timestamp": packet.timestamp,
                "message": message,
                "visibility": "UNAVAILABLE",
                "lexical": [],
                "client": None,
                "parent": None,
            }
            if status == "PARSED" and tick is not None:
                qr = message["qr"]
                client, server, port = (
                    (packet.dst_ip, packet.src_ip, packet.dst_port)
                    if qr
                    else (packet.src_ip, packet.dst_ip, packet.src_port)
                )
                visibility, paired, nx = self._correlate(packet, message, client, server, port)
                record.update(visibility=visibility, client=client, server=server)
                states = [
                    self.window.get(("client", client), tick),
                    self.window.get(("server", server), tick),
                ]
                for state, bucket in states:
                    bucket.counts["response_messages" if qr else "query_messages"] += 1
                    bucket.counts["nxdomain_responses"] += int(qr and message["rcode"] == 3)
                    bucket.counts["paired_responses"] += int(paired)
                    bucket.counts["paired_nxdomain"] += int(paired and nx)
                parents_seen = set()  # At most four questions per parsed message.
                for question in message["questions"]:
                    stats = lexical(question["name"])
                    record["lexical"].append(stats)
                    if question["qclass"] != 1:
                        continue
                    labels = question["name"].split(".")
                    parent = ".".join(labels[-2:])
                    record["parent"] = parent
                    parent_state = self.window.get(("parent", client, parent), tick)
                    if parent not in parents_seen:
                        parents_seen.add(parent)
                        parent_bucket = parent_state[1]
                        parent_bucket.counts["response_messages" if qr else "query_messages"] += 1
                        parent_bucket.counts["nxdomain_responses"] += int(
                            qr and message["rcode"] == 3
                        )
                        parent_bucket.counts["paired_responses"] += int(paired)
                        parent_bucket.counts["paired_nxdomain"] += int(paired and nx)
                    if qr:
                        continue  # A response question echo is not another query.
                    high = any(
                        v["length"] >= self.config.entropy_min_label
                        and v["entropy"] >= self.config.entropy_bits
                        for v in stats["label_statistics"]
                    )
                    for state, bucket in [*states, parent_state]:
                        bucket.counts.update(
                            {
                                "questions": 1,
                                "length_sum": stats["qname_length"],
                                "entropy_sum": stats["max_label_entropy"],
                                "high_entropy": int(high),
                                "long_labels": int(
                                    stats["longest_label"] >= self.config.long_label
                                ),
                                "long_queries": int(
                                    stats["qname_length"] >= self.config.long_query
                                ),
                                "txt": int(question["qtype"] == 16),
                            }
                        )
                        self.window.member(state, bucket, "sources", question["name"])
                        self.window.member(state, bucket, "destinations", parent)
                        self.window.member(state, bucket, "ports", question["qtype"])
            elif tick is None:
                record["reason"] = "Observation outside retained event-time window"
            if tick is not None:
                previous = self.observations.get(key)
                if previous and previous["timestamp"] > record["timestamp"]:
                    if (
                        record["visibility"] == "PAIRED"
                        and previous["message"].get("transaction_id")
                        == message.get("transaction_id")
                        and previous["message"].get("questions") == message.get("questions")
                    ):
                        previous["visibility"] = "PAIRED"
                    continue
                self._put(
                    self.observations, key, record, self.config.max_observations, "dns_observations"
                )

    def summary(self, key):
        state = self.window.keys.get(key)
        if not state:
            return None
        totals = state.totals()
        n, responses = totals.counts["questions"], totals.counts["response_messages"]
        return {
            "questions": n,
            "query_messages": totals.counts["query_messages"],
            "query_rate": totals.counts["query_messages"] / self.config.window_sec,
            "unique_domains": len(totals.sources),
            "unique_parent_proxies": len(totals.destinations),
            "repeated_questions_lower_bound": sum(
                max(0, count - 1) for count in totals.sources.values()
            ),
            "qtype_distribution": dict(totals.ports),
            "identity_counts_are_lower_bounds": bool(totals.overflow),
            "membership_overflows": totals.overflow,
            "high_entropy_ratio": totals.counts["high_entropy"] / max(n, 1),
            "long_label_ratio": totals.counts["long_labels"] / max(n, 1),
            "long_query_ratio": totals.counts["long_queries"] / max(n, 1),
            "mean_query_length": totals.counts["length_sum"] / n if n else None,
            "mean_max_label_entropy": totals.counts["entropy_sum"] / n if n else None,
            "txt_ratio": totals.counts["txt"] / max(n, 1),
            "observed_responses": responses,
            "nxdomain_count": totals.counts["nxdomain_responses"],
            "nxdomain_ratio": totals.counts["nxdomain_responses"] / responses
            if responses
            else None,
            "paired_responses": totals.counts["paired_responses"],
            "paired_nxdomain_ratio": totals.counts["paired_nxdomain"]
            / totals.counts["paired_responses"]
            if totals.counts["paired_responses"]
            else None,
        }

    def enrich(self, event, flow):
        cfg = self.config
        event.metadata["dns_evidence"] = []
        event.metadata["dns_attack_context"] = []
        if not cfg.enabled:
            event.metadata["dns_status"] = "disabled"
            return
        self._advance(flow.end_time)
        f = flow.flow_key
        record = self.observations.get(
            conversation(f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol)
        )
        if (
            not record
            or record["timestamp"] < flow.start_time
            or record["timestamp"] > flow.end_time
        ):
            event.metadata["dns_status"] = "unavailable_or_not_observed"
            return
        event.metadata["dns_status"] = record["message"]["status"]
        observation = deepcopy(record)
        observation["retention"] = (
            "Latest retained message for this conversation; not a complete DNS history"
        )
        observation["parent_semantics"] = (
            "Last two labels only; not a public-suffix/registrable-domain classification"
        )
        observation["disposition"] = "Contextual evidence"
        event.metadata["dns_observation"] = observation
        if record["message"]["status"] != "PARSED" or not record["client"]:
            return
        source = self.summary(("client", record["client"]))
        parent = (
            self.summary(("parent", record["client"], record["parent"]))
            if record["parent"]
            else None
        )
        observation["source_window"] = source
        observation["server_window"] = self.summary(("server", record["server"]))
        observation["parent_window"] = parent
        observation["observation_window"] = self.window.interval
        evidence = event.metadata["dns_evidence"]

        def emit(kind, value, threshold, scope, context):
            evidence.append(
                {
                    "signal_type": kind,
                    "detector": "dns_intelligence",
                    "detector_version": "1.0.0",
                    "observed_value": value,
                    "reference_threshold": threshold,
                    "comparison": ">=",
                    "unit": scope,
                    "observation_window": self.window.interval,
                    "supporting_context": context,
                    "confidence_semantics": "Operational heuristic; not attack probability or confirmed malicious activity.",
                    "interpretation": "Legitimate CDN, cloud hostnames, telemetry, discovery and security records may produce these observations.",
                }
            )

        for question, stats in zip(record["message"]["questions"], record["lexical"]):
            context = {
                "domain": question["name"],
                "scope": "latest observed message",
                "sample_count": 1,
                "statistics": stats,
            }
            if stats["longest_label"] >= cfg.long_label or stats["qname_length"] >= cfg.long_query:
                emit(
                    "DNS_LEXICAL_ANOMALY",
                    stats["longest_label"]
                    if stats["longest_label"] >= cfg.long_label
                    else stats["qname_length"],
                    cfg.long_label if stats["longest_label"] >= cfg.long_label else cfg.long_query,
                    "label characters"
                    if stats["longest_label"] >= cfg.long_label
                    else "QNAME characters",
                    context,
                )
            qualifying = [
                v["entropy"]
                for v in stats["label_statistics"]
                if v["length"] >= cfg.entropy_min_label
            ]
            if qualifying and max(qualifying) >= cfg.entropy_bits:
                emit(
                    "DNS_HIGH_ENTROPY_LABEL",
                    max(qualifying),
                    cfg.entropy_bits,
                    "bits/character",
                    context,
                )
        if source:
            if source["unique_domains"] >= cfg.unique_domains:
                emit(
                    "DNS_UNIQUE_DOMAIN_RATE",
                    source["unique_domains"] / cfg.window_sec,
                    cfg.unique_domains / cfg.window_sec,
                    "distinct queried names/second",
                    source,
                )
            if (
                source["observed_responses"] >= cfg.min_responses
                and source["nxdomain_ratio"] >= cfg.nxdomain_ratio
            ):
                emit(
                    "DNS_NXDOMAIN_PATTERN",
                    source["nxdomain_ratio"],
                    cfg.nxdomain_ratio,
                    "observed response fraction",
                    source,
                )
            if source["questions"] >= cfg.min_queries and source["txt_ratio"] >= cfg.txt_ratio:
                emit(
                    "DNS_QTYPE_PATTERN",
                    source["txt_ratio"],
                    cfg.txt_ratio,
                    "TXT question fraction",
                    source,
                )
            diverse = source["unique_parent_proxies"] >= cfg.unique_domains
            failed = (
                source["paired_responses"] >= cfg.min_responses
                and source["paired_nxdomain_ratio"] >= cfg.nxdomain_ratio
            )
            if (
                source["questions"] >= cfg.min_queries
                and diverse
                and source["high_entropy_ratio"] >= cfg.high_entropy_ratio
                and (failed or source["long_label_ratio"] >= cfg.long_label_ratio)
            ):
                emit(
                    "DGA_LIKE_BEHAVIOR",
                    source["high_entropy_ratio"],
                    cfg.high_entropy_ratio,
                    "high-entropy question fraction",
                    {
                        **source,
                        "criteria": "minimum questions AND diverse parent proxies AND elevated entropy AND (paired failed responses OR repeated long labels)",
                        "policy_thresholds": cfg.model_dump(),
                        "response_context": "paired"
                        if failed
                        else "not required; lexical/diversity branch",
                    },
                )
        if (
            parent
            and parent["questions"] >= cfg.min_queries
            and parent["unique_domains"] >= cfg.unique_subdomains
            and parent["high_entropy_ratio"] >= cfg.high_entropy_ratio
            and parent["long_label_ratio"] >= cfg.long_label_ratio
            and parent["questions"] / cfg.window_sec >= cfg.query_rate
        ):
            emit(
                "DNS_TUNNELLING_LIKE_BEHAVIOR",
                parent["unique_domains"],
                cfg.unique_subdomains,
                "distinct names under parent proxy",
                {
                    **parent,
                    "parent_proxy": record["parent"],
                    "criteria": "minimum questions AND unique names under repeated parent proxy AND entropy AND long labels AND question rate",
                    "policy_thresholds": cfg.model_dump(),
                },
            )
        if any(s["signal_type"] == "DNS_TUNNELLING_LIKE_BEHAVIOR" for s in evidence):
            for mapping in ATTACKMapper().map("dns_tunneling"):
                if mapping.technique_id == "T1071.004":
                    item = mapping.to_dict()
                    item.update(
                        qualification="possible",
                        source="dns_intelligence",
                        rationale="Context only: combined passive DNS patterns may also be legitimate. No command-and-control, transfer, intent or attribution is established.",
                    )
                    event.metadata["dns_attack_context"].append(item)
        self.metrics.increment("dns_evidence_generated", len(evidence))

    def close(self):
        self.window.close()
        self.transactions.clear()
        self.observations.clear()
        self.metrics.set_gauge("dns_transactions", 0)
        self.metrics.set_gauge("dns_observations", 0)
