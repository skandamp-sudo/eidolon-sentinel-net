"""Operational disposition, independent of frozen model severity/confidence."""


class EvidencePolicy:
    def __init__(self, config):
        self.config = config

    def decide(self, evidence):
        action = self.config.policy_mode if evidence else "informational"
        return {
            "version": "sih-f3/1.0",
            "action": action,
            "behavioral_alert": bool(evidence and action == "behavioral_alert"),
            "semantics": "Operational heuristic evidence; not an attack confirmation or probability. ML severity and scores are unchanged.",
        }
