"""
Weighted Finite Automaton (WFA) for Phishing URL Detection
Theory of Computation - Core Innovation Layer (Layer 3)

States Q0-Q8 represent risk levels:
Q0: Initial/Clean
Q1: Protocol detected
Q2: IP-based host (high risk)
Q3: Suspicious subdomain depth
Q4: Obfuscation characters detected
Q5: Suspicious path structure
Q6: Credential/social indicators
Q7: Encoding anomalies
Q8: Terminal/Malicious
"""

import re
import math
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional


@dataclass
class WFATransition:
    from_state: str
    to_state: str
    symbol: str
    weight: float
    description: str


@dataclass
class WFAResult:
    path: List[str]
    transitions_taken: List[dict]
    raw_score: float
    normalized_score: float
    triggered_patterns: List[str]
    final_state: str


class WeightedFiniteAutomaton:
    """
    WFA with states Q0-Q8, weighted transitions derived from ML feature weights.
    Processes tokenized URL segments and accumulates a malicious score.
    """

    STATES = ["Q0", "Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8"]
    INITIAL_STATE = "Q0"
    ACCEPTING_STATES = ["Q7", "Q8"]  # High-risk terminal states

    def __init__(self, feature_weights: Optional[Dict[str, float]] = None):
        self.feature_weights = feature_weights or self._default_weights()
        self.transitions: List[WFATransition] = []
        self.state_weights: Dict[str, float] = {}
        self._build_automaton()

    def _default_weights(self) -> Dict[str, float]:
        """Default feature weights from literature-based logistic regression."""
        return {
            "url_length": 0.45,
            "subdomain_depth": 0.62,
            "has_ip": 0.89,
            "has_at": 0.78,
            "has_double_slash": 0.55,
            "has_dash_in_domain": 0.38,
            "has_encoding": 0.67,
            "path_depth": 0.41,
            "has_suspicious_tld": 0.72,
            "has_port": 0.58,
            "digit_ratio": 0.44,
            "has_https": -0.35,
            "has_unicode": 0.61,
            "query_length": 0.33,
            "fragment_present": 0.29,
        }

    def _build_automaton(self):
        """Define all WFA transitions with weights."""
        w = self.feature_weights
        self.transitions = [
            # Q0 → Q1: Protocol analysis
            WFATransition("Q0", "Q1", "http://", 0.15, "HTTP (no TLS)"),
            WFATransition("Q0", "Q1", "https://", -0.05, "HTTPS detected"),
            WFATransition("Q0", "Q1", "ftp://", 0.30, "FTP protocol"),

            # Q1 → Q2: IP-based host (very suspicious)
            WFATransition("Q1", "Q2", "IP_HOST", w["has_ip"] * 1.2, "IP address as host"),
            WFATransition("Q1", "Q3", "DEEP_SUBDOMAIN", w["subdomain_depth"], "Excessive subdomains"),
            WFATransition("Q1", "Q5", "NORMAL_DOMAIN", 0.05, "Normal domain"),
            WFATransition("Q1", "Q4", "ENCODED_DOMAIN", w["has_encoding"] * 0.9, "Encoded characters in domain"),

            # Q2 → Q8: IP host almost always malicious
            WFATransition("Q2", "Q8", "ANY", w["has_ip"] * 1.5, "IP host → malicious terminal"),

            # Q3 → Q4: Suspicious subdomain + encoding
            WFATransition("Q3", "Q4", "ENCODED", w["has_encoding"], "Encoding after deep subdomain"),
            WFATransition("Q3", "Q6", "CREDENTIAL_KWORD", w["has_at"], "Credential keyword"),
            WFATransition("Q3", "Q5", "PATH", w["path_depth"] * 0.5, "Deep path"),

            # Q4 → Q7: Encoding anomaly path
            WFATransition("Q4", "Q7", "PERCENT_ENC", w["has_encoding"] * 1.3, "URL percent encoding"),
            WFATransition("Q4", "Q7", "UNICODE", w["has_unicode"] * 1.1, "Unicode spoofing"),
            WFATransition("Q4", "Q5", "SLASH", w["has_double_slash"] * 0.7, "Double slash"),

            # Q5 → Q6: Path analysis
            WFATransition("Q5", "Q6", "AT_SIGN", w["has_at"] * 1.4, "@ sign in URL"),
            WFATransition("Q5", "Q6", "LOGIN_PATH", 0.65, "Login/auth path detected"),
            WFATransition("Q5", "Q7", "DEEP_PATH", w["path_depth"] * 1.2, "Suspicious path depth"),
            WFATransition("Q5", "Q5", "NORMAL_PATH", 0.02, "Normal path token"),

            # Q6 → Q8: Credential indicators
            WFATransition("Q6", "Q8", "PARAM_CRED", 0.82, "Credential parameters"),
            WFATransition("Q6", "Q7", "LONG_QUERY", w["query_length"] * 1.1, "Suspicious query string"),

            # Q7 → Q8: High-risk escalation
            WFATransition("Q7", "Q8", "FINAL_RISK", 0.90, "Multiple anomalies → malicious"),
            WFATransition("Q7", "Q7", "ENCODED", w["has_encoding"] * 0.5, "Additional encoding"),

            # Q8 is terminal (absorbing state)
            WFATransition("Q8", "Q8", "ANY", 0.0, "Terminal malicious state"),
        ]

        # State output weights (initial weight when entering each state)
        self.state_weights = {
            "Q0": 0.0,
            "Q1": 0.05,
            "Q2": 0.70,
            "Q3": 0.45,
            "Q4": 0.55,
            "Q5": 0.30,
            "Q6": 0.65,
            "Q7": 0.80,
            "Q8": 1.00,
        }

    def update_weights(self, feature_weights: Dict[str, float]):
        """Update transition weights from trained ML model."""
        self.feature_weights = feature_weights
        self._build_automaton()

    def tokenize_url(self, url: str) -> List[Tuple[str, str]]:
        """
        Tokenize URL into (symbol, raw_value) pairs for WFA processing.
        Returns list of (symbol_type, actual_value) tuples.
        """
        tokens = []
        url_lower = url.lower()

        # Protocol
        if url_lower.startswith("https://"):
            tokens.append(("https://", "https://"))
            url = url[8:]
        elif url_lower.startswith("http://"):
            tokens.append(("http://", "http://"))
            url = url[7:]
        elif url_lower.startswith("ftp://"):
            tokens.append(("ftp://", "ftp://"))
            url = url[6:]
        else:
            tokens.append(("http://", "http://"))

        # Split into host and path
        parts = url.split("/", 1)
        host = parts[0]
        path = parts[1] if len(parts) > 1 else ""

        # Host analysis
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", host):
            tokens.append(("IP_HOST", host))
        else:
            host_parts = host.split(".")
            domain_parts = host_parts[:-2] if len(host_parts) > 2 else []
            if len(domain_parts) > 2:
                tokens.append(("DEEP_SUBDOMAIN", ".".join(domain_parts)))
            elif re.search(r"%[0-9a-fA-F]{2}", host):
                tokens.append(("ENCODED_DOMAIN", host))
            else:
                tokens.append(("NORMAL_DOMAIN", host))

        # @ sign
        if "@" in url:
            tokens.append(("AT_SIGN", "@"))

        # Path analysis
        if path:
            path_segments = path.split("/")
            if len(path_segments) > 4:
                tokens.append(("DEEP_PATH", path))
            if re.search(r"(login|signin|account|verify|secure|update|confirm)", path, re.I):
                tokens.append(("LOGIN_PATH", path))
            else:
                tokens.append(("PATH", path))

        # Encoding analysis
        if re.search(r"%[0-9a-fA-F]{2}", url):
            tokens.append(("PERCENT_ENC", url))
        if re.search(r"%u[0-9a-fA-F]{4}|xn--", url, re.I):
            tokens.append(("UNICODE", url))
        if "//" in url[url.find("//") + 2:]:
            tokens.append(("SLASH", "//"))

        # Query string
        if "?" in url:
            query = url.split("?", 1)[1]
            if len(query) > 50:
                tokens.append(("LONG_QUERY", query))
            if re.search(r"(pass|pwd|token|auth|key|secret)", query, re.I):
                tokens.append(("PARAM_CRED", query))

        # Credential keywords in full URL
        if re.search(r"(paypal|ebay|amazon|bank|secure|account|login|verify)", url_lower):
            tokens.append(("CREDENTIAL_KWORD", url_lower))

        # Encoding in non-path areas
        if re.search(r"(%20|%2F|%3A|%40)", url, re.I):
            tokens.append(("ENCODED", url))

        # Final risk aggregator (always added)
        tokens.append(("FINAL_RISK", "terminal"))

        return tokens

    def _find_transition(self, current_state: str, symbol: str) -> Optional[WFATransition]:
        """Find best matching transition from current state for given symbol."""
        # Exact match first
        for t in self.transitions:
            if t.from_state == current_state and t.symbol == symbol:
                return t
        # ANY match (catch-all)
        for t in self.transitions:
            if t.from_state == current_state and t.symbol == "ANY":
                return t
        return None

    def compute_score(self, url: str) -> WFAResult:
        """
        Run WFA on the URL and compute weighted malicious score.
        Returns WFAResult with path, transitions, and score.
        """
        tokens = self.tokenize_url(url)
        current_state = self.INITIAL_STATE
        path = [current_state]
        transitions_taken = []
        accumulated_weight = self.state_weights[current_state]
        triggered_patterns = []

        for symbol, raw_value in tokens:
            if current_state == "Q8":
                break

            transition = self._find_transition(current_state, symbol)
            if transition:
                accumulated_weight += transition.weight
                current_state = transition.to_state
                path.append(current_state)
                accumulated_weight += self.state_weights[current_state]
                transitions_taken.append({
                    "from": transition.from_state,
                    "to": transition.to_state,
                    "symbol": symbol,
                    "raw_value": raw_value[:50],  # Truncate for display
                    "weight": round(transition.weight, 4),
                    "description": transition.description,
                })
                if transition.weight > 0.3:
                    triggered_patterns.append(transition.description)

        # Normalize using sigmoid
        raw_score = accumulated_weight
        normalized_score = 1 / (1 + math.exp(-raw_score + 1.5))

        return WFAResult(
            path=path,
            transitions_taken=transitions_taken,
            raw_score=round(raw_score, 4),
            normalized_score=round(normalized_score, 4),
            triggered_patterns=list(set(triggered_patterns)),
            final_state=current_state,
        )


# Singleton instance
_wfa_instance: Optional[WeightedFiniteAutomaton] = None


def get_wfa(feature_weights: Optional[Dict[str, float]] = None) -> WeightedFiniteAutomaton:
    global _wfa_instance
    if _wfa_instance is None or feature_weights:
        _wfa_instance = WeightedFiniteAutomaton(feature_weights)
    return _wfa_instance
