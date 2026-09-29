"""
Unit Tests for Multi-Stage Request Normalization Layer (Layer 1 Spec).
"""

from bastion.core.normalizer import (
    is_valid_base64_payload,
    normalize_request,
    recursive_normalize,
    single_pass_decode,
)


def test_recursive_url_decoding_loop():
    # Double-encoded SELECT: %2553%2545%254C%2545%2543%2554 -> SELECT
    double_encoded = "%2553%2545%254C%2545%2543%2554"
    res = recursive_normalize(double_encoded)
    assert res == "SELECT"

    # Triple-encoded payload
    triple_encoded = "%25252e%25252e%25252f"
    res_lfi = recursive_normalize(triple_encoded)
    assert res_lfi == "../"


def test_html_entity_decoding():
    html_ent = "&#83;&#69;&#76;&#69;&#67;&#84; * &#70;&#82;&#79;&#77; users"
    res = recursive_normalize(html_ent)
    assert "SELECT * FROM users" in res


def test_base64_detection_and_validation():
    # Valid base64 printable attack snippet: alert(1) -> YWxlcnQoMSk=
    b64_str = "YWxlcnQoMSk="
    decoded = is_valid_base64_payload(b64_str)
    assert decoded == "alert(1)"

    # Invalid / random non-base64 or non-printable binary should not decode
    invalid_b64 = "notbase64!!!"
    assert is_valid_base64_payload(invalid_b64) is None


def test_unicode_nfkc_normalization():
    # Full-width Unicode characters: ＳＥＬＥＣＴ -> SELECT
    full_width = "ＳＥＬＥＣＴ * ＦＲＯＭ users"
    res = recursive_normalize(full_width)
    assert "SELECT * FROM users" in res


def test_comment_and_whitespace_stripping():
    # SQL comment split: UNI/**/ON SEL/**/ECT
    comment_split = "UNI/**/ON /*!50000SELECT*/ 1,2,3"
    res = recursive_normalize(comment_split)
    assert "UNION SELECT 1,2,3" in res


def test_null_byte_and_control_char_removal():
    # Null byte truncation evasion: ../../../../etc/passwd%00.jpg
    null_byte_str = "../../../../etc/passwd\x00.jpg"
    res = recursive_normalize(null_byte_str)
    assert "\x00" not in res
    assert "../../../../etc/passwd.jpg" in res


def test_dual_raw_and_normalized_retention():
    raw_query = "q=%2553%2545%254C%2545%2543%2554%201"
    req = normalize_request(
        method="GET",
        path="/search",
        query_string=raw_query,
        headers={"User-Agent": "Bastion%20Tester"},
        body=b"payload=UNI/**/ON%20SELECT",
        client_ip="192.168.1.50",
    )

    # Check normalized values
    norm_values = dict(req.iter_values())
    assert norm_values["query:q"] == "SELECT 1"
    assert norm_values["body"] == "payload=UNION SELECT"

    # Check that original raw strings were preserved
    raw_values = dict(req.iter_raw_values())
    assert raw_values["query:q"] == "%2553%2545%254C%2545%2543%2554%201"
    assert raw_values["body"] == "payload=UNI/**/ON%20SELECT"
