from bastion.core.normalizer import normalize_request, repeated_url_decode, strip_null_bytes


def test_repeated_url_decode_single_pass():
    assert repeated_url_decode("admin%27%20OR") == "admin' OR"


def test_repeated_url_decode_handles_double_encoding():
    assert repeated_url_decode("%2527") == "'"


def test_repeated_url_decode_stable_input_unchanged():
    assert repeated_url_decode("clean text 123") == "clean text 123"


def test_strip_null_bytes():
    assert strip_null_bytes("file.php\x00.jpg") == "file.php.jpg"


def test_normalize_request_parses_query_params():
    req = normalize_request(
        method="get",
        path="/search",
        query_string="q=admin%27--&category=books",
    )
    assert req.method == "GET"
    assert req.path == "/search"
    assert req.query_params["q"] == ["admin'--"]
    assert req.query_params["category"] == ["books"]


def test_normalize_request_lowercases_header_keys():
    req = normalize_request(
        method="post",
        path="/login",
        headers={"User-Agent": "Mozilla/5.0", "X-Custom-Header": "Test"},
    )
    assert "user-agent" in req.headers
    assert "x-custom-header" in req.headers


def test_normalize_request_decodes_form_body():
    req = normalize_request(
        method="POST",
        path="/login",
        body=b"username=admin%27+OR+%271%27%3D%271&password=pass",
    )
    assert "admin' OR '1'='1" in req.body
