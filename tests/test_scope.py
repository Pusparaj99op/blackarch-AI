from blackarch_ai_mcp.scope import ScopeConfig, ScopeTarget, is_authorized


def _config(**target_kwargs) -> ScopeConfig:
    defaults = {"host": None, "cidr": None, "authorized_by": "tester", "authorization_ref": "ref", "expires": None}
    defaults.update(target_kwargs)
    return ScopeConfig(targets=(ScopeTarget(**defaults),))


def test_empty_scope_refuses():
    authorized, reason = is_authorized("127.0.0.1", ScopeConfig(targets=()))
    assert authorized is False
    assert "no targets defined" in reason


def test_exact_host_match_authorizes():
    config = _config(host="127.0.0.1")
    authorized, _ = is_authorized("127.0.0.1", config)
    assert authorized is True


def test_non_matching_host_refuses():
    config = _config(host="127.0.0.1")
    authorized, reason = is_authorized("10.0.0.1", config)
    assert authorized is False
    assert "does not match" in reason


def test_cidr_match_authorizes():
    config = _config(cidr="192.168.56.0/24")
    authorized, _ = is_authorized("192.168.56.10", config)
    assert authorized is True


def test_cidr_outside_range_refuses():
    config = _config(cidr="192.168.56.0/24")
    authorized, _ = is_authorized("192.168.57.10", config)
    assert authorized is False


def test_expired_authorization_refuses():
    config = _config(host="127.0.0.1", expires="2000-01-01")
    authorized, reason = is_authorized("127.0.0.1", config)
    assert authorized is False
    assert "expired" in reason


def test_future_expiry_authorizes():
    config = _config(host="127.0.0.1", expires="2999-01-01")
    authorized, _ = is_authorized("127.0.0.1", config)
    assert authorized is True


def test_unparseable_expiry_fails_closed():
    config = _config(host="127.0.0.1", expires="not-a-date")
    authorized, _ = is_authorized("127.0.0.1", config)
    assert authorized is False
