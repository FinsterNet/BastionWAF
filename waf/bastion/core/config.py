"""
Declarative Configuration Manager for BastionWAF.
Loads, validates, and manages settings from bastion.yaml with environment variable support.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    timeout_seconds: float = 10.0


@dataclass
class OpenSearchBufferConfig:
    batch_size: int = 50
    flush_interval_seconds: float = 2.0
    fallback_log_path: str = "logs/bastion_events.jsonl"


@dataclass
class OpenSearchAuthConfig:
    username: str = ""
    password: str = ""


@dataclass
class OpenSearchConfig:
    enabled: bool = True
    hosts: List[str] = field(default_factory=lambda: ["http://127.0.0.1:9200"])
    index_prefix: str = "bastion-waf-events"
    ssl_verify: bool = False
    auth: OpenSearchAuthConfig = field(default_factory=OpenSearchAuthConfig)
    buffer: OpenSearchBufferConfig = field(default_factory=OpenSearchBufferConfig)


@dataclass
class SiteConfig:
    domain: str
    upstream: str
    defense_mode: bool = True


@dataclass
class PolicyConfig:
    block_threshold: float = 5.0
    challenge_threshold: float = 2.5
    shadow_mode: bool = False
    rule_weight: float = 0.6
    semantic_weight: float = 0.4


@dataclass
class RulesConfig:
    disabled_rules: List[str] = field(default_factory=list)


@dataclass
class BastionConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    opensearch: OpenSearchConfig = field(default_factory=OpenSearchConfig)
    sites: List[SiteConfig] = field(default_factory=list)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)

    def get_site(self, host: str) -> Optional[SiteConfig]:
        """Match incoming Host header against configured sites."""
        if not host:
            return None
        cleaned_host = host.split(":")[0].lower()
        for site in self.sites:
            domain = site.domain.lower()
            if domain == cleaned_host or domain in cleaned_host or cleaned_host in domain:
                return site
        return None

    def resolve_upstream(self, host: str) -> Tuple[Optional[str], bool]:
        """Returns (upstream_url, defense_mode) for host."""
        site = self.get_site(host)
        if site:
            target = site.upstream if site.upstream.startswith("http") else f"http://{site.upstream}"
            return target, site.defense_mode
        return None, True

    def get_disabled_rules(self) -> List[str]:
        return list(self.rules.disabled_rules)


_CONFIG_INSTANCE: Optional[BastionConfig] = None


def find_config_path() -> Path:
    """Find bastion.yaml in standard locations or via BASTION_CONFIG env."""
    env_path = os.environ.get("BASTION_CONFIG")
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    # Search up relative to this file
    base_dir = Path(__file__).resolve().parent.parent.parent
    candidate_paths = [
        base_dir / "config" / "bastion.yaml",
        base_dir / "config" / "bastion.yml",
        Path.cwd() / "config" / "bastion.yaml",
        Path.cwd() / "bastion.yaml",
    ]
    for p in candidate_paths:
        if p.is_file():
            return p
    return base_dir / "config" / "bastion.yaml"


def load_config(config_path: Optional[Path] = None, set_global: bool = True) -> BastionConfig:
    """Load and parse bastion.yaml into strongly-typed BastionConfig."""
    global _CONFIG_INSTANCE
    path = config_path or find_config_path()

    if not path.is_file():
        # Fallback to default config
        cfg = BastionConfig()
        if set_global:
            _CONFIG_INSTANCE = cfg
        return cfg

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}
    except Exception:
        raw_data = {}

    server_data = raw_data.get("server", {})
    server = ServerConfig(
        host=os.environ.get("BASTION_HOST", server_data.get("host", "0.0.0.0")),
        port=int(os.environ.get("PORT", os.environ.get("BASTION_PORT", server_data.get("port", 8080)))),
        timeout_seconds=float(server_data.get("timeout_seconds", 10.0)),
    )

    os_data = raw_data.get("opensearch", {})
    buf_data = os_data.get("buffer", {})
    auth_data = os_data.get("auth", {})
    opensearch = OpenSearchConfig(
        enabled=bool(os_data.get("enabled", True)),
        hosts=os_data.get("hosts", ["http://127.0.0.1:9200"]),
        index_prefix=os_data.get("index_prefix", "bastion-waf-events"),
        ssl_verify=bool(os_data.get("ssl_verify", False)),
        auth=OpenSearchAuthConfig(
            username=os.environ.get("OPENSEARCH_USERNAME", auth_data.get("username", "")),
            password=os.environ.get("OPENSEARCH_PASSWORD", auth_data.get("password", "")),
        ),
        buffer=OpenSearchBufferConfig(
            batch_size=int(buf_data.get("batch_size", 50)),
            flush_interval_seconds=float(buf_data.get("flush_interval_seconds", 2.0)),
            fallback_log_path=buf_data.get("fallback_log_path", "logs/bastion_events.jsonl"),
        ),
    )

    sites_list: List[SiteConfig] = []
    for s in raw_data.get("sites", []):
        if isinstance(s, dict) and "domain" in s and "upstream" in s:
            sites_list.append(
                SiteConfig(
                    domain=str(s["domain"]),
                    upstream=str(s["upstream"]),
                    defense_mode=bool(s.get("defense_mode", True)),
                )
            )

    policy_data = raw_data.get("policy", {})
    policy = PolicyConfig(
        block_threshold=float(policy_data.get("block_threshold", 5.0)),
        challenge_threshold=float(policy_data.get("challenge_threshold", 2.5)),
        shadow_mode=bool(policy_data.get("shadow_mode", False)),
        rule_weight=float(policy_data.get("rule_weight", 0.6)),
        semantic_weight=float(policy_data.get("semantic_weight", 0.4)),
    )

    rules_data = raw_data.get("rules", {})
    rules = RulesConfig(
        disabled_rules=[str(r) for r in rules_data.get("disabled_rules", [])],
    )

    loaded_cfg = BastionConfig(
        server=server,
        opensearch=opensearch,
        sites=sites_list,
        policy=policy,
        rules=rules,
    )
    if set_global:
        _CONFIG_INSTANCE = loaded_cfg
    return loaded_cfg


def reset_config():
    """Reset cached global configuration to None so it reloads on next access."""
    global _CONFIG_INSTANCE
    _CONFIG_INSTANCE = None


def get_config() -> BastionConfig:
    """Return currently active or cached BastionConfig."""
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        _CONFIG_INSTANCE = load_config()
    return _CONFIG_INSTANCE
