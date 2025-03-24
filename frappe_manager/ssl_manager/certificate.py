from pydantic import BaseModel, Field, model_validator
from typing import List, Optional
from pathlib import Path
from frappe_manager.ssl_manager import SUPPORTED_SSL_TYPES
from frappe_manager.utils.site import is_wildcard_fqdn


class SSLCertificate(BaseModel):
    domain: str
    ssl_type: SUPPORTED_SSL_TYPES
    hsts: str = 'off'
    alias_domains: List[str] = []
    cert_path: Optional[Path] = Field(None, description="Path to local SSL certificate")
    key_path: Optional[Path] = Field(None, description="Path to local SSL key")
    toml_exclude: Optional[set] = {'domain', 'alias_domains', 'toml_exclude', 'cert_path', 'key_path'}

    @model_validator(mode='after')
    def validate_local_cert_paths(self):
        if self.ssl_type == SUPPORTED_SSL_TYPES.local:
            if not self.cert_path or not self.key_path:
                raise ValueError("cert_path and key_path are required for local SSL")
            if not self.cert_path.exists() or not self.key_path.exists():
                raise ValueError("SSL certificate or key file not found")
        return self

    @property
    def has_wildcard(self) -> bool:
        return any(is_wildcard_fqdn(domain) for domain in self.alias_domains)
