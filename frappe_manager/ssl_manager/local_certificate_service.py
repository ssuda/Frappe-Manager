from pathlib import Path
from frappe_manager.ssl_manager import SUPPORTED_SSL_TYPES
from frappe_manager.ssl_manager.ssl_certificate_service import SSLCertificateService
from frappe_manager.ssl_manager.certificate_exceptions import SSLCertificateNotFoundError

class LocalCertificateService(SSLCertificateService):
    def __init__(self, ssl_service_dir: Path):
        self.root_dir = ssl_service_dir / SUPPORTED_SSL_TYPES.local.value

    def generate_certificate(self, certificate):
        cert_path = certificate.cert_path
        key_path = certificate.key_path
        
        self.root_dir.mkdir(parents=True)

        if not cert_path.exists() or not key_path.exists():
            raise SSLCertificateNotFoundError(f"Local certificate files not found: {cert_path} {key_path}")

        # Copy certificates to SSL directory
        target_cert = self.root_dir / f'{certificate.domain}.crt'
        target_key = self.root_dir / f'{certificate.domain}.key'

        target_cert.write_text(cert_path.read_text())
        target_key.write_text(key_path.read_text())
        
        return target_key, target_cert

    def renew_certificate(self, certificate):
        # No-op for local certificates
        pass

    def remove_certificate(self, certificate):
        # Clean up certificate files
        cert_file = self.root_dir / f'{certificate.domain}.crt'
        key_file = self.root_dir / f'{certificate.domain}.key'
        
        cert_file.unlink(missing_ok=True)
        key_file.unlink(missing_ok=True)