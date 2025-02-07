import ssl
import warnings
import contextlib
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.utils import CryptographyDeprecationWarning


# Suppress specific warnings for cleaner output
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


class SSLCert:
    """
    A class to fetch and parse SSL certificates from a given host and port.
    """

    def __init__(self, host: str, port: int) -> None:
        """
        Initialize the SSLCert class with the target host and port.

        :param host: The hostname or IP address of the target server.
        :param port: The port number to connect to (typically 443 for HTTPS).
        """

        self.addr = (host, port)  # Tuple representing the target address
        self.certificate = None  # Holds the fetched certificate object
        self.parsed_certificate = {}  # Dictionary to store parsed certificate details

    def scan(self) -> dict | None:
        """
        Fetch and parse the SSL certificate from the server.

        :return: A dictionary containing parsed certificate details, or None if fetching fails.
        """

        self.pem()  # Fetch the certificate in PEM format
        if self.certificate:
            self.parse()  # Parse the certificate details
            return self.parsed_certificate if self.parsed_certificate else None

    def pem(self) -> None:
        """
        Retrieve the SSL certificate from the server in PEM format and store it.
        """

        pem_data = None
        with contextlib.suppress(Exception):
            pem_data = ssl.get_server_certificate(self.addr, timeout=7.50)
        if pem_data:
            pem_byte = bytes(pem_data, "utf-8")
            self.certificate = x509.load_pem_x509_certificate(pem_byte, default_backend())

    def parse(self) -> None:
        """
        Extract and structure relevant details from the fetched SSL certificate.
        """

        if self.certificate:
            self.parsed_certificate["version"] = {
                "name": self.certificate.version.name,
                "value": self.certificate.version.value,
            }
            self.parsed_certificate["serial"] = self.certificate.serial_number
            self.parsed_certificate["expiration"] = {
                "not_valid_before": datetime.isoformat(self.certificate.not_valid_before),
                "not_valid_after": datetime.isoformat(self.certificate.not_valid_after),
            }
            self.parsed_certificate["subject"] = {attr.oid._name: attr.value for attr in self.certificate.subject}
            self.parsed_certificate["issuer"] = {attr.oid._name: attr.value for attr in self.certificate.issuer}
            self.parsed_certificate["signature_algorithm"] = self.certificate.signature_algorithm_oid._name
            self.parsed_certificate["fingerprints"] = {
                "SHA256": self.certificate.fingerprint(hashes.SHA256()).hex(":"),
                "SHA1": self.certificate.fingerprint(hashes.SHA1()).hex(":"),
            }
            self.parsed_certificate["public_key"] = str(
                self.certificate.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            extensions = SSLCert.extensions(self.certificate.extensions)
            if extensions:
                self.parsed_certificate["extensions"] = extensions

    @staticmethod
    def extensions(extensions: x509.Extensions) -> dict:
        """
        Extract SSL certificate extensions and return them in a structured dictionary.

        :param extensions: The extensions object from an x509 certificate.
        :return: A dictionary containing relevant extension details.
        """

        extracted_ext = {}
        for ext in extensions:
            match type(ext.value):
                case x509.KeyUsage:
                    extracted_ext[ext.value.oid.dotted_string] = {
                        "digital_signature": ext.value.digital_signature,
                        "content_commitment": ext.value.content_commitment,
                        "key_encipherment": ext.value.key_encipherment,
                        "data_encipherment": ext.value.data_encipherment,
                        "key_agreement": ext.value.key_agreement,
                        "key_cert_sign": ext.value.key_cert_sign,
                        "crl_sign": ext.value.crl_sign,
                        "encipher_only": ext.value.encipher_only if ext.value.key_agreement else None,
                        "decipher_only": ext.value.decipher_only if ext.value.key_agreement else None,
                    }
                case x509.ExtendedKeyUsage:
                    extracted_ext[ext.value.oid.dotted_string] = {oid._name: oid.dotted_string for oid in ext.value}
                case x509.BasicConstraints:
                    extracted_ext[ext.value.oid.dotted_string] = {
                        "ca": ext.value.ca,
                        "path_length": ext.value.path_length,
                    }
                case x509.SubjectKeyIdentifier:
                    extracted_ext[ext.value.oid.dotted_string] = {"digest": ext.value.digest.hex()}
                case x509.AuthorityKeyIdentifier:
                    extracted_ext[ext.value.oid.dotted_string] = {
                        "key_identifier": ext.value.key_identifier.hex(),
                        "authority_cert_issuer": str(ext.value.authority_cert_issuer),
                        "authority_cert_serial_number": ext.value.authority_cert_serial_number,
                    }
                case x509.AuthorityInformationAccess:
                    extracted_ext[ext.value.oid.dotted_string] = [
                        {
                            "access_method": item.access_method.dotted_string,
                            "access_location": item.access_location.value,
                        }
                        for item in ext.value
                    ]
                case x509.SubjectAlternativeName:
                    extracted_ext[ext.value.oid.dotted_string] = {
                        "dns_names": ext.value.get_values_for_type(x509.DNSName)
                    }
                case x509.CertificatePolicies:
                    extracted_ext[ext.value.oid.dotted_string] = [
                        {"policy_identifier": p.policy_identifier.dotted_string} for p in ext.value
                    ]
                case x509.PrecertificateSignedCertificateTimestamps:
                    extracted_ext[ext.value.oid.dotted_string] = [
                        {"log_id": sct.log_id.hex(), "timestamp": sct.timestamp.__str__()} for sct in ext.value
                    ]
                case _:
                    extracted_ext[ext.value.oid.dotted_string] = str(ext.value)
        return extracted_ext
