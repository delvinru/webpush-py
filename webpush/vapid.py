import time
from base64 import urlsafe_b64encode
from io import BytesIO, StringIO
from pathlib import Path

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import AnyHttpUrl, EmailStr


class VAPIDException(Exception):
    pass


class VAPID:
    """
    VAPID (Voluntary Application Server Identification)
    """

    def __init__(
        self,
        private_key: bytes | Path | BytesIO | StringIO,
        public_key: bytes | Path | BytesIO,
    ) -> None:
        # Load the private key
        match private_key:
            case BytesIO() | StringIO():
                self.private_key = private_key.read()
            case Path():
                if not private_key.expanduser().exists():
                    raise VAPIDException("Private key file doesn't exists")
                self.private_key = private_key.read_text()
            case bytes():
                self.private_key = private_key
            case _:
                raise VAPIDException(f"Unsupported private key type: {type(private_key)}")

        # Load the public key
        public_key_data = b""
        match public_key:
            case BytesIO():
                public_key_data = public_key.read()
            case Path():
                if not public_key.expanduser().exists():
                    raise VAPIDException("Public key file doesn't exists")
                public_key_data = public_key.read_bytes()
            case bytes():
                public_key_data = public_key
            case _:
                raise VAPIDException(f"Unsupported public key type: {type(public_key)}")

        self.public_key = serialization.load_pem_public_key(public_key_data)

    def get_authorization_header(self, endpoint: AnyHttpUrl, subscriber: EmailStr, expiration: int) -> str:
        """
        :param endpoint from subscribtion info
        :param subscriber email for response in vapid
        :param expiration value

        :return vapid authorization header
        """

        token = jwt.encode(
            payload={
                "aud": f"{endpoint.scheme}://{endpoint.host}",
                "exp": int(time.time()) + expiration,
                "sub": f"mailto:{subscriber}",
            },
            key=self.private_key,
            algorithm="ES256",
        )
        public_key = self.get_application_server_key(self.public_key)
        return f"vapid t={token}, k={public_key}"

    @staticmethod
    def _encode_vapid_key(key: bytes) -> str:
        return urlsafe_b64encode(key).replace(b"=", b"").decode()

    @staticmethod
    def get_application_server_key(public_key: PublicKeyTypes) -> str:
        return VAPID._encode_vapid_key(
            public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        )

    @staticmethod
    def generate_keys() -> tuple[bytes, bytes, str]:
        """
        Generate private/public keys in PEM format and application server key
        """

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return (
            private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            ),
            public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
            VAPID.get_application_server_key(public_key),
        )
