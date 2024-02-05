import time
from base64 import urlsafe_b64encode
from pathlib import Path
import io

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

    def __init__(self, private_key: str | Path | io.StringIO | io.BytesIO, public_key: str | Path | io.BytesIO) -> None:


        # Load the private key
        if isinstance(private_key, io.BytesIO) or isinstance(private_key, io.StringIO):
            self.private_key = private_key.read()
        else:
            private_key_path = Path(private_key)

            if not private_key_path.expanduser().exists():
                raise VAPIDException("Private key file doesn't exists")

            with open(private_key_path) as fd:
                self.private_key = fd.read()

        # Load the public key
        if isinstance(private_key, io.BytesIO):
            public_key_bytes = public_key.read()
            self.public_key = serialization.load_pem_public_key(public_key_bytes)
        else:
            public_key_path = Path(public_key)

            if not public_key_path.expanduser().exists():
                raise VAPIDException("Public key file doesn't exists")

            with open(public_key_path, "rb") as fd:
                self.public_key = serialization.load_pem_public_key(fd.read())

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
                Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
            ),
            public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
            VAPID.get_application_server_key(public_key),
        )
