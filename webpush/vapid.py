import time
from base64 import urlsafe_b64encode
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from pydantic import AnyHttpUrl, EmailStr


class VAPIDException(Exception):
    pass


class VAPID:
    """
    VAPID (Voluntary Application Server Identification)
    """

    def __init__(self, private_key: Path, public_key: Path) -> None:
        if not private_key.expanduser().exists():
            raise VAPIDException("Private key file doesn't exists")

        if not public_key.expanduser().exists():
            raise VAPIDException("Public key file doesn't exists")

        with open(private_key) as fd:
            self.private_key = fd.read()

        with open(public_key, "rb") as fd:
            self.public_key = serialization.load_pem_public_key(fd.read())

    def get_authorization_header(
        self, endpoint: AnyHttpUrl, subscriber: EmailStr, expiration: int
    ) -> str:
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
        public_key = self._encode_vapid_key(
            self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        )
        return f"vapid t={token}, k={public_key}"

    def _encode_vapid_key(self, key: bytes) -> str:
        return urlsafe_b64encode(key).replace(b"=", b"").decode()
