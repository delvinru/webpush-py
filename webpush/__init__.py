import json
import os
import struct
from base64 import urlsafe_b64decode
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import EmailStr

from webpush.types import WebPushMessage, WebPushSubscription
from webpush.vapid import VAPID


class WebPushException(Exception):
    pass


class WebPush:
    """
    Helper class for generating WebPush message
    """

    def __init__(
        self,
        private_key: str | Path,
        public_key: str | Path,
        subscriber: EmailStr | None = None,
        ttl: int = 0,
        expiration: int = 12 * 60 * 60,
    ) -> None:
        """
        :param private_key - file with private VAPID key
        :param public_key - file with public VAPID key
        :param subscriber - (global) email address require for VAPID
        :param ttl - (global) lifespan of a web push message in seconds
        :param expiration - (global) time after which the token expires
            value must not be more than 24 hours from the of the request
        """
        self.vapid = VAPID(private_key=private_key, public_key=public_key)
        self.max_resord_size = 4096

        if ttl < 0:
            raise WebPushException("Invalid ttl value")

        if expiration < 0 or expiration > 24 * 60 * 60:
            raise WebPushException("Invalid expiration value")

        self.ttl = ttl
        self.expiration = expiration
        self.subscriber = subscriber or ""

    def get(
        self,
        message: bytes | str | dict,
        subscription: WebPushSubscription,
        subscriber: EmailStr | None = None,
        ttl: int | None = None,
        expiration: int | None = None,
    ) -> WebPushMessage:
        """
        :param message - the message to be sent
        :param subscription - subscription info from web
        :param subscriber - email address required for VAPID
        :param ttl - (Time To Live) lifespan of a web push message in seconds
            0 - message will be delivered only if the device is reacheable immediately
        :param expiration - time after which the token expires
            value must not be more than 24 hours from the of the request

        :return ready message to be sent
        """
        data: bytes
        match message:
            case bytes():
                data = message
            case str():
                data = message.encode()
            case dict():
                data = json.dumps(message).encode()
            case _:
                raise WebPushException("Unsupported type for sending message")

        if subscriber:
            self.subscriber = subscriber
        else:
            if not self.subscriber:
                raise WebPushException("Subscriber email required")

        if ttl:
            if ttl < 0:
                raise WebPushException("Invalid ttl value")
            self.ttl = ttl

        if expiration:
            if expiration < 0 or expiration > 24 * 60 * 60:
                raise WebPushException("Invalid expiration value")
            self.expiration = expiration

        encrypted = self._encrypt(data, subscription)
        authorization = self.vapid.get_authorization_header(
            endpoint=subscription.endpoint,
            subscriber=self.subscriber,
            expiration=self.expiration,
        )
        return WebPushMessage(
            encrypted=encrypted,
            headers={
                "ttl": str(self.ttl),
                "content-encoding": "aes128gcm",
                "authorization": authorization,
            },
        )

    def _encrypt(self, message: bytes, subscription: WebPushSubscription) -> bytes:
        def _derive_key() -> tuple[bytes, bytes]:
            """
            helper function for derive keys from diffie hellman
            """
            hkdf_auth = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=auth_secret,
                info=context,
                backend=default_backend(),
            )
            hkdf_secret = hkdf_auth.derive(secret)
            hkdf_key = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=salt,
                info=keyinfo,
                backend=default_backend(),
            )
            hkdf_nonce = HKDF(
                algorithm=hashes.SHA256(),
                length=12,
                salt=salt,
                info=nonceinfo,
                backend=default_backend(),
            )
            return (hkdf_key.derive(hkdf_secret), hkdf_nonce.derive(hkdf_secret))

        # Authentication secret
        auth_secret = self._decode_subscription_key(subscription.keys.auth)

        # dh (Diffie Hellman)
        dh = self._decode_subscription_key(subscription.keys.p256dh)

        # Generate random salt
        salt = os.urandom(16)

        # Local keys
        local_server_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        local_public_key = local_server_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dh)

        context = b"WebPush: info\x00" + dh + local_public_key
        keyinfo = b"Content-Encoding: aes128gcm\x00"
        nonceinfo = b"Content-Encoding: nonce\x00"

        secret = local_server_key.exchange(ec.ECDH(), pubkey)
        hkdf_key, hkdf_nonce = _derive_key()

        # RFC8291 require add '\0x02' byte to end of message
        data = message + b"\x02"
        cipher = AESGCM(hkdf_key)
        ciphertext = cipher.encrypt(hkdf_nonce, data, associated_data=None)

        # craft encrypted message
        header = salt
        header += struct.pack("!L", self.max_resord_size)
        header += struct.pack("!B", len(local_public_key))
        header += local_public_key
        header += ciphertext

        return header

    def _decode_subscription_key(self, key: str) -> bytes:
        if (rem := len(key) % 4) != 0:
            key += "=" * (4 - rem)
        return urlsafe_b64decode(key)
