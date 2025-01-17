import unittest

from webpush import WebPush, WebPushException
from webpush.vapid import VAPID


class ValidatedWebpush(unittest.TestCase):
    def test_webpush_init(self) -> None:
        private_key, public_key, _ = VAPID.generate_keys()

        wp = WebPush(
            private_key=private_key,
            public_key=public_key,
            subscriber="administrator@mail.com",
            ttl=10,
            expiration=100,
        )

        print(wp)

        self.assertIsInstance(wp, WebPush)

    def test_incorrect_ttl(self) -> None:
        private_key, public_key, _ = VAPID.generate_keys()

        with self.assertRaises(WebPushException):
            WebPush(
                private_key=private_key,
                public_key=public_key,
                subscriber="admin@mail.com",
                ttl=-1,
            )

    def test_incorrect_expiration(self) -> None:
        private_key, public_key, _ = VAPID.generate_keys()

        with self.assertRaises(WebPushException):
            WebPush(
                private_key=private_key,
                public_key=public_key,
                subscriber="admin@mail.com",
                expiration=-1,
            )

        with self.assertRaises(WebPushException):
            WebPush(
                private_key=private_key,
                public_key=public_key,
                subscriber="admin@mail.com",
                expiration=24 * 61 * 61,
            )
