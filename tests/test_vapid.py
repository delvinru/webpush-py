import io
import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile

from pydantic import AnyHttpUrl

from webpush.vapid import VAPID, VAPIDException


class ValidateVAPID(unittest.TestCase):
    def test_key_generation(self) -> None:
        private_key, public_key, application_server_key = VAPID.generate_keys()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(application_server_key)

    def test_non_existing_files(self) -> None:
        with self.assertRaises(VAPIDException):
            VAPID(Path("/non-existing-file-2"), Path("/non-existing-file-2"))

    def test_get_authorization_header(self) -> None:
        private_key, public_key, _ = VAPID.generate_keys()
        # some dirty hacks but ok
        private_fd, public_fd = NamedTemporaryFile(mode="wb"), NamedTemporaryFile(mode="wb")
        private_fd.write(private_key)
        private_fd.flush()
        public_fd.write(public_key)
        public_fd.flush()

        vapid = VAPID(private_key=Path(private_fd.name), public_key=Path(public_fd.name))
        header = vapid.get_authorization_header(
            endpoint=AnyHttpUrl("http://google.com"),
            subscriber="test@mail.com",
            expiration=10,
        )

        private_fd.close()
        public_fd.close()

        self.assertIsNotNone(header)

    def test_BytesIO_keys_get_authorization_header(self) -> None:
        private_key, public_key, _ = VAPID.generate_keys()

        public_fd = io.BytesIO()
        public_fd.write(public_key)
        public_fd.seek(0)

        private_fd = io.BytesIO()
        private_fd.write(private_key)
        private_fd.seek(0)

        vapid = VAPID(private_key=private_fd, public_key=public_fd)

        header = vapid.get_authorization_header(
            endpoint=AnyHttpUrl("http://google.com"),
            subscriber="test@mail.com",
            expiration=10,
        )

        private_fd.close()
        public_fd.close()

        self.assertIsNotNone(header)

    def test_raw_strings_get_authorization_header(self) -> None:
        private_key, public_key, _ = VAPID.generate_keys()

        vapid = VAPID(private_key=private_key, public_key=public_key)

        header = vapid.get_authorization_header(
            endpoint=AnyHttpUrl("http://google.com"),
            subscriber="test@mail.com",
            expiration=10,
        )

        self.assertIsNotNone(header)
