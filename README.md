# WebPush-Py

Simple library for working with [WebPush](https://web.dev/articles/push-notifications-web-push-protocol) in python

## Usage

### Installation

```bash
TBA
```

### Basic Usage

```python
import requests
from webpush import WebPush, WebPushSubscription

wp = WebPush(private_key="./private_key.pem", public_key="./public_key.pem")

# example subscription info
subscription = WebPushSubscription.model_validate({
    "endpoint": "https://fcm.googleapis.com/fcm/send/...",
    "keys": {
        "auth": "...",
        "p256dh": "..."
    }
})

message = wp.get(message='Hello, world!', subscription=subscription)

requests.post(subscription.endpoint, data=message.encrypted, headers=message.headers)
```

Generate VAPID keys:
```
vapid-gen
```

Private key stored in `public_key.pem` and public key saved in `public_key.pem`

### Example simple FastApi server

```python
TBA
```

## FAQ
- Why do I need another library?

The current python libraries that work with Web Push have been written for a very long time, so they do not support typing, try to support outdated encryption algorithms and pull a lot of deprecated dependencies.

- Why is only `aes128gcm` supported?

According to the [RFC8192](https://datatracker.ietf.org/doc/html/rfc8291), this is the recommended format. At the moment, all modern systems support this encryption.

- Will there be support for other encryption modes?

New, yes, but there are no old ones, for example `aesgcm`

- Who is this library for?

You need type support, you're writing a modern backend, minimum number of dependencies.

And last one, if you have ideas for improvements, bug fixes, feel free to contribute.

## Change log

- 0.1.0 - initial release

## Credits

- [pywebpush](https://github.com/web-push-libs/pywebpush)
- [http-ece](https://github.com/web-push-libs/encrypted-content-encoding)