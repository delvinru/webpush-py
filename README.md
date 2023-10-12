# WebPush-Py

Simple library for working with [WebPush](https://web.dev/articles/push-notifications-web-push-protocol) in python

## Usage

### Installation

```bash
pip install webpush
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

Generate VAPID keys and get applicationServerKey:
```
vapid-gen
```

Private key saved in `public_key.pem` and public key saved in `public_key.pem`.
Application Server Key saved in `applicationServerKey`

### simple usage with fastapi

```python
import aiohttp
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from webpush import WebPush, WebPushSubscription

app = FastAPI()

wp = WebPush(
    public_key="./public_key.pem",
    private_key="./private_key.pem",
    subscriber="admin@mail.com",
)


@app.get("/notification/key")
async def get_public_key() -> JSONResponse:
    application_server_key = "<generated from vapid-gen>"
    return JSONResponse(content={"public_key": application_server_key})


@app.post("/notification/subscribe")
async def subscribe_user(subscription: WebPushSubscription) -> JSONResponse:
    message = wp.get(message="Hello, world", subscription=subscription)
    async with aiohttp.ClientSession() as session:
        await session.post(
            url=str(subscription.endpoint),
            data=message.encrypted,
            headers=message.headers,
        )
    return JSONResponse(content={"status": "ok"})
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

- 1.0.0 - initial release

## Credits

- [pywebpush](https://github.com/web-push-libs/pywebpush)
- [http-ece](https://github.com/web-push-libs/encrypted-content-encoding)