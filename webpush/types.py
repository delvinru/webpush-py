from pydantic import AnyHttpUrl, BaseModel, Field
from typing_extensions import TypedDict


class WebPushKeys(BaseModel):
    auth: str
    p256dh: str


class WebPushSubscription(BaseModel):
    endpoint: AnyHttpUrl
    keys: WebPushKeys


# a little bit of ugly but ok
WebPushHeaders = TypedDict(
    "WebPushHeaders", {"content-encoding": str, "ttl": str, "authorization": str}
)


class WebPushMessage(BaseModel):
    encrypted: bytes
    headers: WebPushHeaders
