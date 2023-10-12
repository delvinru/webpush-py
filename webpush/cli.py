#!/usr/bin/env python3

from webpush.vapid import VAPID

def main():
    private_key, public_key = VAPID.generate_keys()
    with open("private_key.pem", "wb") as fd:
        fd.write(private_key)

    with open("public_key.pem", "wb") as fd:
        fd.write(public_key)

    print("keys saved in private_key.pem and public_key.pem")
