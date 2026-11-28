# Root key ceremony: guide for key holders

For the five holders of the Gravit Verifier registry root keys. Procedure: `root-key-custody.md`.
About 30 minutes on the day. No call is needed; everything is done in writing.

## What you hold and why

You hold one of five keys. A registry of verifiers is valid only when three of the five holders have signed it,
so no one alone, including the Foundation, can add a verifier. Your private key is created on your own device
and never leaves it. You send only two small files: your public key and one signature.

## Before the day

1. You have signed the one-page acceptance of the procedure.
2. You have received your hardware device (a YubiKey 5 with firmware 5.7 or newer), or you use the fallback
   below if your device cannot make plain Ed25519 signatures. The dry run on 3 December 2026 settles this.
3. Have a computer you trust. For the fallback it must be a computer you can keep offline.

## On the day: the maintainer sends you one file

`challenge.bin`, and by a second channel (SMS or phone message) its SHA-256. The file holds one line:
`gravit-root-key-v1 <your name> <date>`.

Check that the SHA-256 of the file you received is the one sent by the second channel:

    shasum -a 256 challenge.bin        # macOS, Linux
    certutil -hashfile challenge.bin SHA256    # Windows

If the two differ, stop and tell the maintainer.

## Path A: hardware device

The exact commands for the YubiKey are fixed after the dry run of 3 December 2026 and sent with your device.
In short: the device creates an Ed25519 key in its own memory, shows you the public key, and signs
`challenge.bin` exactly as it is (no hashing, no wrapper). You send `pub.pem` and `sig.bin`.

## Path B: fallback on an offline computer

Use this only if the maintainer tells you so. You need Python 3.10 or newer and a copy of this repository,
brought to the computer before you take it offline.

    pip install -e .                 # once, while still online
    # now disconnect the computer from every network
    python tools/ceremony.py keygen --out root-key.pem --public pub.pem
    python tools/ceremony.py sign --key root-key.pem --in challenge.bin --out sig.bin

`keygen` asks for a passphrase of at least 12 characters, twice. Only you know it; nobody can recover it.
It writes `root-key.pem` (your private key, encrypted with the passphrase) and `pub.pem` (your public key).
It never overwrites an existing key.

Keep `root-key.pem` on that computer and one backup on a USB stick stored in another place. Never send it,
never put it in a cloud folder, never email it.

## What you send

Only `pub.pem` and `sig.bin`, by email to the maintainer. Two other holders then check your proof:

    python tools/ceremony.py verify --holder "<your name>" --date <date> --public-key pub.pem --signature sig.bin

Your public key goes into `registry/ROOT_KEYS.md` and `registry/trust_root.json` through a reviewed pull request.
Your name is not published.

## Later: signing a registry

When the registry changes, you get the change to look at, the file to sign and its SHA-256 by a second channel.
Sign it only after you have looked at the change yourself and the SHA-256 matches. With the fallback:

    python tools/ceremony.py sign --key root-key.pem --in to-sign.bin --out sig.bin

## If something goes wrong

- Device or backup lost, or passphrase forgotten: tell the maintainer. Your key is replaced; the other four
  keep the registry working (three of five suffice).
- Someone asks you for your private key, passphrase or to sign without showing you the change: refuse and
  tell the maintainer. Nobody from the Foundation will ever ask for them.
