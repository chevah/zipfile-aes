# zipfile-aes

Extend stdlib zipfile to support [WinZip AES](https://www.winzip.com/en/support/aes-encryption/) encryption.

This is an alternative to [pyzipper](https://github.com/danifus/pyzipper),
with the difference that *zipfile-aes* uses the [cryptography](https://github.com/pyca/cryptography/) library.
The code from here is based on pyzipper.

This code can't be included in Python `stdlib` since there is no `crypto` support.
The [stdlib ssl](https://docs.python.org/3/library/ssl.html) library only exposes the TLS part.

Supported operations (check the automated tests for details):
 * WinZIP AES V2 and V1 read without seek.


# Contribution

Setup Python and uv

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install uv
uv sync
uv pip install -e .[dev]
uv run patch_zipfile.py
```

Use dev tools

```sh
uv run pytest
uv run ruff format .
uv run ruff check
```
