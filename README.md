# zipfile-aes
Extend stdlib zipfile to support [WinZip AES](https://www.winzip.com/en/support/aes-encryption/) encryption.

As a side-gig, it also support generating ZIP files as a stream.

Supported operations:
 * WinZIP AES V2 read without seek


# Contribution

Setup Python and uv

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install uv
uv sync
uv pip install -e .
python patch_zipfile.py
```

Use dev tools

```sh
pytest
ruff format .
ruff check
```
