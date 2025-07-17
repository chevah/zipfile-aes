# Copyright (c) 2019 Adi Roiban.
# See LICENSE for details.
"""
Tests for ZIP archive handling.
"""

import time
import datetime

from zipfile_aes import (
    AES_V2,
    AES_256,
    ZipWithAES,
)

PASSWORD = b"chevah"

# Offset of date-time saving from local time.
# Done by convert back and fort, but getting rid of the timezone.
_base_dst_offset = time.time()
DST_OFFSET = time.mktime(time.localtime(_base_dst_offset)[:6] + (0, 0, 0)) - int(
    _base_dst_offset
)


def localClock(
    year=1971,
    month=1,
    day=1,
    hour=0,
    minute=0,
    second=0,
    microsecond=0,
):
    """
    Return the timestamp which is already set at the defined local time.

    By default it starts one year in Unix epoch.

    Be careful when using the clock with 1/1/1970 as setting hour 0 in
    different timezone might end up with negative timestamps.
    """
    date = datetime.datetime(
        year=year,
        month=month,
        day=day,
        hour=hour,
        minute=minute,
        second=second,
        microsecond=microsecond,
    )
    seconds = time.mktime(date.timetuple()) + float(microsecond) / 10**6
    return seconds


def test_infolist_single_v2():
    """
    It can read the content of the archive for files encrypted with AES V2.
    """
    sut = ZipWithAES("tests/single-file-ascii-aes256-v2-deflate.zip", mode="r")
    result = sut.infolist()
    assert 1 == len(result)
    assert AES_256 == result[0].aes_strength
    assert AES_V2 == result[0].aes_version


def test_open_v2_256():
    """
    It can read files encrypted with AES-256 V2 .
    """
    sut = ZipWithAES("tests/single-file-ascii-aes256-v2-deflate.zip", mode="r")
    result = sut.infolist()

    assert 549 == result[0].file_size

    with sut.open(result[0], pwd=PASSWORD) as source:
        chunk = source.read(85)
        assert (
            b"Zip test data.\nAscii password is: "
            b"chevah\nUnicode password is: chevah\xc8\x9b\n\nCreated using"
        ) == chunk
        chunk = source.read(101)
        assert chunk.startswith(b"::\n\n    zip -r --encrypt")
        assert chunk.endswith(b"7za a -tzip -pchevah -mem=")

        chunk = source.read(1000)
        assert chunk.startswith(b"AES256 -mm=STORE")
        assert chunk.endswith(
            b"python test_data/zip/create_zip.py test_data/zip/result-file.zip\n"
        )
