# See LICENSE for details.
"""
Tests for ZIP archive handling.
"""

from io import BytesIO

import pytest


from zipfile_aes import (
    AES_V1,
    AES_V2,
    AES_128,
    AES_192,
    AES_256,
    ZipFileWithAES,
    zipfile,  # Should be moved to canonical name once we no longer need patching.
)

PASSWORD = b"chevah"
TESTS_DIR = "tests/"


def test_read_single_v2_aes256():
    """
    It can read the content of the archive for files encrypted with
    v2 AES256.
    """
    sut = ZipFileWithAES(
        TESTS_DIR + "single-file-ascii-aes256-v2-deflate.zip", mode="r"
    )
    result = sut.infolist()
    assert 1 == len(result)
    assert AES_256 == result[0].aes_strength
    assert AES_V2 == result[0].aes_version

    with sut.open(result[0], pwd=PASSWORD) as source:
        chunk = source.read(85)
        assert (
            b"Zip test data.\nAscii password is: "
            b"chevah\nUnicode password is: chevah\xc8\x9b\n\nCreated using" == chunk
        )
        chunk = source.read(101)
        assert chunk.startswith(b"::\n\n    zip -r --encrypt")
        assert chunk.endswith(b"7za a -tzip -pchevah -mem=")

        chunk = source.read(1000)
        assert chunk.startswith(b"AES256 -mm=STORE")
        assert chunk.endswith(
            b"python test_data/zip/create_zip.py test_data/zip/result-file.zip\n",
        )

    # The file can be opened multiple times.
    with sut.open(result[0], pwd=PASSWORD) as source:
        source.read()

    # It fails for invalid passwords.
    with pytest.raises(RuntimeError) as context:
        sut.open(result[0], pwd=b"bad-pass")
    assert "Bad password for file 'README.rst'" == context.value.args[0]


def test_read_multiple_v2_store_aes128():
    """
    It can read the content of the archive for files encrypted with AES V2
    for which the content is not compressed.
    """
    sut = ZipFileWithAES(TESTS_DIR + "small-file-aes128-v2-store.zip", mode="r")
    result = sut.infolist()
    assert 3 == len(result)

    assert "root-dir/" == result[0].filename
    assert 0 == result[0].file_size
    assert result[0].aes_strength is None
    assert result[0].aes_version is None

    assert "root-dir/empty-dir/" == result[1].filename
    assert 0 == result[1].file_size
    assert result[1].aes_strength is None
    assert result[1].aes_version is None

    assert "root-dir/test.txt" == result[2].filename
    assert 5 == result[2].file_size
    assert AES_128 == result[2].aes_strength
    assert AES_V2 == result[2].aes_version
    assert zipfile.ZIP_STORED == result[2].aes_compression

    with sut.open(result[2], pwd=PASSWORD) as source:
        chunk = source.read(85)
        assert b"test\n" == chunk


def test_read_multiple_v2_lzma_aes192():
    """
    It can read the content of the archive for files compressed with LZMA
    """
    sut = ZipFileWithAES(TESTS_DIR + "multiple-files-aes192-v2-lzma.zip", mode="r")
    result = sut.infolist()
    assert 4 == len(result)

    assert "root-dir/" == result[0].filename
    assert 0 == result[0].file_size
    assert result[0].aes_strength is None
    assert result[0].aes_version is None

    assert "root-dir/empty-dir/" == result[1].filename
    assert 0 == result[1].file_size
    assert result[1].aes_strength is None
    assert result[1].aes_version is None

    assert "root-dir/test.txt" == result[2].filename
    assert 19932 == result[2].file_size
    assert AES_192 == result[2].aes_strength
    assert AES_V2 == result[2].aes_version
    assert zipfile.ZIP_LZMA == result[2].aes_compression

    with sut.open(result[2], pwd=PASSWORD) as source:
        chunk = source.read(45)
        assert b"Testing\n#######\n\nThis is the documentation fo" == chunk
        chunk = source.read(20000)
        assert chunk.startswith(b"r developing and running the tests.")
        assert chunk.endswith(b"tes\xc8\x9b-group-ci-v1 - for web client access\n")

    assert "root-dir/unicode-empțy-file.txt" == result[3].filename
    assert 0 == result[3].file_size
    assert AES_192 == result[3].aes_strength
    assert AES_V2 == result[3].aes_version
    # Empty files are just "stored".
    assert zipfile.ZIP_STORED == result[3].aes_compression

    with sut.open(result[3], pwd=PASSWORD) as source:
        chunk = source.read(85)
        assert b"" == chunk

    sut.close()


def test_read_file_object_v1():
    """
    It can read files with AES v1.

    This is also a test for using the context manager and reading from
    a file like object until the end of the file.
    """
    data = (
        b"PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<ZC\x00\x00\x00"
        b"'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE"
        b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
        b"\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU"
        b"\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873"
        b"\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00"
        b"&[<ZC\x00\x00\x00'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00"
        b"\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
        b"A\x00\x00\x00t\x00\x00\x00\x00\x00"
    )
    source = BytesIO(data)

    with ZipFileWithAES(source, "r") as sut:
        result = sut.infolist()
        assert 1 == len(result)
        assert "test.txt" == result[0].filename
        assert 39 == result[0].file_size
        assert AES_256 == result[0].aes_strength
        assert AES_V1 == result[0].aes_version
        assert zipfile.ZIP_STORED == result[0].aes_compression

        chunk = sut.read("test.txt", pwd=b"test")
        assert b"This is a test file for AES encryption." == chunk

        # The content can be read multiple times.
        chunk = sut.read("test.txt", pwd=b"test")
        assert b"This is a test file for AES encryption." == chunk

        # It fails for invalid passwords.
        with pytest.raises(RuntimeError) as context:
            sut.read("test.txt", pwd=b"bad-pass")
        assert "Bad password for file 'test.txt'" == context.value.args[0]


def test_decrypt_bad_hmac_ae1():
    """
    Decrypting an encrypted AE-1 file with a bad HMAC raises an
    exception.
    """
    source = BytesIO(
        b"PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<ZC\x00\x00\x00"
        b"'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE"
        b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
        b"\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU"
        b"\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873"
        b"\xb0\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00"
        b"&[<ZC\x00\x00\x00'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00"
        b"\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
        b"A\x00\x00\x00t\x00\x00\x00\x00\x00"
    )

    with ZipFileWithAES(source, "r") as sut:
        result = sut.infolist()
        assert 1 == len(result)
        assert "test.txt" == result[0].filename
        assert 39 == result[0].file_size
        assert AES_256 == result[0].aes_strength
        assert AES_V1 == result[0].aes_version
        assert zipfile.ZIP_STORED == result[0].aes_compression

        with pytest.raises(zipfile.BadZipFile) as context:
            sut.read("test.txt", pwd=b"test")
        assert "Bad HMAC check for file 'test.txt'" == context.value.args[0]


def test_decrypt_bad_hmac_ae2():
    """
    Decrypting an encrypted AE-2 file with a bad HMAC raises an exception.
    """
    source = BytesIO(
        b"PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00\x00\x00\x00\x00"
        b"C\x00\x00\x00"
        b"'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x02\x00AE"
        b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
        b"\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU"
        b"\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873"
        b"\xb0\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00"
        b"\x00\x00\x00\x00C\x00\x00\x00'\x00\x00\x00\x08\x00\x0b\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00"
        b"\x02\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
        b"A\x00\x00\x00t\x00\x00\x00\x00\x00"
    )

    with ZipFileWithAES(source, "r") as sut:
        result = sut.infolist()
        assert 1 == len(result)
        assert "test.txt" == result[0].filename
        assert 39 == result[0].file_size
        assert AES_256 == result[0].aes_strength
        assert AES_V2 == result[0].aes_version
        assert zipfile.ZIP_STORED == result[0].aes_compression

        with pytest.raises(zipfile.BadZipFile) as context:
            sut.read("test.txt", pwd=b"test")
        assert "Bad HMAC check for file 'test.txt'" == context.value.args[0]


def test_decrypt_bad_crc_ae1():
    """
    Decrypting an encrypted AE-1 with a bad CRC raises an exception
    """
    source = BytesIO(
        b"PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<0C\x00\x00\x00"
        b"'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE"
        b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
        b"\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU"
        b"\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873"
        b"\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00"
        b"&[<0C\x00\x00\x00'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00"
        b"\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
        b"A\x00\x00\x00t\x00\x00\x00\x00\x00"
    )

    with ZipFileWithAES(source, "r") as sut:
        result = sut.infolist()
        assert 1 == len(result)
        assert "test.txt" == result[0].filename
        assert 39 == result[0].file_size
        assert AES_256 == result[0].aes_strength
        assert AES_V1 == result[0].aes_version
        assert zipfile.ZIP_STORED == result[0].aes_compression

        with pytest.raises(zipfile.BadZipFile) as context:
            sut.read("test.txt", pwd=b"test")
        assert "Bad CRC-32 for file 'test.txt'" == context.value.args[0]


def test_decrypt_bad_crc_ae2():
    """
    Decrypting an encrypted AE-2 with an incorrect non-zero CRC raises
    an exception.

    CRC is not supposed to be used for AE-2 encryption and should be set
    to 0 but in the case where it is provided, let's make sure it matches.
    """
    source = BytesIO(
        b"PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<0C\x00\x00\x00"
        b"'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x02\x00AE"
        b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
        b"\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU"
        b"\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873"
        b"\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00"
        b"&[<0C\x00\x00\x00'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00"
        b"\x02\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
        b"A\x00\x00\x00t\x00\x00\x00\x00\x00"
    )

    with ZipFileWithAES(source, "r") as sut:
        result = sut.infolist()
        assert 1 == len(result)
        assert "test.txt" == result[0].filename
        assert 39 == result[0].file_size
        assert AES_256 == result[0].aes_strength
        assert AES_V2 == result[0].aes_version
        assert zipfile.ZIP_STORED == result[0].aes_compression

        with pytest.raises(zipfile.BadZipFile) as context:
            sut.read("test.txt", pwd=b"test")
        assert "Bad CRC-32 for file 'test.txt'" == context.value.args[0]
