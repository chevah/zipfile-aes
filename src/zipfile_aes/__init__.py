# See LICENSE for details.
"""
Code for handling ZIP aES archives.
"""

import struct
import zipfile_patched as zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Public constants exposed via ZipInfo
AES_V1 = b"\x01\x00"
AES_V2 = b"\x02\x00"

AES_128 = b"\x01"
AES_192 = b"\x02"
AES_256 = b"\x03"

# Compression type.
AES_COMPRESSION_TYPE = 99

# The id for the extra data.
_EXTRA_AES_HEADER_ID = 0x9901

_AES_VENDOR_ID = b"AE"

_AES_HMAC_SIZE = 10

_AES_SALT_LENGTHS = {
    AES_128: 8,
    AES_192: 12,
    AES_256: 16,
}

_AES_KEY_LENGTHS = {
    AES_128: 16,
    AES_192: 24,
    AES_256: 32,
}


class ZipInfoWithAES(zipfile.ZipInfo):
    """
    Extend the stdblib code to read AES encryption extra data.
    """

    __slots__ = (
        "aes_version",
        "aes_strength",
        "aes_compression",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.aes_strength = None
        self.aes_version = None
        self.aes_compression = None

    def _decodeExtra(self, filename_crc):
        """
        Little endian encoding.
        Fragment has minimum 11 bytes:
        * 2 bytes - extra fragment type
        * 2 bytes - extra data length
        * 2 bytes - AES encryption version
        * 2 bytes - Vendor always b'AE"
        * 1 byte - AES strength
        * 2 bytes - compression type
        """
        # Do the upstream decoding first.
        # This should validate each fragment.
        super()._decodeExtra(filename_crc)

        # Re-read the extra fragments to check for AES.
        extra = self.extra
        while len(extra) >= 4:
            tp, ln = struct.unpack("<HH", extra[:4])
            if tp != _EXTRA_AES_HEADER_ID:
                # Not AES.
                extra = extra[ln + 4 :]
                continue

            if ln < 7 or len(extra) < 11:
                # We validate both the actual data
                # and the advertised length.
                raise zipfile.BadZipFile("Short AES extra data.")

            vendor = extra[6:8]
            if vendor != _AES_VENDOR_ID:
                raise zipfile.BadZipFile("Unknown AES vendor.")

            vendor_version = extra[4:6]
            if vendor_version == AES_V1:
                self.aes_version = AES_V1
            elif vendor_version == AES_V2:
                self.aes_version = AES_V2
            else:
                raise zipfile.BadZipFile("Unknown AES version.")

            aes_strength = extra[8:9]
            if aes_strength == AES_128:
                self.aes_strength = AES_128
            elif aes_strength == AES_192:
                self.aes_strength = AES_192
            elif aes_strength == AES_256:
                self.aes_strength = AES_256
            else:
                raise zipfile.BadZipFile("Unknown AES strength.")

            compression_method = struct.unpack("<H", extra[9:11])[0]
            self.aes_compression = compression_method
            # Don't look for other extension fragments.
            return


class ZipExtFileWithAES(zipfile.ZipExtFile):
    """
    Extend stdlib code to support AES encryption.
    """

    def __init__(self, fileobj, mode, zipinfo, pwd=None, close_fileobj=False):
        if zipinfo.aes_version:
            # To share the decompressor code,
            # We pretend that we are a non AES encrypted file.
            # This is reverted at the end of init.
            zipinfo.compress_type = zipinfo.aes_compression

        self._zipinfo = zipinfo

        super().__init__(fileobj, mode, zipinfo, pwd, close_fileobj)

        if zipinfo.aes_version == AES_V2:
            # CRC is not used for v2.
            # Only the HMAC is used.
            self._expected_crc = None

        if zipinfo.aes_version:
            zipinfo.compress_type = AES_COMPRESSION_TYPE
            # For now, we don't support seek operation.
            self._seekable = False

    def _init_decrypter(self):
        """
        This is upstream method called from `__init__`.
        """
        if self._zipinfo.aes_version:
            return self._init_aes_decrypter()

        # Use upstream code.
        return super()._init_decrypter()

    def _update_crc(self, newdata):
        """
        This is upstream method called after each read.
        """
        if self._zipinfo.aes_version is not None and self._eof:
            # We are at the end of the file for an AES encrypted file.
            hmac_check = self._fileobj.read(_AES_HMAC_SIZE)
            self._decrypter.check_hmac(hmac_check)

        super()._update_crc(newdata)

    def _init_aes_decrypter(self):
        if not self._pwd:
            raise zipfile.BadZipFile("File is AES encrypted and requires a password.")

        # salt_length + pwd_verify_length
        header_length = _AES_SALT_LENGTHS[self._zipinfo.aes_strength] + 2
        header = self._fileobj.read(header_length)
        # Adjust read size for encrypted files since the start of the file
        # may be used for the encryption/password information.
        self._compress_left -= header_length
        # Also remove the hmac length from the end of the file.
        self._compress_left -= _AES_HMAC_SIZE

        self._decrypter = AESZipDecrypter(self._zipinfo, self._pwd, header)

        if self._zipinfo.aes_version == AES_V2:
            # The CRC check is not used for v2.
            # This is done to prevent disclosure of data for very small files.
            return 0

        return self._decrypter(header)[11]


class AESZipDecrypter:
    hmac_size = 10

    def __init__(self, zinfo, pwd, encryption_header):
        self.filename = zinfo.filename

        key_length = _AES_KEY_LENGTHS[zinfo.aes_strength]
        salt_length = _AES_SALT_LENGTHS[zinfo.aes_strength]

        salt = struct.unpack(
            "<{}s".format(salt_length), encryption_header[:salt_length]
        )[0]
        pwd_verify_length = 2
        pwd_verify = encryption_header[salt_length:]
        dkLen = 2 * key_length + pwd_verify_length
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=dkLen,
            salt=salt,
            iterations=1000,
        )
        keymaterial = kdf.derive(pwd)

        encpwdverify = keymaterial[2 * key_length :]
        if encpwdverify != pwd_verify:
            raise RuntimeError("Bad password for file %r" % zinfo.filename)

        self._enckey = keymaterial[:key_length]
        self._counter = 0

        encmac_key = keymaterial[key_length : 2 * key_length]
        self._hmac = hmac.HMAC(encmac_key, hashes.SHA1())

    def __call__(self, data):
        """
        This is the main public API.
        """
        return b"".join(self._decrypt(self._getBlocks(data)))

    def check_hmac(self, hmac_check):
        """
        This is the public API called at the end of the file.
        """
        if self._hmac.finalize()[:_AES_HMAC_SIZE] != hmac_check:
            raise zipfile.BadZipFile(f"Bad HMAC check for file {self.filename}")

    def _decrypt(self, blocks):
        for block in blocks:
            self._counter += 1
            cipher = Cipher(
                algorithms.AES(self._enckey),
                modes.CTR((self._counter).to_bytes(16, byteorder="little")),
            )
            self._hmac.update(block)
            data = cipher.decryptor().update(block)
            data += cipher.decryptor().finalize()
            yield data

    def _getBlocks(self, original):
        """
        Return AES blocks.
        """
        for i in range(0, len(original), 16):
            yield original[i : i + 16]


class ZipWithAES(zipfile.ZipFile):
    """
    ZipFile which handles AES encrypted files.
    """

    _ZipInfo = ZipInfoWithAES
    _ZipExtFile = ZipExtFileWithAES
