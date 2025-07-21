# See LICENSE for details.
"""
Code for handling ZIP aES archives.
"""

import io
import os
import struct
import zipfile_patched as zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Compression type.
AES_COMPRESSION_TYPE = 99

# The id for the extra data.
EXTRA_AES_HEADER_ID = 0x9901

AES_VENDOR_ID = b"AE"

AES_V1 = b"\x01\x00"
AES_V2 = b"\x02\x00"

AES_128 = b"\x01"
AES_192 = b"\x02"
AES_256 = b"\x03"

AES_HMAC_SIZE = 10

AES_SALT_LENGTHS = {
    AES_128: 8,
    AES_192: 12,
    AES_256: 16,
}
AES_KEY_LENGTHS = {
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

    def setAESInfo(self, version, strength):
        """
        Set the attributes to prepare writing an AES encrypted file.
        """
        self.aes_strength = strength
        self.aes_version = version
        self.aes_compression = self.compress_type

        self.compress_type = AES_COMPRESSION_TYPE

        # We set it here... but when the file is written,
        # the stdlib will reset all the flags.
        self.flag_bits |= zipfile._MASK_ENCRYPTED

        # FIXME
        # Handle setting the extra multiple times.
        self.extra += (
            struct.pack("<HH", EXTRA_AES_HEADER_ID, 7)
            + self.aes_version
            + AES_VENDOR_ID
            + self.aes_strength
            + struct.pack("<H", self.aes_compression)
        )

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
            if tp != EXTRA_AES_HEADER_ID:
                # Not AES.
                extra = extra[ln + 4 :]
                continue

            if ln < 7 or len(extra) < 11:
                # We validate both the actual data
                # and the advertised length.
                raise zipfile.BadZipFile("Short AES extra data.")

            vendor = extra[6:8]
            if vendor != AES_VENDOR_ID:
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

            if not pwd:
                raise RuntimeError("AES encrypted file requires a password.")

        self._zipinfo = zipinfo

        super().__init__(fileobj, mode, zipinfo, pwd, close_fileobj)

        if zipinfo.aes_version == AES_V2 and self._expected_crc == 0:
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
            hmac_check = self._fileobj.read(AES_HMAC_SIZE)
            self._decrypter.check_hmac(hmac_check)

        super()._update_crc(newdata)

    def _init_aes_decrypter(self):
        """
        Setup decryption for an AES file.
        """
        if not self._pwd:
            raise zipfile.BadZipFile("File is AES encrypted and requires a password.")

        # salt_length + pwd_verify_length
        header_length = AES_SALT_LENGTHS[self._zipinfo.aes_strength] + 2
        header = self._fileobj.read(header_length)

        # Adjust read size for encrypted files since the start of the file
        # may be used for the encryption/password information.
        self._compress_left -= header_length
        # Also remove the hmac length from the end of the file.
        self._compress_left -= AES_HMAC_SIZE

        self._decrypter = AESZipDecipher(self._zipinfo, self._pwd, header)

        # TODO:
        # This can be removed once the upstream zipfile
        # does the password checking as part of decryption initialization.
        # For AES the password is validate in AESZipDecipher.
        # This is here to reduce the patch for stdlib.
        if self._zipinfo.flag_bits & zipfile._MASK_USE_DATA_DESCRIPTOR:
            # compare against the file type from extended local headers
            check_byte = (self._zipinfo._raw_time >> 8) & 0xFF
        else:
            # compare against the CRC otherwise
            check_byte = (self._zipinfo.CRC >> 24) & 0xFF
        return check_byte


class AESZipDecipher:
    """
    Decrypt using WinZip AES.
    """

    hmac_size = 10

    def __init__(self, zinfo, pwd, encryption_header):
        self.filename = zinfo.filename

        key_length = AES_KEY_LENGTHS[zinfo.aes_strength]
        salt_length = AES_SALT_LENGTHS[zinfo.aes_strength]

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

        # Check p
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
        if self._hmac.finalize()[:AES_HMAC_SIZE] != hmac_check:
            raise zipfile.BadZipFile(f"Bad HMAC check for file '{self.filename}'")

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


class ZipFileWithAES(zipfile.ZipFile):
    """
    ZipFile which handles AES encrypted files.
    """

    _ZipInfo = ZipInfoWithAES
    _ZipExtFile = ZipExtFileWithAES
    _aes_password = None
    _aes_strength = AES_256
    _aes_version = AES_V2

    def setAESEncryption(self, password, version=None):
        self._aes_password = password

    def _open_to_write(self, zinfo, force_zip64=False):
        if self._aes_password:
            zinfo.setAESInfo(version=self._aes_version, strength=self._aes_strength)

        # Stdlib will reset the flag_bits.
        # We set them again in _writecheck
        stream = super()._open_to_write(zinfo, force_zip64=force_zip64)

        if not self._aes_password:
            return stream

        # TODO:
        # Refactor _open_to_write to alow to reuse more code.
        # Here we close the zipfilewriter created by _open_to_write
        # and set a fake file and revert the filelist updated at close.
        original_fp = self.fp
        try:
            self.fp = io.BytesIO()
            stream.close()
            self.filelist.pop()
        finally:
            self.fp = original_fp

        # The need for zip64 is computes inside _open_to_write and
        # was already set in the file header.
        return _ZipWithAESWriteFile(self, zinfo, stream._zip64)

    def _writecheck(self, zinfo):
        """
        Pretend that we have normal compression.

        This also fixes the flag_bits that are reset by upstream _open_to_write.
        """
        try:
            if zinfo.aes_version:
                zinfo.compress_type = zinfo.aes_compression
                zinfo.flag_bits |= zipfile._MASK_ENCRYPTED
            super()._writecheck(zinfo)
        finally:
            if zinfo.aes_version:
                zinfo.compress_type = AES_COMPRESSION_TYPE


class _ZipWithAESWriteFile(zipfile._ZipWriteFile):
    def __init__(self, zf, zinfo, zip64):
        self._zinfo = zinfo
        self._zip64 = zip64
        self._zipfile = zf
        # Here we update stdlib to pass the compression.
        self._compressor = zipfile._get_compressor(
            zinfo.aes_compression, zinfo._compresslevel
        )
        self._file_size = 0
        self._compress_size = 0
        self._crc = 0

        self._salt_length = AES_SALT_LENGTHS[zinfo.aes_strength]
        key_length = AES_KEY_LENGTHS[zinfo.aes_strength]
        salt = os.urandom(self._salt_length)

        pwd_verify_length = 2
        dkLen = 2 * key_length + pwd_verify_length
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=dkLen,
            salt=salt,
            iterations=1000,
        )
        keymaterial = kdf.derive(self._zipfile._aes_password)

        encryption_verify = keymaterial[2 * key_length :]

        self._enckey = keymaterial[:key_length]
        self._counter = 0
        encmac_key = keymaterial[key_length : 2 * key_length]
        self._hmac = hmac.HMAC(encmac_key, hashes.SHA1())

        buf = salt + encryption_verify
        self._compress_size += len(buf)
        self._fileobj.write(buf)

    def _encrypt(self, data):
        blocks = self._getBlocks(data)
        encrypted_data = []
        for block in blocks:
            self._counter += 1
            cipher = Cipher(
                algorithms.AES(self._enckey),
                modes.CTR((self._counter).to_bytes(16, byteorder="little")),
            )
            data = cipher.encryptor().update(block)
            data += cipher.encryptor().finalize()
            encrypted_data.append(data)

        result = b"".join(encrypted_data)
        self._hmac.update(result)
        return result

    @staticmethod
    def _getBlocks(original):
        """
        Return AES blocks.
        """
        for i in range(0, len(original), 16):
            yield original[i : i + 16]

    def write(self, data):
        if self.closed:
            raise ValueError("I/O operation on closed file.")

        # Accept any data that supports the buffer protocol
        if isinstance(data, (bytes, bytearray)):
            nbytes = len(data)
        else:
            data = memoryview(data)
            nbytes = data.nbytes
        self._file_size += nbytes

        self._crc = zipfile.crc32(data, self._crc)
        if self._compressor:
            data = self._compressor.compress(data)

        # TODO:
        # This is updated to add encryption.
        data = self._encrypt(data)

        self._compress_size += len(data)
        # This is stdlib code.
        self._fileobj.write(data)
        return nbytes

    def close(self):
        if self.closed:
            return

        try:
            io.BufferedIOBase.close(self)

            # Flush any data from the compressor, encrypt it and update header info
            if self._compressor:
                buf = self._compressor.flush()
            else:
                buf = b""

            buf = self._encrypt(buf)
            buf += struct.pack(f"<{AES_HMAC_SIZE}s", self._hmac.finalize()[:10])
            self._compress_size += len(buf)
            self._fileobj.write(buf)

            self._zinfo.compress_size = self._compress_size

            # Below is stdlib code
            self._zinfo.CRC = self._crc
            self._zinfo.file_size = self._file_size

            if not self._zip64:
                if self._file_size > zipfile.ZIP64_LIMIT:
                    raise RuntimeError("File size too large, try using force_zip64")
                if self._compress_size > zipfile.ZIP64_LIMIT:
                    raise RuntimeError(
                        "Compressed size too large, try using force_zip64"
                    )

            # Write updated header info
            if self._zinfo.flag_bits & zipfile._MASK_USE_DATA_DESCRIPTOR:
                # Write CRC and file sizes after the file data
                fmt = "<LLQQ" if self._zip64 else "<LLLL"
                self._fileobj.write(
                    struct.pack(
                        fmt,
                        zipfile._DD_SIGNATURE,
                        self._zinfo.CRC,
                        self._zinfo.compress_size,
                        self._zinfo.file_size,
                    )
                )
                self._zipfile.start_dir = self._fileobj.tell()
            else:
                # Seek backwards and write file header (which will now include
                # correct CRC and file sizes)

                # Preserve current position in file
                self._zipfile.start_dir = self._fileobj.tell()
                self._fileobj.seek(self._zinfo.header_offset)
                self._fileobj.write(self._zinfo.FileHeader(self._zip64))
                self._fileobj.seek(self._zipfile.start_dir)

            # Successfully written: Add file to our caches
            self._zipfile.filelist.append(self._zinfo)
            self._zipfile.NameToInfo[self._zinfo.filename] = self._zinfo
        finally:
            self._zipfile._writing = False
