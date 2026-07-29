# -*- coding: utf-8 -*-
import enum
import io
import os
import pathlib
import struct
import zlib
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from typing import Dict
from typing import List
from typing import Tuple
from typing import Union
from uuid import uuid4 as uniquename

import xdis
from Crypto.Cipher import AES
from xdis.magics import magic2int
from xdis.disasm import disassemble_file

import pydecipher
from pydecipher import bytecode
from pydecipher import logger
from pydecipher import utils


def _decompress_limited(data: bytes, extraction_budget: utils.ExtractionBudget) -> bytes:
    """Decompress one zlib stream without exceeding the extraction budget."""
    maximum_output = min(
        extraction_budget.max_member_size,
        extraction_budget.max_total_size - extraction_budget.total_size,
    )
    if maximum_output < 0:
        raise utils.ExtractionLimitError("archive extraction budget is exhausted")

    decompressor = zlib.decompressobj()
    output = decompressor.decompress(data, maximum_output + 1)
    if len(output) > maximum_output or decompressor.unconsumed_tail:
        raise utils.ExtractionLimitError(f"compressed member exceeds {maximum_output} output bytes")
    output += decompressor.flush(maximum_output + 1 - len(output))
    if len(output) > maximum_output:
        raise utils.ExtractionLimitError(f"compressed member exceeds {maximum_output} output bytes")
    if not decompressor.eof:
        raise zlib.error("incomplete or truncated zlib stream")
    extraction_budget.validate_payload(len(data), len(output))
    return output


def _safe_output_path(output_dir: os.PathLike, member_name: str, suffix: str = "") -> Path:
    """Compatibility wrapper around the shared safe-path helper."""
    return utils.safe_output_path(output_dir, member_name, suffix=suffix)


@pydecipher.register
class CArchive:
    PYINST20_COOKIE_SIZE: int = 24  # For PyInstaller 2.0
    PYINST21_COOKIE_SIZE: int = 24 + 64  # For PyInstaller 2.1+
    MAGIC: bytes = b"MEI\014\013\012\013\016"  # Magic number which identifies PyInstaller CArchive
    magic_index: int
    archive_path: pathlib.Path
    archive_contents: bytes
    pyinstaller_version: float
    python_version: float
    toc: List["CTOCEntry"] = []
    output_dir: Path
    potential_zlib_archive_passwords: List[str] = []

    class ArchiveItem(enum.Enum):
        """The different types of entries in a CArchive.

        Look here for more info: https://github.com/pyinstaller/pyinstaller/blob/1844d69f5aa1d64d3feca912ed1698664a3faf3e/bootloader/src/pyi_archive.h#L18
        """

        BINARY = "b"  # binary
        DEPENDENCY = "d"  # runtime option
        PYZ = "z"  # zlib (pyz) - frozen Python code
        ZIPFILE = "Z"  # zlib (pyz) - frozen Python code
        PYPACKAGE = "M"  # Python package (__init__.py)
        PYMODULE = "m"  # Python module
        PYSOURCE = "s"  # Python script (v3)
        DATA = "x"  # data
        RUNTIME_OPTION = "o"  # runtime option

        @staticmethod
        def from_str(value):
            try:
                return CArchive.ArchiveItem(value)
            except ValueError:
                logger.warning(f"[!] Unknown item type found in archive with type code letter '{value}'")
                return CArchive.ArchiveItem.DATA

    class CTOCEntry:
        entry_offset: int
        compressed_data_size: int
        uncompressed_data_size: int
        compression_flag: bool
        type_code: "CArchive.ArchiveItem"
        name: str
        ENTRYSTRUCT = "!iiiiBB"
        ENTRYLEN = struct.calcsize(ENTRYSTRUCT)

        def __init__(
            self,
            entry_offset: int,
            compressed_data_size: int,
            uncompressed_data_size: int,
            compression_flag: bool,
            type_code: str,
            name: str,
        ):
            self.entry_offset = entry_offset
            self.compressed_data_size = compressed_data_size
            self.uncompressed_data_size = uncompressed_data_size
            self.compression_flag = compression_flag
            self.type_code = CArchive.ArchiveItem.from_str(type_code)
            self.name = name

    def __init__(
        self,
        carchive_path_or_bytes: Union[str, os.PathLike, BinaryIO],
        output_dir: os.PathLike = None,
        **kwargs,
    ):
        if isinstance(carchive_path_or_bytes, str):
            carchive_path_or_bytes: Path = Path(carchive_path_or_bytes)
        if isinstance(carchive_path_or_bytes, Path):
            if not carchive_path_or_bytes.exists():
                msg = f"[!] Could not find the provided path: {str(carchive_path_or_bytes)}."
                raise FileNotFoundError(msg)
            if not os.access(carchive_path_or_bytes, os.R_OK):
                msg = f"[!] Lacking read permissions on: {str(carchive_path_or_bytes)}."
                raise PermissionError(msg)
            self.archive_path = carchive_path_or_bytes
            with self.archive_path.open("rb") as input_file:
                self.archive_contents = input_file.read()
        if isinstance(carchive_path_or_bytes, io.BufferedIOBase):
            self.archive_contents = carchive_path_or_bytes.read()

        if output_dir:
            self.output_dir = output_dir
        else:
            if hasattr(self, "archive_path"):
                self.output_dir = self.archive_path.parent / utils.slugify(self.archive_path.name + "_output")
            else:
                self.output_dir = Path.cwd()
        if not os.access(self.output_dir.parent, os.W_OK):
            msg = f"[!] Cannot write output directory to dir: {str(self.output_dir)}."
            raise PermissionError(msg)
        self.kwargs = kwargs

        if not self.validate_pyinstaller_carchive():
            raise TypeError(
                "[!] This is not a PyInstaller CArchive (or is an archive of an unsupported PyInstaller version"
            )

    def validate_pyinstaller_carchive(self):
        self.magic_index = self.archive_contents.find(self.MAGIC)
        cookie_size = len(self.archive_contents) - self.magic_index
        if self.magic_index > 0:
            if cookie_size == self.PYINST20_COOKIE_SIZE:
                self.pyinstaller_version = 2.0
                logger.debug("[*] PyInstaller version: 2.0")
                return True
            elif cookie_size == self.PYINST21_COOKIE_SIZE:
                self.pyinstaller_version = 2.1  # or greater
                return True
                logger.debug("[*] PyInstaller version: 2.1")
            else:
                logger.debug(
                    f"[!] PyInstaller cookie size is {cookie_size}, which does not correspond to a known "
                    "version of PyInstaller."
                )
                if cookie_size < 100:
                    # Some valid cookies were seen with size 94
                    self.pyinstaller_version = "unknown"
                    return True
                else:
                    return False
        else:
            logger.debug("[!] Could not find PyInstaller magic within this archive.")
        return False

    def parse_toc(self):
        self.toc = []
        # Read CArchive cookie
        if self.pyinstaller_version == 2.0 or self.pyinstaller_version == "unknown":
            try:
                (magic, self.length_of_package, self.toc_offset, self.toc_size, self.python_version,) = struct.unpack(
                    "!8siiii",
                    self.archive_contents[self.magic_index : self.magic_index + self.PYINST20_COOKIE_SIZE],
                )
            except (struct.error, ValueError):
                pass
            else:
                self.pyinstaller_version = 2.0
        if self.pyinstaller_version == 2.1 or self.pyinstaller_version == "unknown":
            try:
                (
                    magic,
                    self.length_of_package,
                    self.toc_offset,
                    self.toc_size,
                    self.python_version,
                    self.python_dynamic_lib,
                ) = struct.unpack(
                    "!8siiii64s",
                    self.archive_contents[self.magic_index : self.magic_index + self.PYINST21_COOKIE_SIZE],
                )
            except (struct.error, UnicodeDecodeError, ValueError):
                pass
            else:
                self.pyinstaller_version = 2.1
                if self.python_dynamic_lib:
                    self.python_dynamic_lib = self.python_dynamic_lib.decode("ascii").rstrip("\x00")

        if self.pyinstaller_version == "unknown":
            logger.warning("[!] Could not parse CArchive because PyInstaller version is unknown.")
            return

        try:
            self.python_version = float(self.python_version) / 10
        except (TypeError, ValueError):
            logger.warning("[!] CArchive contains an invalid Python version.")
            return
        logger.info(f"[*] This CArchive was built with Python {self.python_version}")
        logger.debug(f"[*] CArchive Package Size: {self.length_of_package}")
        logger.debug(f"[*] CArchive Python Version: {self.python_version}")
        if self.pyinstaller_version == 2.1:
            logger.debug(f"[*] CArchive Python Dynamic Library Name: {self.python_dynamic_lib}")

        if self.toc_offset < 0 or self.toc_size < 0:
            logger.warning("[!] CArchive contains a negative TOC offset or size.")
            return
        toc_end = self.toc_offset + self.toc_size
        if self.toc_offset > len(self.archive_contents) or toc_end > len(self.archive_contents):
            logger.warning("[!] CArchive TOC extends beyond the archive.")
            return

        toc_bytes = self.archive_contents[self.toc_offset : self.toc_offset + self.toc_size]
        parsed_toc = []
        while toc_bytes:
            if len(toc_bytes) < 4:
                logger.warning("[!] CArchive TOC ends with a truncated entry size.")
                return
            (entry_size,) = struct.unpack("!i", toc_bytes[0:4])
            if entry_size < self.CTOCEntry.ENTRYLEN or entry_size > len(toc_bytes):
                logger.warning(f"[!] CArchive TOC contains an invalid entry size: {entry_size}.")
                return
            name_length = entry_size - self.CTOCEntry.ENTRYLEN
            try:
                (
                    entry_offset,
                    compressed_data_size,
                    uncompressed_data_size,
                    compression_flag,
                    type_code,
                    name,
                ) = struct.unpack(f"!iiiBB{name_length}s", toc_bytes[4:entry_size])
                name = name.decode("utf-8").rstrip("\0")
            except (struct.error, UnicodeDecodeError):
                logger.warning("[!] CArchive TOC contains a malformed entry.")
                return

            entry_end = entry_offset + compressed_data_size
            if (
                entry_offset < 0
                or compressed_data_size < 0
                or uncompressed_data_size < 0
                or entry_offset > len(self.archive_contents)
                or entry_end > len(self.archive_contents)
            ):
                logger.warning(f"[!] CArchive TOC entry {name!r} points outside the archive.")
                return
            if compression_flag not in (0, 1):
                logger.warning(f"[!] CArchive TOC entry {name!r} has an invalid compression flag.")
                return
            if name == "":
                name = str(uniquename())
                logger.debug(f"[!] Warning: Found an unnamed file in CArchive. Using random name {name}")

            type_code = chr(type_code)
            parsed_toc.append(
                self.CTOCEntry(
                    entry_offset,
                    compressed_data_size,
                    uncompressed_data_size,
                    compression_flag,
                    type_code,
                    name,
                )
            )

            toc_bytes = toc_bytes[entry_size:]
        self.toc = parsed_toc
        logger.debug(f"[*] Found {len(self.toc)} entries in this PyInstaller CArchive")

    def extract_files(self):
        extraction_budget = utils.get_extraction_budget(getattr(self, "kwargs", {}))
        magic_nums: set = set()
        decompression_errors = 0
        successfully_extracted = 0
        entry: CTOCEntry
        for entry in self.toc:
            try:
                extraction_budget.begin_member(entry.compressed_data_size, entry.uncompressed_data_size)
            except utils.ExtractionLimitError as error:
                logger.warning(f"[!] Skipping CArchive entry {entry.name!r}: {error}.")
                continue
            try:
                file_path = _safe_output_path(self.output_dir, entry.name)
            except ValueError as error:
                logger.warning(f"[!] Skipping unsafe CArchive entry {entry.name!r}: {error}.")
                continue

            data = self.archive_contents[entry.entry_offset : entry.entry_offset + entry.compressed_data_size]

            if entry.compression_flag:
                try:
                    data = _decompress_limited(data, extraction_budget)
                except (zlib.error, utils.ExtractionLimitError) as e:
                    decompression_errors += 1
                    logger.debug(f"[!] PyInstaller CArchive decompression failed with error: {e}")
                    continue
                else:
                    if len(data) != entry.uncompressed_data_size:
                        logger.warning(
                            f"[!] {entry.name} entry in CArchive listed its uncompressed data size as"
                            f" {entry.uncompressed_data_size}, however in actuality, uncompressed to be {len(data)}"
                            " bytes. This may be a sign that the CArchive was manually altered."
                        )
            else:
                try:
                    extraction_budget.validate_payload(len(data), len(data))
                except utils.ExtractionLimitError as error:
                    logger.warning(f"[!] Skipping CArchive entry {entry.name!r}: {error}.")
                    continue

            extraction_budget.commit_payload(entry.compressed_data_size, len(data))

            file_suffix = ""
            if entry.type_code == self.ArchiveItem.PYSOURCE:
                if not data:
                    logger.warning(f"[!] Skipping empty CArchive source entry {entry.name!r}.")
                    continue
                if ord(data[:1]) == ord(xdis.marsh.TYPE_CODE) or ord(data[:1]) == (
                    ord(xdis.marsh.TYPE_CODE) | xdis.unmarshal.FLAG_REF
                ):
                    file_suffix = ".pyc"
                    if len(magic_nums) > 1:
                        magic_num = next(iter(magic_nums))
                        logger.warning(
                            "[!] More than one magic number found within this CArchive. Using magic number"
                            f" {magic_num}, but also found numbers: {magic_nums}"
                        )
                    elif len(magic_nums) == 0:
                        logger.warning(
                            f"[!] Skipping CArchive source entry {entry.name!r} because no Python magic number "
                            "has been found."
                        )
                        continue
                    try:
                        data = pydecipher.bytecode.create_pyc_header(next(iter(magic_nums))) + data
                    except (KeyError, ValueError, struct.error) as error:
                        logger.warning(f"[!] Skipping CArchive source entry {entry.name!r}: {error}.")
                        continue
                else:
                    file_suffix = ".py"
                if "pyi" not in entry.name:
                    logger.info(f"[!] Potential entrypoint found at script {entry.name}.py")
            elif entry.type_code == self.ArchiveItem.PYMODULE:
                magic_bytes = data[:4]  # Python magic value
                if len(magic_bytes) != 4:
                    logger.warning(f"[!] Skipping truncated CArchive module entry {entry.name!r}.")
                    continue
                try:
                    magic_nums.add(magic2int(magic_bytes))
                except (KeyError, TypeError, ValueError, struct.error) as error:
                    logger.warning(f"[!] Skipping CArchive module entry {entry.name!r}: {error}.")
                    continue
                file_suffix = ".pyc"

            if file_suffix:
                try:
                    file_path = _safe_output_path(self.output_dir, entry.name, suffix=file_suffix)
                except ValueError as error:
                    logger.warning(f"[!] Skipping unsafe CArchive entry {entry.name!r}: {error}.")
                    continue

            if entry.type_code != self.ArchiveItem.RUNTIME_OPTION:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                file_path.parent.mkdir(parents=True, exist_ok=True)
                with file_path.open(mode="wb") as f:
                    f.write(data)
                    successfully_extracted += 1

            if entry.type_code in (self.ArchiveItem.PYZ, self.ArchiveItem.ZIPFILE):
                output_dir_name = (
                    str(file_path.parent.joinpath(utils.slugify(file_path.name.split(".")[0]))) + "_output"
                )
                try:
                    pydecipher.unpack(
                        file_path,
                        output_dir=output_dir_name,
                        **utils.next_recursion_kwargs(self.kwargs),
                    )
                except utils.ExtractionLimitError as error:
                    logger.warning(f"[!] Skipping nested CArchive artifact {entry.name!r}: {error}.")

        if decompression_errors:
            logger.debug(f"[!] Failed to write {decompression_errors} files due to decompression errors.")
        if successfully_extracted:
            logger.info(f"[+] Successfully extracted {successfully_extracted} files from this CArchive.")

    def unpack(self) -> None:
        self.parse_toc()
        if self.toc:
            self.extract_files()


@pydecipher.register
class ZlibArchive:
    """
    Pyinstaller ZlibArchive (.pyz)
    """

    potential_keys = List[str]
    encryption_key: str = ""
    encrypted: bool = False
    archive_path: Path
    archive_contents: bytes
    magic_int: int
    toc: Dict[str, Tuple]
    compilation_time: datetime

    class ArchiveItem(enum.Enum):
        """The different types of entries in a ZlibArchive.

        Look here for more info: https://github.com/pyinstaller/pyinstaller/blob/1844d69f5aa1d64d3feca912ed1698664a3faf3e/PyInstaller/loader/pyimod02_archive.py#L41
        """

        MODULE = 0
        PKG = 1
        DATA = 2

        @staticmethod
        def from_int(value):
            try:
                return ZlibArchive.ArchiveItem(value)
            except ValueError:
                logger.warning(f"[!] Unknown item type found in ZlibArchive with type code number '{value}'")
                return ZlibArchive.ArchiveItem.DATA

    class ZTOCEntry:
        name: str
        type_code: "ZlibArchive.ArchiveItem"
        position: int
        compressed_data_size: int

        def __init__(self, name: str, type_code: str, position: int, compressed_data_size: int):
            """
            :type position: Offset in the archive where the member starts
            :type compressed_data_size: Size of compressed member data, if compressed. Otherwise, zero.
            :type uncompressed_data_size: Size of uncompressed member data
            :type compressed_flag: Bool indicating where member is compressed
            :type type_code: Single char indicating type of
            """
            self.name = name
            self.type_code = type_code
            self.position = position
            self.compressed_data_size = compressed_data_size

    def __init__(
        self,
        zlibarchive_path_or_bytes: Union[str, os.PathLike, BinaryIO],
        output_dir: os.PathLike = None,
        **kwargs,
    ):
        if isinstance(zlibarchive_path_or_bytes, str):
            zlibarchive_path_or_bytes: Path = Path(zlibarchive_path_or_bytes)
        if isinstance(zlibarchive_path_or_bytes, Path):
            if not zlibarchive_path_or_bytes.exists():
                msg = f"[!] Could not find the provided path: {str(zlibarchive_path_or_bytes)}."
                raise FileNotFoundError(msg)
            if not os.access(zlibarchive_path_or_bytes, os.R_OK):
                msg = f"[!] Lacking read permissions on: {str(zlibarchive_path_or_bytes)}."
                raise PermissionError(msg)
            self.archive_path = zlibarchive_path_or_bytes
            with self.archive_path.open("rb") as input_file:
                self.archive_contents = input_file.read()
        if isinstance(zlibarchive_path_or_bytes, io.BufferedIOBase):
            self.archive_contents = zlibarchive_path_or_bytes.read()

        if output_dir:
            self.output_dir = output_dir
        else:
            if hasattr(self, "file_path"):
                self.output_dir = self.file_path.parent / utils.slugify(self.file_path.name + "_output")
            else:
                self.output_dir = Path.cwd()
        if not os.access(self.output_dir.parent, os.W_OK):
            msg = f"[!] Cannot write output directory to dir: {str(self.output_dir)}."
            raise PermissionError(msg)
        self.kwargs = kwargs
        # if not self.output_dir.exists():
        #     self.output_dir.mkdir(parents=True)

        if not self.validate_zlibarchive():
            raise TypeError(
                "[!] This is not a PyInstaller ZlibArchive (or is an archive of an unsupported PyInstaller version"
            )

    def validate_zlibarchive(self):
        if (
            len(self.archive_contents) >= 12
            and self.archive_contents[:4] == b"PYZ\0"
            and CArchive.MAGIC not in self.archive_contents
        ):
            return True
        else:
            return False

    def check_for_password_file(self):
        self.potential_keys = []
        if hasattr(self, "archive_path"):
            dir_of_pyz = self.archive_path.parent
        else:
            dir_of_pyz = Path.cwd()

        key_file = dir_of_pyz / "pyimod00_crypto_key.pyc"
        if key_file.exists():
            self.encrypted = True
            logger.debug(f"[+] Found ZlibArchive encryption key file at path {key_file}")
            crypto_key_filename: str  # full path of
            try:
                (
                    crypto_key_filename,
                    crypto_key_co,
                    crypto_key_python_version,
                    crypto_key_compilation_timestamp,
                    crypto_key_magic_int,
                    crypto_key_is_pypy,
                    crypto_key_source_size,
                    crypto_key_sip_hash,
                ) = disassemble_file(str(key_file), outstream=open(os.devnull, "w"))
            except Exception as e:
                logger.warning(f"[!] Could not disassemble file {key_file}. Received error: {e}")
            else:
                self.compilation_time = datetime.fromtimestamp(crypto_key_compilation_timestamp)
                for const_string in crypto_key_co.co_consts:
                    if const_string and len(const_string) == 16:
                        self.potential_keys.append(const_string)
            # If we couldn't decompile the file to see the consts, lets just search the raw bytes of the file
            # for the password
            if not self.potential_keys:
                with key_file.open("rb") as file_ptr:
                    file_strings = utils.parse_for_strings(file_ptr.read())
                s: str
                for s in file_strings:
                    if len(s) >= 16 and "pyimod00_crypto_key" not in s:
                        while len(s) >= 16:
                            self.potential_keys.append(s[0:16])
                            s = s[1:]

            logger.info(f"[*] Found these potential PyInstaller PYZ Archive encryption keys: {self.potential_keys}")

            if not self.potential_keys:
                logger.error(f"[*] Encryption key file detected, however no password was able to be retrieved.")

    def parse_toc(self) -> None:
        self.toc = {}
        try:
            self.magic_int = magic2int(self.archive_contents[4:8])
            (toc_position,) = struct.unpack("!i", self.archive_contents[8:12])
        except (KeyError, TypeError, ValueError, struct.error) as error:
            logger.warning(f"[!] PYZ archive contains an invalid header: {error}.")
            return
        if toc_position < 12 or toc_position >= len(self.archive_contents):
            logger.warning("[!] PYZ archive TOC position is outside the archive.")
            return
        try:
            parsed_toc = xdis.unmarshal.load_code(self.archive_contents[toc_position:], self.magic_int)
        except Exception as error:
            logger.warning(f"[!] Could not parse PYZ archive TOC: {error}.")
            return

        # From PyInstaller 3.1+ toc is a list of tuples
        if isinstance(parsed_toc, list):
            try:
                parsed_toc = dict(parsed_toc)
            except (TypeError, ValueError) as error:
                logger.warning(f"[!] PYZ archive contains an invalid TOC list: {error}.")
                return
        if not isinstance(parsed_toc, dict):
            logger.warning("[!] PYZ archive TOC is not a dictionary.")
            return

        validated_toc = {}
        for key, value in parsed_toc.items():
            if not isinstance(key, str) or not isinstance(value, (tuple, list)) or len(value) != 3:
                logger.warning(f"[!] Skipping malformed PYZ TOC entry {key!r}.")
                continue
            type_code, position, compressed_data_size = value
            if not all(isinstance(item, int) for item in (type_code, position, compressed_data_size)):
                logger.warning(f"[!] Skipping malformed PYZ TOC entry {key!r}.")
                continue
            member_end = position + compressed_data_size
            if (
                position < 12
                or compressed_data_size < 0
                or position > len(self.archive_contents)
                or member_end > len(self.archive_contents)
            ):
                logger.warning(f"[!] Skipping out-of-bounds PYZ TOC entry {key!r}.")
                continue
            validated_toc[key] = (type_code, position, compressed_data_size)
        self.toc = validated_toc
        logger.debug(f"[*] Found {len(self.toc)} entries in this PYZ archive")

    def decrypt_file(self, data) -> Union[bytes, None]:
        CRYPT_BLOCK_SIZE = 16
        initialization_vector = data[:CRYPT_BLOCK_SIZE]

        if not self.encryption_key:
            while self.potential_keys:
                encryption_key = self.potential_keys.pop(0)
                try:
                    cipher: AES.AESCipher = AES.new(encryption_key.encode(), AES.MODE_CFB, initialization_vector)
                    decrypted_data = cipher.decrypt(data[CRYPT_BLOCK_SIZE:])  # will silently fail if password is wrong
                    _ = _decompress_limited(
                        decrypted_data,
                        utils.get_extraction_budget(getattr(self, "kwargs", {})),
                    )  # ensures the password is correct
                except (zlib.error, utils.ExtractionLimitError) as e:
                    logger.debug(f"[!] Decryption of .pyc failed with password {encryption_key}. Discarding key.")
                else:
                    self.encryption_key = encryption_key
                    logger.debug(f"[!] Verified ZlibArchive password is {self.encryption_key}.")
                    return decrypted_data
        else:
            try:
                cipher: AES.AESCipher = AES.new(self.encryption_key.encode(), AES.MODE_CFB, initialization_vector)
                return cipher.decrypt(data[CRYPT_BLOCK_SIZE:])
            except zlib.error as e:
                logger.error(f"[!] Failed to decrypt .pyc with error: {e}")
                return None

    def extract_files(self) -> None:
        extraction_budget = utils.get_extraction_budget(getattr(self, "kwargs", {}))
        decompression_errors = 0
        successfully_extracted = 0
        for key in self.toc.keys():
            (type_code, position, compressed_data_size) = self.toc[key]
            try:
                extraction_budget.begin_member(compressed_data_size, 0)
            except utils.ExtractionLimitError as error:
                logger.warning(f"[!] Skipping ZlibArchive entry {key!r}: {error}.")
                continue
            try:
                pyc_file = _safe_output_path(self.output_dir, key, suffix=".pyc")
            except ValueError as error:
                logger.warning(f"[!] Skipping unsafe ZlibArchive entry {key!r}: {error}.")
                continue

            if not hasattr(self, "compilation_time"):
                timestamp = None
            else:
                timestamp = self.compilation_time
            header_bytes = pydecipher.bytecode.create_pyc_header(self.magic_int, compilation_ts=timestamp, file_size=0)

            compressed_data = self.archive_contents[position : position + compressed_data_size]
            if self.encrypted:
                compressed_data = self.decrypt_file(compressed_data)
            if compressed_data is None:
                # decrypt_file returns None on failure
                decompression_errors += 1
                continue

            try:
                uncompressed_data = _decompress_limited(compressed_data, extraction_budget)
            except (zlib.error, utils.ExtractionLimitError) as e:
                decompression_errors += 1
                logger.debug(f"[!] PYZ zlib decompression failed with error: {e}")
            else:
                extraction_budget.commit_payload(compressed_data_size, len(uncompressed_data))
                self.output_dir.mkdir(parents=True, exist_ok=True)
                with pyc_file.open("wb") as pyc_file_ptr:
                    pyc_file_ptr.write(header_bytes + uncompressed_data)
                successfully_extracted += 1

        if decompression_errors:
            logger.debug(f"[!] Failed to write {decompression_errors} files due to decompression errors.")
        if successfully_extracted:
            logger.info(f"[+] Successfully extracted {successfully_extracted} files from this ZlibArchive.")

    def unpack(self) -> None:
        self.check_for_password_file()
        self.parse_toc()
        if self.toc:
            self.extract_files()
