# -*- coding: utf-8 -*-
import io
import os
import pathlib
import re
import shutil
import struct
import tempfile
from contextlib import redirect_stderr
from pathlib import Path
from pathlib import PureWindowsPath
from typing import BinaryIO
from typing import Union

import xdis
from xdis.magics import magic2int
from xdis.magics import magicint2version
from xdis.unmarshal import load_code

import pydecipher
from pydecipher import logger
from pydecipher import utils
from pydecipher.artifact_types.pe import PortableExecutable
from pydecipher.bytecode import version_str_to_magic_num_int

# When we don't know exactly what version of Python was used to create
BRUTE_FORCE_SUFFIX = ".BF.pyc"


@pydecipher.register
class PYTHONSCRIPT:

    PYTHONSCRIPT_MAGIC: int = 0x78563412

    magic_value: int  # first four bytes of resource
    optimization_level: int  # Py2Exe bytecode optimization flag/setting
    unbuffered_flag: bool  # Py2Exe unbuffered flag  # TODO make this better
    code_len: int  # Size of resource file in bytes
    python_version: str = ""  # major version in float form (i.e. '2.7' or '3.6')
    magic_num: int = -1  # THE magic number to use when disassembling/decompiling this resource
    marshalled_obj_start_idx: int = -1  # index of marshalled object (after the Py2Exe header + archive name)
    archive_name = ""  # name of archive, if built into PE overlay

    def __init__(
        self,
        pythonscript_path_or_bytes: Union[str, os.PathLike, BinaryIO],
        output_dir: os.PathLike = None,
        **kwargs,
    ):
        max_input_size = int(kwargs.get("max_input_size", utils.ExtractionBudget.max_member_size))
        if isinstance(pythonscript_path_or_bytes, str):
            pythonscript_path_or_bytes: Path = Path(pythonscript_path_or_bytes)
            # TODO try a path resolve here and fail if not working
        if isinstance(pythonscript_path_or_bytes, Path):
            if not pythonscript_path_or_bytes.exists():
                msg = f"[!] Could not find the provided path: {str(pythonscript_path_or_bytes)}."
                raise FileNotFoundError(msg)
            if not os.access(pythonscript_path_or_bytes, os.R_OK):
                msg = f"[!] Lacking read permissions on: {str(pythonscript_path_or_bytes)}."
                raise PermissionError(msg)
            if pythonscript_path_or_bytes.stat().st_size > max_input_size:
                raise utils.ExtractionLimitError(f"artifact exceeds {max_input_size} input bytes")
            self.archive_path = pythonscript_path_or_bytes
            with self.archive_path.open("rb") as input_file:
                self.resource_contents = utils.read_limited(input_file, max_input_size)
        if isinstance(pythonscript_path_or_bytes, io.BufferedIOBase):
            self.resource_contents = utils.read_limited(pythonscript_path_or_bytes, max_input_size)

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

        if not self.validate_pythonscript_resource():
            raise TypeError("[!] This is not a Py2Exe PYTHONSCRIPT resource.")

        self.version_hint = kwargs.get("version_hint", None)
        if self.version_hint:
            try:
                self.magic_num = version_str_to_magic_num_int(self.version_hint)
            except:
                pass  # TODO improve this error handling
        self.kwargs = kwargs

    def validate_pythonscript_resource(self):
        header_size = struct.calcsize(b"iiii")  # TODO check if this should be B for unbuffered flag
        try:
            (
                self.magic_value,
                self.optimization_level,
                self.unbuffered_flag,
                self.code_len,
            ) = struct.unpack(b"iiii", self.resource_contents[:header_size])
        except struct.error:
            return False

        if self.magic_value != self.PYTHONSCRIPT_MAGIC:
            return False

        first_null = self.resource_contents[header_size:].find(b"\00")
        if first_null == -1:
            return False
        self.marshalled_obj_start_idx = header_size + first_null + 1
        self.archive_name = self.resource_contents[header_size : header_size + first_null]
        if self.archive_name:
            try:
                self.archive_name = self.archive_name.decode()
            except UnicodeDecodeError:
                return False

        return True

    def _determine_python_version(self):
        """Will attempt to determine what version of python was used when this
        py2exe PE was compiled. We need to know this because xdis requires
        knowledge of the python version to unmarshal the bytecode correctly"""
        potential_magic_nums = set()
        logger.debug("[*] Attempting to discover version for PYTHONSCRIPT resource")

        # Method 1: Looking for PythonXY.DLL resource in the same directory as the PYTHONSCRIPT resource. If there,
        # check to see if it has a VERSIONINFO resource with a FileVersion or ProductVersion field,
        # as these typically contain the python version. See https://github.com/erocarrera/pefile for more info on
        # the structures used below
        if hasattr(self, "archive_path"):
            parent_dir = self.archive_path.parents[0]
        else:
            parent_dir = pathlib.Path.cwd()
        for python_dll in os.listdir(parent_dir):
            if re.match(r"python[0-9]{0,2}\.dll", python_dll, re.I):
                logger.debug(f"[*] Found python DLL resource {str(python_dll)} in directory {parent_dir}")
                try:
                    dll_class_inst = PortableExecutable(parent_dir.joinpath(python_dll))
                except TypeError:
                    logger.debug(f"[!] PyDecipher could not create a PE/DLL class instance for {str(python_dll)}")
                else:
                    dll_class_inst.load_version_info(quiet=True)
                    if dll_class_inst.python_version:
                        potential_magic_nums.add(version_str_to_magic_num_int(dll_class_inst.python_version))
                finally:
                    break

        # Method 2: Check to see if there are pyc files in the same directory with magic numbers
        for pyc_file in parent_dir.rglob("*.pyc"):
            if pyc_file.is_symlink():
                continue
            with pyc_file.open("rb") as pyc_file_ptr:
                try:
                    magic_bytes = pyc_file_ptr.read(4)
                    magic_num = magic2int(magic_bytes)
                except:  # TODO make more specific error catching
                    pass
                else:
                    potential_magic_nums.add(magic_num)
            break

        # Searching the PYTHONSCRIPT resource for strings like c:\python24\lib\site-packages\py2exe\boot_common.py
        b_python_regex = re.compile(b"(python)([0-9]{2})", re.I)
        script_re_obj = b_python_regex.search(self.resource_contents)
        if script_re_obj:
            version_str = script_re_obj.group(2).decode("utf-8")
            logger.info(
                "[*] Detected potential version string in PYTHONSCRIPT resource: {}".format(
                    script_re_obj.group().decode("utf-8")
                )
            )
            potential_magic_nums.add(version_str_to_magic_num_int(version_str[0] + "." + version_str[1]))

        if potential_magic_nums:
            logger.info(f"[*] Will attempt to unmarshal using these python magic numbers: {potential_magic_nums}")
            return potential_magic_nums
        else:
            logger.info(
                "[!] Couldn't find any python magic numbers to hint at the python version of this resource. "
                "Will attempt to brute-force determine the correct magic number."
            )
            return

    def _clean_filename(self, filename: str) -> str:
        new_filename: str = filename
        if "\\" in new_filename:
            new_filename: PureWindowsPath = pathlib.PureWindowsPath(new_filename)
        else:
            new_filename: Path = pathlib.Path(new_filename)

        new_filename: str = re.sub(
            r"[^0-9a-zA-Z._-]+", "", new_filename.name
        )  # removing filename chars that aren't numbers, letters, periods, hyphens, or underscores
        new_filename: str = re.sub(r"\.py[a-z]*", "", new_filename)  # stripping any .pyc, .py, .pyo, .pyw etc extension

        new_filename += ".pyc"
        return new_filename

    def disassemble_and_dump(self, brute_force: bool = False):
        code_bytes = self.resource_contents[self.marshalled_obj_start_idx :]
        extraction_budget = utils.get_extraction_budget(getattr(self, "kwargs", {}))
        hijacked_stderr = io.StringIO()
        with redirect_stderr(hijacked_stderr):
            try:  # TODO make this more specific error catching
                code_objects = load_code(code_bytes, self.magic_num)
                if not isinstance(code_objects, list):
                    # TODO make this a non-generic error
                    raise RuntimeError("Py2Exe should return a marshalled list of code objects")
                if not all(code_objects):
                    raise RuntimeError("NoneType code objects returned")
            except Exception:
                logger.debug(
                    f"[!] Failed to produce disassembly of bytecode with magic num {self.magic_num} "
                    f"(Python version {magicint2version[self.magic_num]})"
                )
                self.magic_num = -1
                return
            else:
                logger.info(
                    f"[+] Successfully disassembled bytecode with magic number {self.magic_num}, "
                    f"corresponding to Python version {magicint2version[self.magic_num]}"
                )

        for co in code_objects:
            new_filename: str = self._clean_filename(co.co_filename)
            if brute_force:
                member_name = f"{magicint2version[self.magic_num]}/{new_filename}"
            else:
                member_name = new_filename

            try:
                with tempfile.NamedTemporaryFile(suffix=".pyc") as temporary_file:
                    xdis.load.write_bytecode_file(temporary_file.name, co, self.magic_num)
                    generated_size = os.fstat(temporary_file.fileno()).st_size
                    extraction_budget.begin_member(generated_size, generated_size)
                    temporary_file.seek(0)
                    with utils.open_output_file(self.output_dir, member_name) as (bytecode_filepath, output_file):
                        shutil.copyfileobj(temporary_file, output_file)
                    extraction_budget.commit_payload(generated_size, generated_size)
            except Exception as e:
                logger.error(f"[!] Could not write file {member_name} with error: {e}")
            else:
                logger.info(f"[+] Successfully wrote file {new_filename} to {self.output_dir}")

    @staticmethod
    def cleanup(output_dir: pathlib.Path):
        """Leave extraction output intact; discovered paths are not safe cleanup targets."""
        return

    def unpack(self):
        """Dump the pyc file from the Py2Exe object."""
        if self.archive_name:
            logger.info(f"[*] Archive name: {self.archive_name}")

        if self.magic_num == -1:
            potential_magic_nums = self._determine_python_version() or set()
            for magic_num in potential_magic_nums:
                self.magic_num = magic_num
                self.disassemble_and_dump()
        else:
            self.disassemble_and_dump()

        if self.magic_num == -1:
            # Brute force disassembly because we still don't know what version was used
            max_version_attempts = int(self.kwargs.get("max_version_attempts", 8))
            all_magic_nums = sorted(magicint2version, reverse=True)[:max_version_attempts]
            for magic_num in all_magic_nums:
                self.magic_num = magic_num
                self.disassemble_and_dump(brute_force=True)
