# -*- coding: utf-8 -*-
"""Code for the handling of Portable Executable files within pydecipher's pipeline.

pydecipher extracts several items from PE files. First, it will search for the
PYTHONSCRIPT resource, which is an artifact from Py2Exe-frozen binaries that contains
a marshalled list of code objects related to the initialization of the user code.
Second, if the PE has extra data appended to it (the overlay), pydecipher will dump
this extra data to a separate file within the output directory for further inspection.
"""
import abc
import io
import json
import os
import pprint
import re
import pathlib
from typing import Any, BinaryIO, Dict, List, Union

import pefile
from asn1crypto import cms, pem, x509

import pydecipher
from pydecipher import logger, utils


@pydecipher.register
class PortableExecutable(metaclass=abc.ABCMeta):
    """The artifact class representing a Portable Executable Windows binary.

    Much of the functionality is just an augmentation of the pefile library
    to aid in analysis of python packaged artifacts.

    Attributes
    ----------
    file_path : pathlib.Path, optional
        If this artifact comes from a file on disk, this is the path to that file.
    file_contents : bytes
        The contents of the file read into memory.
    output_dir : os.PathLike
        Where any output extracted from this artifact should get dumped.
    python_version : str
        The version of Python used to create this frozen artifact.
    overlay: bytes
        The overlay of the PE (the data that is appended to the binary).
    pe : pefile.PE
        The pefile library PE object for this file.
    version_info : Dict[bytes, bytes]
        The version info resource of this executable stored as key:value pairs.
    certificates_dumped : bool
        Whether or not the certificates (if they exist in the PE) have been
        dumped to the output directory on disk.
    INTERESTING_RESOURCES : List[str]
        String-matching patterns for resources that should be dumped to disk if
        found within a PE.
    kwargs : Any
        Any keyword arguments needed for the parsing of this artifact, or for
        parsing nested artifacts.

    Raises
    ------
    TypeError
        Will raise a TypeError if the file_path_or_bytes item is not a recognizable PE object.
    """

    output_dir: pathlib.Path
    python_version: str = ""
    pe: pefile.PE
    file_contents: bytes
    file_path: pathlib.Path
    kwargs: Any
    overlay: bytes
    version_info: Dict[bytes, bytes] = {}
    certificates_dumped: bool = False
    INTERESTING_RESOURCES: List[str] = [
        "pythonscript",
        r"python.*\.dll",
    ]  # case-insensitive patterns for resources that should be dumped/unpacked

    def __init__(
        self,
        pe_path_or_bytes: Union[str, os.PathLike, BinaryIO],
        output_dir: os.PathLike = None,
        **kwargs,
    ) -> None:
        max_input_size = int(kwargs.get("max_input_size", utils.ExtractionBudget.max_member_size))
        if isinstance(pe_path_or_bytes, str):
            pe_path_or_bytes: pathlib.Path = pathlib.Path(pe_path_or_bytes)
        if isinstance(pe_path_or_bytes, pathlib.Path):
            utils.check_read_access(pe_path_or_bytes)
            if pe_path_or_bytes.stat().st_size > max_input_size:
                raise utils.ExtractionLimitError(f"artifact exceeds {max_input_size} input bytes")
            self.file_path = pe_path_or_bytes
            with self.file_path.open("rb") as input_file:
                self.file_contents = utils.read_limited(input_file, max_input_size)
        if isinstance(pe_path_or_bytes, io.BufferedIOBase):
            self.file_contents = utils.read_limited(pe_path_or_bytes, max_input_size)

        try:
            self.pe = pefile.PE(data=self.file_contents)
        except pefile.PEFormatError as e:
            raise TypeError(e)

        if output_dir:
            self.output_dir = output_dir
        else:
            if hasattr(self, "file_path"):
                self.output_dir = self.file_path.parent / utils.slugify(self.file_path.name + "_output")
            else:
                self.output_dir = pathlib.Path.cwd()
        utils.check_write_access(self.output_dir)
        self.kwargs = kwargs

    def dump_resource(self, resource_name: str) -> pathlib.Path:
        """Dump the specified resource to the output directory on disk.

        Parameters
        ----------
        resource_name
            The name of the resource within the PE's resources to extract.

        Returns
        -------
        pathlib.Path
            The path to the dumped resource.
        """
        entry: pefile.ResourceDirEntryData
        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            try:
                current_resource_name = entry.name.string.decode()
            except UnicodeDecodeError:
                continue
            if current_resource_name == resource_name:
                try:
                    data_entry = entry.directory.entries[0].directory.entries[0].data.struct
                    rva: int = data_entry.OffsetToData
                    size: int = data_entry.Size
                except (AttributeError, IndexError, TypeError):
                    logger.warning(f"[!] Skipping malformed PE resource {resource_name!r}.")
                    continue
                resource_data = self.pe.get_data(rva, size)
                extraction_budget = utils.get_extraction_budget(self.kwargs)
                try:
                    extraction_budget.begin_member(size, len(resource_data))
                except utils.ExtractionLimitError as error:
                    logger.warning(f"[!] Skipping PE resource {resource_name!r}: {error}.")
                    return

                try:
                    with utils.open_output_file(self.output_dir, resource_name) as (resource_dump, outfile_ptr):
                        outfile_ptr.write(resource_data)
                except (OSError, ValueError) as error:
                    logger.warning(f"[!] Skipping unsafe PE resource {resource_name!r}: {error}.")
                    return
                extraction_budget.commit_payload(size, len(resource_data))
                logger.info(f"[+] Successfully dumped PE resource {resource_name} to disk at {self.output_dir}")
                return resource_dump

    def load_version_info(self, quiet: bool = False) -> None:
        """Extract the VersionInfo dictionary from the pefile.PE object.

        If pydecipher is running in anything but 'quiet' mode, it will print
        the version info to the log. Additionally, it will search for Python
        version strings within the version info.

        Parameters
        ----------
        quiet : bool, optional
            Whether or not to print the version info dictionary to the log.
        """
        if not hasattr(self.pe, "FileInfo"):
            return
        structure: pefile.Structure
        for structure in self.pe.FileInfo:
            sub_structure: pefile.Structure
            for sub_structure in structure:
                if sub_structure.Key != b"StringFileInfo":
                    continue
                if hasattr(sub_structure, "StringTable"):
                    string_table: pefile.Structure
                    for string_table in sub_structure.StringTable:
                        if string_table.entries:
                            decoded_entries = {}
                            for key, value in string_table.entries.items():
                                try:
                                    decoded_entries[key.decode("utf-8")] = value.decode("utf-8")
                                except (AttributeError, UnicodeDecodeError):
                                    continue
                            self.version_info = decoded_entries
        formatted_version_info: Dict[str, str] = json.dumps(self.version_info, indent=4, separators=(",", ": "))
        if not quiet:
            logger.debug(f"[*] This PE had the following VersionInfo resource: {formatted_version_info}")

        if "python" in str(self.version_info).lower():
            if "FileVersion" in self.version_info:
                self.python_version = self.version_info["FileVersion"]
            if "ProductVersion" in self.version_info:
                if self.python_version and len(self.python_version) < len(self.version_info["ProductVersion"]):
                    # assume longer string means more detailed version info (we'd rather know it was 2.7.14 vs just 2.7)
                    self.python_version = self.version_info["ProductVersion"]

    def dump_certificates(self, output_dir: pathlib.Path = None) -> None:
        """Dump Authenticode certificates from the PE's certificate attribute table.

        Parameters
        ----------
        output_dir: pathlib.Path, optional
            An optional alternative output directory to dump the certificates, besides
            the class's output directory.
        """
        certificate_table_entry: pefile.Structure = None
        if hasattr(self.pe, "OPTIONAL_HEADER") and hasattr(self.pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            idx: int
            for idx in range(len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
                directory: pefile.Structure = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
                if directory.name == "IMAGE_DIRECTORY_ENTRY_SECURITY" and directory.Size:
                    logger.debug("[*] This PE has a certificate table.")
                    certificate_table_entry = directory
                    break

        if certificate_table_entry is None:
            return

        if output_dir is None:
            certificate_extraction_dir = self.output_dir.joinpath("Authenticode_Certificates")
        else:
            certificate_extraction_dir = pathlib.Path(output_dir)
        try:
            utils.make_output_directory(
                certificate_extraction_dir.parent,
                certificate_extraction_dir.name,
            )
        except (OSError, ValueError) as error:
            logger.warning(f"[!] Could not safely create certificate output directory: {error}.")
            return

        certificate_start = certificate_table_entry.VirtualAddress
        certificate_end = certificate_start + certificate_table_entry.Size
        certificate_table_data: bytes = self.pe.__data__[certificate_start:certificate_end]
        while certificate_table_data:
            # https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#the-attribute-certificate-table-image-only
            if len(certificate_table_data) < 8:
                logger.warning("[!] Certificate table ends with a truncated WIN_CERTIFICATE header.")
                break
            cert_length: int = int.from_bytes(certificate_table_data[0:4], byteorder="little")
            if cert_length < 8 or cert_length > len(certificate_table_data):
                logger.warning(f"[!] Certificate table contains an invalid record length: {cert_length}.")
                break
            cert_version: bytes = certificate_table_data[4:6]  # noqa
            cert_type = certificate_table_data[6:8]  # noqa
            cert: bytes = certificate_table_data[8:cert_length]
            aligned_length = (cert_length + 7) & ~7
            certificate_table_data = certificate_table_data[aligned_length:]

            # Extract all the X509 certificates from the PKCS#7 structure using asn1crypto
            try:
                content_info = cms.ContentInfo.load(cert)
                if content_info["content_type"].native != "signed_data":
                    continue
                signed_data = content_info["content"]
                certificates = signed_data["certificates"]
            except Exception as e:
                logger.debug(f"[!] Failed to parse PKCS#7 structure: {e}")
                continue

            unnamed_certificate_index = 0
            for cert_choice in certificates:
                if cert_choice.name != "certificate":
                    continue
                cert_obj: x509.Certificate = cert_choice.chosen
                subject = cert_obj.subject

                # Get a human-readable name for the certificate file
                preferred_name_fields: List[str] = [
                    "organizational_unit_name",
                    "organization_name",
                    "common_name",
                ]
                cert_name: str = None
                for field_name in preferred_name_fields:
                    value = subject.native.get(field_name)
                    if value:
                        cert_name = value if isinstance(value, str) else value[0]
                        break
                if not cert_name:
                    cert_name = str(unnamed_certificate_index)
                    unnamed_certificate_index += 1
                cert_name = utils.slugify(cert_name, allow_unicode=True) + ".pem"

                logger.debug(f"[+] Extracting Authenticode certificate {cert_name}.")
                der_bytes: bytes = cert_obj.dump()
                pem_bytes: bytes = pem.armor("CERTIFICATE", der_bytes)
                extraction_budget = utils.get_extraction_budget(self.kwargs)
                try:
                    extraction_budget.begin_member(len(der_bytes), len(pem_bytes))
                except utils.ExtractionLimitError as error:
                    logger.warning(f"[!] Skipping Authenticode certificate {cert_name!r}: {error}.")
                    continue
                try:
                    with utils.open_output_file(certificate_extraction_dir, cert_name) as (_, f):
                        f.write(pem_bytes)
                except (OSError, ValueError) as error:
                    logger.warning(f"[!] Skipping occupied certificate output {cert_name!r}: {error}.")
                    continue
                extraction_budget.commit_payload(len(der_bytes), len(pem_bytes))
        self.certificates_dumped = True

    def dump_overlay(self) -> pathlib.Path:
        """
        Check to see if this binary has data appended, and if so, dump it for further analysis.

        python's pefile library puts the certificate table in the overlay section even
        though its not really traditional overlay data.

        Relevant links:
        https://github.com/erocarrera/pefile/issues/104#issuecomment-429037686
        https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
        https://blog.barthe.ph/2009/02/22/change-signed-executable/

        Returns
        -------
        pathlib.Path
            The path to the dumped overlay on disk.
        """
        certificate_table_entry: pefile.Structure = None
        if hasattr(self.pe, "OPTIONAL_HEADER") and hasattr(self.pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            idx: int
            for idx in range(len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
                directory: pefile.Structure = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
                if directory.name == "IMAGE_DIRECTORY_ENTRY_SECURITY" and directory.Size:
                    certificate_table_entry = directory
                    break

        # Get overlay data, excluding certificate table if its there
        if certificate_table_entry:
            overlay_start: int = self.pe.get_overlay_data_start_offset()
            certificate_start: int = certificate_table_entry.VirtualAddress
            certificate_end = certificate_start + certificate_table_entry.Size
            self.overlay = (
                self.pe.__data__[overlay_start:certificate_start]
                + self.pe.__data__[certificate_end:]
            )
        else:
            self.overlay = self.pe.get_overlay()

        if self.overlay:
            extraction_budget = utils.get_extraction_budget(self.kwargs)
            try:
                extraction_budget.begin_member(len(self.overlay), len(self.overlay))
            except utils.ExtractionLimitError as error:
                logger.warning(f"[!] Skipping PE overlay: {error}.")
                return
            try:
                with utils.open_output_file(self.output_dir, "overlay_data") as (overlay_path, overlay_file_ptr):
                    overlay_file_ptr.write(self.overlay)
            except (OSError, ValueError) as error:
                logger.warning(f"[!] Skipping occupied PE overlay output: {error}.")
                return
            extraction_budget.commit_payload(len(self.overlay), len(self.overlay))
            logger.info(f"[+] Dumped this PE's overlay data to {overlay_path.relative_to(self.output_dir.parent)}")
            return overlay_path

    def unpack(self) -> None:
        """Dump any interesting aspects of this PE for further investigation.

        This will log the PEs version info resource for manual inspection,
        dump any Authenticode certificates, and look for frozen Python artifacts
        within the PE's resources and overlay.
        """
        self.load_version_info()
        self.dump_certificates()

        unpack_me: List[pathlib.Path] = []
        overlay_path: pathlib.Path = self.dump_overlay()
        if overlay_path:
            unpack_me.append(overlay_path)

        version_strings: List[str] = utils.parse_for_version_strings(self.file_contents)
        if version_strings:
            logger.debug(
                "[*] Found the following strings (and their surrounding bytes, for context) in this PE, which may "
                "indicate the version of Python used to freeze the executable: \n"
                f"{pprint.pformat(version_strings, width=120)}"
            )

        pythonscript_idx: int = None
        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            entry: pefile.ResourceDirEntryData
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.name is None:
                    continue
                try:
                    resource_name: str = entry.name.string.decode()
                except UnicodeDecodeError:
                    logger.warning("[!] Skipping PE resource with an invalid UTF-8 name.")
                    continue
                if any(re.fullmatch(pattern, resource_name, re.I) for pattern in self.INTERESTING_RESOURCES):
                    resource_path: pathlib.Path = self.dump_resource(resource_name)
                    if resource_path is None:
                        continue
                    if resource_name == "PYTHONSCRIPT":
                        pythonscript_idx = len(unpack_me)
                    unpack_me.append(resource_path)

        if pythonscript_idx:
            # We want to unpack Py2Exe PYTHONSCRIPT last to give it highest chance of successfully determining version.
            unpack_me.append(unpack_me.pop(pythonscript_idx))

        artifact_path: pathlib.Path
        for artifact_path in unpack_me:
            output_dir_name: str = utils.slugify(str(artifact_path.name) + "_output")
            try:
                nested_kwargs = utils.next_recursion_kwargs(self.kwargs)
                pydecipher.unpack(
                    artifact_path,
                    output_dir=self.output_dir.joinpath(output_dir_name),
                    **nested_kwargs,
                )
            except utils.ExtractionLimitError as error:
                logger.warning(f"[!] Skipping nested PE artifact {artifact_path}: {error}.")
