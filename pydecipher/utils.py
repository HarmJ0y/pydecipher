# -*- coding: utf-8 -*-
"""General utility functions that may be useful across the module."""
import os
import pathlib
import re
import stat
import string
import sys
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Generator, List, Set, Tuple

import xdis

from pydecipher import logger

__all__ = [
    "ExtractionBudget",
    "ExtractionLimitError",
    "get_extraction_budget",
    "next_recursion_kwargs",
    "read_limited",
    "open_existing_file",
    "open_output_file",
    "make_output_directory",
    "slugify",
    "safe_output_path",
    "parse_for_strings",
    "parse_for_version_strings",
    "rglob_limit_depth",
    "check_read_access",
    "check_write_access",
    "check_for_our_xdis",
]


class ExtractionLimitError(RuntimeError):
    """Raised when recursive extraction exceeds a configured safety limit."""


@dataclass
class ExtractionBudget:
    """Shared limits and accounting for one recursive extraction tree."""

    max_member_size: int = 256 * 1024 * 1024
    max_total_size: int = 1024 * 1024 * 1024
    max_members: int = 10000
    max_compression_ratio: int = 1000
    max_recursion_depth: int = 10
    total_size: int = 0
    member_count: int = 0

    def begin_member(self, compressed_size: int, declared_size: int) -> None:
        """Account for a member and reject unsafe declared metadata."""
        if compressed_size < 0 or declared_size < 0:
            raise ExtractionLimitError("archive member has a negative size")
        if self.member_count >= self.max_members:
            raise ExtractionLimitError(f"archive tree exceeds {self.max_members} members")
        self.member_count += 1
        self.validate_payload(compressed_size, declared_size)

    def validate_payload(self, compressed_size: int, output_size: int) -> None:
        """Check a member's actual or declared expansion without accounting it."""
        if output_size < 0 or compressed_size < 0:
            raise ExtractionLimitError("archive member has a negative size")
        if output_size > self.max_member_size:
            raise ExtractionLimitError(f"archive member exceeds {self.max_member_size} bytes")
        if self.total_size + output_size > self.max_total_size:
            raise ExtractionLimitError(f"archive tree exceeds {self.max_total_size} extracted bytes")
        if compressed_size == 0:
            if output_size:
                raise ExtractionLimitError("non-empty archive member has zero compressed size")
        elif output_size > compressed_size * self.max_compression_ratio:
            raise ExtractionLimitError(
                f"archive member exceeds the {self.max_compression_ratio}:1 compression ratio limit"
            )

    def commit_payload(self, compressed_size: int, output_size: int) -> None:
        """Validate and account for a successfully processed member payload."""
        self.validate_payload(compressed_size, output_size)
        self.total_size += output_size


def read_limited(input_file, max_size: int) -> bytes:
    """Read at most ``max_size`` bytes and reject larger input streams."""
    if max_size <= 0:
        raise ValueError("maximum input size must be a positive integer")

    chunks = []
    remaining = max_size + 1
    while remaining:
        chunk = input_file.read(min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    contents = b"".join(chunks)
    if len(contents) > max_size:
        raise ExtractionLimitError(f"artifact exceeds {max_size} input bytes")
    return contents


def get_extraction_budget(kwargs) -> ExtractionBudget:
    """Return the shared extraction budget stored in an artifact's kwargs."""
    budget = kwargs.get("_extraction_budget")
    if budget is None:
        budget = ExtractionBudget(
            max_member_size=int(kwargs.get("max_member_size", ExtractionBudget.max_member_size)),
            max_total_size=int(kwargs.get("max_total_size", ExtractionBudget.max_total_size)),
            max_members=int(kwargs.get("max_members", ExtractionBudget.max_members)),
            max_compression_ratio=int(
                kwargs.get("max_compression_ratio", ExtractionBudget.max_compression_ratio)
            ),
            max_recursion_depth=int(kwargs.get("max_recursion_depth", ExtractionBudget.max_recursion_depth)),
        )
        if any(
            limit <= 0
            for limit in (
                budget.max_member_size,
                budget.max_total_size,
                budget.max_members,
                budget.max_compression_ratio,
                budget.max_recursion_depth,
            )
        ):
            raise ValueError("extraction limits must be positive integers")
        kwargs["_extraction_budget"] = budget
    return budget


def next_recursion_kwargs(kwargs) -> dict:
    """Copy artifact kwargs and advance the guarded recursion depth."""
    budget = get_extraction_budget(kwargs)
    recursion_depth = int(kwargs.get("_recursion_depth", 0))
    if recursion_depth >= budget.max_recursion_depth:
        raise ExtractionLimitError(f"archive recursion exceeds {budget.max_recursion_depth} levels")
    nested_kwargs = dict(kwargs)
    nested_kwargs["_recursion_depth"] = recursion_depth + 1
    nested_kwargs["_extraction_budget"] = budget
    return nested_kwargs


def _safe_output_parts(member_name: str, suffix: str = "") -> List[str]:
    """Normalize an untrusted member name into safe relative components."""
    if not isinstance(member_name, str) or not member_name:
        raise ValueError("member name must be a non-empty string")
    if "\x00" in member_name:
        raise ValueError("member name contains a null byte")

    posix_path = pathlib.PurePosixPath(member_name)
    windows_path = pathlib.PureWindowsPath(member_name)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive or windows_path.root:
        raise ValueError("absolute member paths are not allowed")

    path_parts = []
    for part in member_name.replace("\\", "/").split("/"):
        if part == "..":
            raise ValueError("parent directory components are not allowed")
        if part not in ("", "."):
            path_parts.append(part)
    if not path_parts:
        raise ValueError("member name does not identify a file")
    if len(path_parts) > 64:
        raise ValueError("member path exceeds 64 components")
    path_parts[-1] += suffix
    return path_parts


def safe_output_path(output_dir: os.PathLike, member_name: str, suffix: str = "") -> pathlib.Path:
    """Build an untrusted member path that remains inside ``output_dir``.

    Archive and resource names may contain POSIX or Windows separators
    regardless of the current platform. Absolute paths, drive-qualified paths,
    parent traversal, null bytes, and destinations redirected by existing
    symlinks are rejected.
    """
    path_parts = _safe_output_parts(member_name, suffix=suffix)

    output_root = pathlib.Path(output_dir)
    output_root_resolved = output_root.resolve(strict=False)
    output_path = output_root.joinpath(*path_parts)
    try:
        output_path.resolve(strict=False).relative_to(output_root_resolved)
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError("member path escapes the output directory") from error

    return output_path


def _supports_secure_output_dir_fd() -> bool:
    """Return whether this platform supports descriptor-relative safe writes."""
    return (
        hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and all(function in os.supports_dir_fd for function in (os.open, os.mkdir, os.link, os.unlink))
    )


def _open_directory_chain(
    output_dir: pathlib.Path, path_parts: List[str], create_missing: bool = True
) -> List[int]:
    """Open or create a directory chain without following symlinks."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    absolute_output_dir = pathlib.Path(os.path.abspath(output_dir))
    descriptors = [os.open(absolute_output_dir.anchor, directory_flags)]
    try:
        for part in [*absolute_output_dir.parts[1:], *path_parts]:
            if create_missing:
                try:
                    os.mkdir(part, dir_fd=descriptors[-1])
                except FileExistsError:
                    pass
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise
    return descriptors


def make_output_directory(output_dir: os.PathLike, member_name: str) -> pathlib.Path:
    """Safely create an archive member directory below ``output_dir``."""
    output_path = safe_output_path(output_dir, member_name)
    path_parts = _safe_output_parts(member_name)
    if not _supports_secure_output_dir_fd():
        raise NotImplementedError("secure output directory creation is not supported on this platform")

    descriptors = _open_directory_chain(pathlib.Path(output_dir), path_parts)
    for descriptor in reversed(descriptors):
        os.close(descriptor)
    return output_path


def open_existing_file(
    path: os.PathLike, mode: str = "a", expected_identity: Tuple[int, int] = None
):
    """Open an existing regular file without following path-component symlinks."""
    if mode != "a":
        raise ValueError("existing output mode must be 'a'")
    if not _supports_secure_output_dir_fd():
        raise NotImplementedError("secure existing-file opening is not supported on this platform")

    absolute_path = pathlib.Path(os.path.abspath(path))
    descriptors = _open_directory_chain(absolute_path.parent, [], create_missing=False)
    file_fd = None
    try:
        file_fd = os.open(
            absolute_path.name,
            os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW,
            dir_fd=descriptors[-1],
        )
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("existing output is not a regular file")
        if expected_identity and (file_stat.st_dev, file_stat.st_ino) != tuple(expected_identity):
            raise ValueError("existing output identity changed")
        output_file = os.fdopen(file_fd, mode)
        file_fd = None
        return output_file
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def open_output_file(output_dir: os.PathLike, member_name: str, suffix: str = "", mode: str = "wb"):
    """Atomically open a contained output file without following symlinks.

    On platforms with descriptor-relative filesystem operations, every parent
    component is opened with ``O_NOFOLLOW`` and the completed temporary file is
    linked relative to the already-open parent directory. Existing destinations
    are never replaced.
    """
    if mode not in ("w", "wb"):
        raise ValueError("output mode must be 'w' or 'wb'")

    output_path = safe_output_path(output_dir, member_name, suffix=suffix)
    path_parts = _safe_output_parts(member_name, suffix=suffix)

    if not _supports_secure_output_dir_fd():
        raise NotImplementedError("secure output creation is not supported on this platform")

    descriptors = _open_directory_chain(pathlib.Path(output_dir), path_parts[:-1])
    parent_fd = descriptors[-1]
    temporary_name = f".{path_parts[-1]}.{uuid.uuid4().hex}.tmp"
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    temporary_fd = None
    try:
        temporary_fd = os.open(temporary_name, open_flags, 0o666, dir_fd=parent_fd)
        with os.fdopen(temporary_fd, mode) as output_file:
            temporary_fd = None
            temporary_stat = os.fstat(output_file.fileno())
            temporary_identity = (temporary_stat.st_dev, temporary_stat.st_ino)
            yield output_path, output_file
        os.link(
            temporary_name,
            path_parts[-1],
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        published_stat = os.stat(path_parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(published_stat.st_mode) or (
            published_stat.st_dev,
            published_stat.st_ino,
        ) != temporary_identity:
            os.unlink(path_parts[-1], dir_fd=parent_fd)
            raise ValueError("temporary output identity changed before publication")
    except Exception:
        if temporary_fd is not None:
            os.close(temporary_fd)
        raise
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def slugify(value: str, allow_unicode: bool = False) -> str:
    """Take a string and remove any potentially 'problematic' characters.

    Note
    ----
        This function is `taken from Django's codebase`_.

    Converts a string to a URL slug by:

    #. Converting to ASCII if allow_unicode is False (the default).
    #. Removing characters that aren’t alphanumerics, underscores, hyphens, or
       whitespace.
    #. Removing leading and trailing whitespace.
    #. Converting to lowercase.
    #. Replacing any whitespace or repeated dashes with single dashes.

    .. _taken from Django's codebase:
        https://github.com/django/django/blob/stable/3.0.x/django/utils/text.py#L393

    Parameters
    ----------
    value: str
        The string to be converted
    allow_unicode: bool
        Whether or not to allow unicode characters.

    Returns
    -------
    str
        The cleaned string.
    """
    value: str = str(value)
    if allow_unicode:
        value = unicodedata.normalize("NFKC", value)
    else:
        value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def parse_for_strings(data: bytes) -> Set[str]:
    """Given a blob of data, will return a set of all the readable/printable strings.

    Parameters
    ----------
    data: bytes
        The data to search for printable strings.

    Returns
    -------
    Set[str]
        A set of the printable strings in this data.

    """
    strings: set = set()
    current_string: str = ""
    byte: bytes
    for byte in bytearray(data):
        try:
            char: str = chr(byte)
            if char not in string.printable:
                raise ValueError
            current_string += char
        except ValueError:
            if current_string:
                strings.add(current_string)
            current_string = ""
    if current_string:
        strings.add(current_string)
    return strings


def parse_for_version_strings(data: bytes, formats=[r"[0-9](?:\.[0-9]+)+", "(?<=(python))[0-9]{2}"]) -> List[str]:
    """Search for Python version numbers within a blob of data.

    Parameters
    ----------
    data: bytes
        The data to search for version strings.

    Returns
    -------
    List[Tuple[str, str]]
        The Python versions found, along with the the strings that contain those version
        numbers. Format is (version_number, string_that_contained_version_number).
    """
    data_utf8: str = data.decode("utf-8", "ignore")
    data_utf16: str = data.decode("utf-16", "ignore")
    data: str = data_utf8 + data_utf16

    matches: List[Tuple[str, str]] = []
    fmt: str
    for fmt in formats:
        match_indices: List[Tuple[str, Tuple[int, int]]] = [
            (m.group(), m.span()) for m in re.finditer(fmt, data, re.IGNORECASE)
        ]
        # This builds a list of the following format:
        #   [
        #       ('match1', (match_1_start_index, match_1_end_index)),
        #       ('match2', (match_2_start_index, match_2_end_index)),
        #       ('match3', (match_3_start_index, match_3_end_index))...
        #   ]
        #  The indices are integers indexing where the matches were found in the
        #  datastream.
        match_tuple: Tuple[str, Tuple[int, int]]
        for match_tuple in match_indices:
            match: str = match_tuple[0]
            start_idx: int = match_tuple[1][0]
            end_idx: int = match_tuple[1][1]

            # Maximum amount of bytes we should give surrounding each match
            surrounding_bytes_length: int = 50
            lower_limit: int = start_idx
            higher_limit: int = end_idx
            i: int
            for i in range(1, min(surrounding_bytes_length, start_idx + 1)):
                if data[start_idx - i] in string.printable:
                    lower_limit = start_idx - i
                else:
                    break
            for i in range(0, min(surrounding_bytes_length, len(data) - end_idx)):
                if data[end_idx + i] in string.printable:
                    higher_limit = end_idx + i + 1
                else:
                    break
            surrounding_bytes: str = data[lower_limit:higher_limit]
            matches.append((match, surrounding_bytes))

    valid_matches: List[Tuple[str, str]] = []
    match_bytes_tuple: Tuple[str, str]
    for match_bytes_tuple in matches:
        match: str = match_bytes_tuple[0]
        if len(match) == 2 and match.isnumeric():
            # makes 27 -> 2.7
            match = f"{match[0]}.{match[1]}"
        if match not in xdis.magics.canonic_python_version.keys():
            continue
        valid_matches.append(match_bytes_tuple)

    valid_matches = list(set(valid_matches))  # unique-ifies this list
    valid_matches.sort(key=lambda x: x[0])  # sort by increasing version number
    return valid_matches


def rglob_limit_depth(path_obj: pathlib.Path, pattern: str, n: int = 1) -> Generator[os.PathLike, None, None]:
    """Path object rglob, but allows for limit to depth of recursive search.

    Parameters
    ----------
    path_obj: pathlib.Path
        The path to recursively search for the pattern.
    pattern: str
        The pattern to search for.
    n: int
        The maximum recursive depth.

    Yields
    ------
    pathlib.Path
        A path matching the given pattern.
    """
    baseline_path_depth: int = len(list(path_obj.parents))
    p: pathlib.Path
    for p in path_obj.rglob(pattern):
        if len(p.parents) <= (baseline_path_depth + n):
            yield p


def check_read_access(path: pathlib.Path) -> None:
    """Verify that we can read successfully from the given file path.

    Parameters
    ----------
    path: os.PathLike
        The path to check.
    """
    if not path.exists():
        msg: str = f"[!] Could not find the provided path: {str(path)}."
        raise FileNotFoundError(msg)
    if not os.access(path, os.R_OK):
        msg: str = f"[!] Lacking read permissions on: {str(path)}."
        raise PermissionError(msg)


def check_write_access(path: pathlib.Path) -> None:
    """Verify that we can write successfully to the given file path.

    Parameters
    ----------
    path: pathlib.Path
        The path to check.
    """
    if not path.parent.exists():
        msg: str = "[!] Parent of output directory does not exist. Cannot write here."
        raise NotADirectoryError(msg)
    if not os.access(path.parent, os.W_OK):
        msg: str = f"[!] Cannot write output directory to dir: {str(path)}."
        raise PermissionError(msg)


def check_for_our_xdis() -> None:
    """Check that the pydecipher fork of xdis is installed.

    Exits if its not.
    """
    if hasattr(xdis.op_imports, "remap_opcodes"):
        logger.debug("[*] Custom version of xdis detected. All clear to proceed.")
    else:
        logger.error(
            "[!] It seems that the public/normal version of xdis has been installed. Please see the documentation"
            "on how to download the pydecipher-customized fork of xdis."
        )
        sys.exit(1)
