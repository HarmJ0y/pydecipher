# PE PyInstaller Corpus Run

Date: 2026-07-30

## Scope

- Input artifacts are PE32 or PE32+ Windows executables.
- Every artifact has an EOF-aligned PyInstaller cookie and is recognized by
  `pyinstxtractor`; plain PE files and `MEI` string false positives are excluded.
- Extraction is static. No sample was executed.

## Sources

- `ytisf/theZoo`: 263 password-protected malware archives scanned; two genuine
  PyInstaller PE files retained from eleven `MEI` candidates.
- `infosecstreams/huntress2023`: the malicious `Snake Oil`, `Snake Eater`, and
  `Snake Eater II` Windows challenges.

The five raw PE files are in the ignored local directory
`.corpus/pe-pyinstaller/samples/`. Run logs are under
`.corpus/pe-pyinstaller/runs/`. Extracted files were deleted after validation so
the retained corpus remains PE-only.

## Results

| SHA256 prefix | PE | Python | Oracle CArchive | PyDecipher PYZ | Result |
| --- | --- | --- | ---: | ---: | --- |
| `251018d2b57e` | PE32 x86 | 3.6 | 7 | 135 | exit 0; 6 PYC decompiled |
| `b000a0095a8f` | PE32 x86 | 3.8 | 75 | 500 | exit 0; 6 PYC decompiled, 2 decompiler failures |
| `2d54f5288fb9` | PE32+ x64 | 3.9 | 963 | 505 | exit 0; decompiler unsupported |
| `dd042c46ccab` | PE32+ x64 | 3.11 | 22 | 100 | exit 0; 8 CArchive PYC files recovered |
| `803441e8f57b` | PE32+ x64 | 3.11 | 22 | 100 | exit 0; 8 CArchive PYC files recovered |

All five PE and CArchive layers were recognized and all available PYZ entries
were extracted. No crash or file-boundary violation occurred.

## Fixed Compatibility Finding

Python 3.11's CArchive cookie version `311` was formatted as `31.1`. Modern raw
marshal entries were also mistaken for invalid PYC headers. Cookie versions now
preserve multi-digit minors, and the cookie-derived xdis magic is used when no
valid embedded PYC header exists. Both Python 3.11 samples now recover all eight
expected CArchive PYC files. Decompilation remains unavailable because the
installed uncompyle6/decompyle3 versions do not support Python 3.11.

## Reproduction

```bash
for f in .corpus/pe-pyinstaller/samples/*.exe; do
  n=${f##*/}; n=${n%.exe}
  mkdir -p ".corpus/pe-pyinstaller/runs/$n"
  timeout 45 .venv/bin/pydecipher "$f" \
    --output ".corpus/pe-pyinstaller/runs/$n/output" -v \
    >".corpus/pe-pyinstaller/runs/$n/run.log" 2>&1
done
```
