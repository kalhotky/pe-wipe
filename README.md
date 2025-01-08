# PE Wipe
A tool for stripping metadata from [PE images](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## Overview
This project uses only the Windows Native API. All of the stripped metadata will be set to zero - that means your file size and structure will remain the same. Strips metadata like `.pdb` paths, compiler, linker or debug information. Also strips unused data by the Windows Loader like timestamps, section names, descriptive flags and more.

## Usage
Download the latest release from the [releases page][RELEASES_PAGE].
```
Usage: pe-wipe <filename> [options]
Options:
   -v              Display verbose processing information.
   -cs             Generate PE checksum.

   -rich           Wipe Rich header.
   -coff           Wipe COFF header.
   -opt            Wipe Optional header.
   -sec            Wipe Section header(s).
   -exp            Wipe Export directory.
   -res            Wipe Resource directory.
   -dbg            Wipe Debug directory.
   -cfg            Wipe LoadConfig directory.

   -fopt-lv        Keep Optional header linker version.
   -fsec-n         Keep Section header(s) name(s).
   -fsec-f         Keep Section header(s) descriptive flags.
   -fts            Keep all timestamp fields.
   -fv             Keep all version fields.
```
Both x86 and x64 builds support PE32/PE32+ binaries.

## Dependencies
- https://github.com/kalhotky/phnt

[RELEASES_PAGE]: https://github.com/kalhotky/pe-wipe/releases