# PE Wipe
A tool for stripping all sensitive or unused data from [PE images](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) using only the Windows Native API.

## Overview
All of the stripped data will be set to zero - that means your file size and structure will remain the same. Strips sensitive data like `.pdb` paths, compiler, linker or debug information. Also strips unused data by the Windows Loader like timestamps, section names, flags and more.

## Usage
Download the latest release from the [releases page][RELEASES_PAGE].
```
Usage: pe-wipe <filename> [options]
Options:
   -v              Display verbose processing information.
   -frich          Wipe Rich header.
   -fcoff          Wipe COFF header.
   -fcoff-ts       Wipe COFF header timestamp only.
   -fopt           Wipe Optional header.
   -fopt-lv        Wipe Optional header linker version only.
   -fopt-v         Wipe Optional header version only.
   -fsec           Wipe Section headers.
   -fsec-n         Wipe Section headers names only.
   -fsec-f         Wipe Section headers unused flags only.
   -fexp           Wipe Export directory.
   -fexp-ts        Wipe Export directory timestamp only.
   -fexp-v         Wipe Export directory version only.
   -fres           Wipe Resource directory.
   -fres-ts        Wipe Resource directory timestamp only.
   -fres-v         Wipe Resource directory version only.
   -fdbg           Wipe Debug directory.
   -fdbg-ts        Wipe Debug directory timestamp only.
   -fdbg-v         Wipe Debug directory version only.
   -fcfg           Wipe LoadConfig directory.
   -fcfg-ts        Wipe LoadConfig directory timestamp only.
   -fcfg-v         Wipe LoadConfig directory version only.
   -fts            Wipe all timestamp fields only.
   -fv             Wipe all version fields only.
   -cs             Generate PE checksum.
```

## Features
- Cross-compatibility
  - x86/x64 both support PE32/PE32+ binaries
- Strips all sensitive/unused data from:
  - Rich header
  - COFF header
  - Optional header
  - Section headers
  - Export directory
  - Resource directory
  - Debug directory
  - LoadConfig directory

## Credits
- https://github.com/winsiderss/phnt by [winsiderss](https://github.com/winsiderss/) (Windows Native API headers)

[RELEASES_PAGE]: https://github.com/kalhotky/pe-wipe/releases