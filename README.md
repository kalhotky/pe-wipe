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
   -frich          Don't wipe Rich header.
   -fcoff          Don't wipe COFF header.
   -fopt           Don't wipe Optional header.
   -fsec           Don't wipe Section headers.
   -fsec-n         Don't wipe Section headers names.
   -fexp           Don't wipe Export directory.
   -fres           Don't wipe Resource directory.
   -fdbg           Don't wipe Debug directory.
   -fcfg           Don't wipe LoadConfig directory.
   -fts            Don't wipe timestamp fields.
   -fuv            Don't wipe user version fields.
   -flv            Don't wipe linker version fields.
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