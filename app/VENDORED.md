# Third-party files in app/

| File | From | Version | License |
|---|---|---|---|
| `qrcodegen.py` | [Project Nayuki QR Code generator](https://github.com/nayuki/QR-Code-generator) (`python/qrcodegen.py`) | commit 777682a64202fdb837b50e351b25b7ddb27852c4 (2025-01-04), unmodified | MIT (header in the file) |
| `common-passwords.txt.gz` | [SecLists](https://github.com/danielmiessler/SecLists) `Passwords/Common-Credentials/Pwdb_top-1000000.txt` + `100k-most-used-passwords-NCSC.txt` | commit cb6d7645abf4a2c467bc80f84cf70bda3d60c2d6, filtered to the 5,531 entries of 15–64 printable characters, lower-cased | MIT |

`qrcodegen.py` only computes (no files, network or OS calls); it draws the QR code for an authenticator app.
The password list blocks common passwords long enough to pass the 15-character minimum.

SecLists is MIT-licensed: Copyright (c) 2018 Daniel Miessler. Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
following conditions: The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
