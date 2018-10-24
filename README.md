# 🐍 get-ca-py

Extracting Certificate Authorities from a request.

## Usage 

```bash
λ python getcert.py -h
usage: getcert.py [-h] [--verify] [--no-verify] URL

Request any URL and dump the certificate chain

positional arguments:
  URL          Valid https URL to be handled by requests

optional arguments:
  -h, --help   show this help message and exit
  --verify     Explicitly set SSL verification
  --no-verify  Explicitly disable SSL verification
```