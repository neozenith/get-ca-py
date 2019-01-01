# Archived

> Please take a look at [Cert Human: SSL Certificates for Humans](https://github.com/lifehackjim/cert_human) for an impressive rewrite of this project by [`lifehackjim`](https://github.com/lifehackjim)

# 🐍 get-ca-py

[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

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
