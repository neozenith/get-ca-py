# 🐍 get-ca-py

[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

Extracting Certificate Authorities from a request.

Somebody said something about over-engineering. So I obviously had to chime in.

# Details

## with_cert_patch.py

Patches urllib3.connectionpool.HTTPSConnectionPool with the following:
  - Replaces the ConnectionCls with a subclassed ConnectionCls that adds:
    - the peer certificate via self.peer_cert
    - the peer certificate chain via self.peer_cert_chain
    - the peer certificate dictionary via self.peer_cert_dict
  - Replaces the ResponseCls with a subclassed ResponseCls that funnels all of the attributes upwards from the ConnectionCls

This allows you to use requests as normal but adds the peer magic to response.raw:

```python
import with_cert_patch
import requests
with_cert_patch.enable_with_cert()
response = requests.get("https://www.google.com")
repr(response.raw.peer_cert)
'<OpenSSL.crypto.X509 object at 0x10edeeb38>'
repr(response.raw.peer_cert_chain)
'[<OpenSSL.crypto.X509 object at 0x10edee7b8>, <OpenSSL.crypto.X509 object at 0x10edee860>]'
repr(response.raw.peer_cert_dict)
"{'subject': ((('commonName', 'www.google.com'),),), 'subjectAltName': [('DNS', 'www.google.com')]}"
```

## get_cert_for_humans.py

This is a whole nother beast. It has two classes:
  - CertX509Store: Makes parsing a certificate more human friendly.
  - CertX509ChainStore: Just acts as a list container of CertX509Stores for a peer_cert_chain.

We forgot to enable_with_cert():
```python
>>> import get_cert_for_humans
>>> response = get_cert_for_humans.get_response("www.google.com")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/gh/get-ca-py/get_cert_for_humans.py", line 31, in get_response
    with_cert_patch.check_with_cert()
  File "/gh/get-ca-py/with_cert_patch.py", line 74, in check_with_cert
    raise Exception(error)
Exception: Not using WithCert classes in <class 'urllib3.connectionpool.HTTPSConnectionPool'>, use enable_with_cert()
```

Lets try that again:
```python
>>> get_cert_for_humans.with_cert_patch.enable_with_cert()
>>> response = get_cert_for_humans.get_response("www.google.com")
>>> repr(response.raw.peer_cert)
'<OpenSSL.crypto.X509 object at 0x1065829b0>'
>>> repr(response.raw.peer_cert_chain)
'[<OpenSSL.crypto.X509 object at 0x106582a20>, <OpenSSL.crypto.X509 object at 0x106582ac8>]'
>>>
>>> repr(response.raw.peer_cert_dict)
"{'subject': ((('commonName', 'www.google.com'),),), 'subjectAltName': [('DNS', 'www.google.com')]}"
```

Now lets use CertX509Store to load in the cert from the response object:
```python
>>> cert = get_cert_for_humans.CertX509Store.new_from_response(response)
>>> cert.issuer
{'country_name': 'US', 'organization_name': 'Google Trust Services', 'common_name': 'Google Internet Authority G3'}
>>> cert.issuer_human
'Common Name: Google Internet Authority G3, Organization: Google Trust Services, Country: US'
>>> print(cert)
CertX509Store:
    {
      "issuer": "Common Name: Google Internet Authority G3, Organization: Google Trust Services, Country: US",
      "subject": "Common Name: www.google.com, Organization: Google LLC, Locality: Mountain View, State/Province: California, Country: US",
      "subject_alt_names": "www.google.com",
      "fingerprints": {
        "sha1": "30 DD 94 CC A7 0C D3 CA FF 5B 1D 89 E9 A9 0A C5 03 92 90 44",
        "sha256": "6D B1 DE 0F 4D BB 97 87 89 B9 61 76 35 48 3C BF 48 0B 3B DC B7 61 77 14 52 57 FA 2A AC CF 5F FF"
      },
      "public_key": {
        "algorithm": "ec",
        "parameters": "secp256r1",
        "key_size": 256,
        "key": "04 36 95 FA 7E 37 2D 70 D4 A2 5E 82 00 61 BC 43 47 E8 48 12 D4 BC 86 84 1D 2F 89 87 4D 75 E4 0E 9F 02 3F CC 6D F6 54 5F A5 7C 1B E6 D8 74 A7 3A 16 C6 2C 95 65 53 36 01 F6 61 5F 31 3A 00 02 CE 86",
        "exponent": null
      },
      "signature": {
        "algorithm": "sha256_rsa",
        "algo": "rsassa_pkcs1v15",
        "value": "38 5E 79 24 9B F3 07 AF C4 4B 6E 62 38 45 5B F2 77 10 70 C4 96 19 32 17 D5 0E 1C 3E 5F 33 E9 2E D5 61 C7 A0 60 4F 89 34 06 83 F1 43 6E 85 AA FF 2B A0 C5 53 C2 E1 37 5D 26 1D 0D 2C 9A BC A1 2F 91 A6 94 C8 24 96 BC BB 7B 4A 76 8C 13 2B E1 D4 94 4E FA 58 39 14 C8 32 94 FC 21 68 B0 B5 8F 8A 81 CC 95 55 81 BB 29 34 33 71 69 7A 94 55 BF A8 68 9B 81 F8 77 4A F6 74 8D 28 C5 BC EE 1C 97 4D B6 EF 4E 04 F3 E7 B9 FC 5E 93 2C F5 06 81 80 88 81 DC 25 64 1E 9A 40 1E 92 73 CF 3E 84 90 D0 17 41 DC 90 F7 36 11 19 6A A7 3F 71 2B F8 C5 60 2B 79 4A 7B 43 A1 AB 8C 26 42 41 B8 55 24 A7 41 26 A6 11 A1 EA F4 BE 59 DF CA A7 41 5A 4C 69 77 59 89 E6 67 40 F3 3C 06 F9 3E 1C 9D EE C0 B1 2E E2 EC 11 A6 83 1F 29 A3 92 3C 5D 2A D1 F0 67 51 CC 2C 8F B0 1F CF 2D EC 09 21 D4 19 E1 B1 EA 37 80"
      },
      "version": "v3",
      "serial_number": {
        "hex": "3F1787E8A53E8A7E",
        "int": 4546251782128306814
      },
      "validity": {
        "not_valid_before": "2018-12-04 09:33:00+00:00",
        "not_valid_after": "2019-02-26 09:33:00+00:00",
        "is_expired": false,
        "is_self_signed": "no",
        "is_self_issued": false
      },
      "extensions": {
        "extendedKeyUsage": "TLS Web Server Authentication",
        "keyUsage": "Digital Signature",
        "subjectAltName": "DNS:www.google.com",
        "authorityInfoAccess": "CA Issuers - URI:http://pki.goog/gsr2/GTSGIAG3.crt OCSP - URI:http://ocsp.pki.goog/GTSGIAG3",
        "subjectKeyIdentifier": "68:F0:B3:E9:9A:2F:1F:C6:FA:88:EA:F7:49:91:32:ED:F9:8C:0A:18",
        "basicConstraints": "CA:FALSE",
        "authorityKeyIdentifier": "keyid:77:C2:B8:50:9A:67:76:76:B1:2D:C2:86:D0:83:A0:7E:A6:7E:BA:4B",
        "certificatePolicies": "Policy: 1.3.6.1.4.1.11129.2.5.3 Policy: 2.23.140.1.2.2",
        "crlDistributionPoints": "Full Name:   URI:http://crl.pki.goog/GTSGIAG3.crl"
      }
    }
```

# Usage 

get_cert_for_humans.py also has some command line fun to it:

```bash
✗ ./get_cert_for_humans.py -h
usage: get_cert_for_humans.py [-h] [--port PORT] [--timeout TIMEOUT]
                              [--verify VERIFY] [--write_path WRITE_PATH]
                              HOST

Request a URL and get the server cert and server cert chain

positional arguments:
  HOST                  Host to get cert and cert chain from

optional arguments:
  -h, --help            show this help message and exit
  --port PORT           Port on host to connect to
  --timeout TIMEOUT     Timeout for connect
  --verify VERIFY       Use this cert when connecting to --url
  --write_path WRITE_PATH
                        Write server certificate to this file
```

Get a cert and write it in pem format:
```
➜  get-ca-py git:(master) ✗ ./get_cert_for_humans.py www.google.com --write_path moo.pem
** Wrote cert in pem format to: 'moo.pem'
➜  get-ca-py git:(master) ✗ cat moo.pem
-----BEGIN CERTIFICATE-----
MIIDxzCCAq+gAwIBAgIIPxeH6KU+in4wDQYJKoZIhvcNAQELBQAwVDELMAkGA1UE
BhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczElMCMGA1UEAxMc
R29vZ2xlIEludGVybmV0IEF1dGhvcml0eSBHMzAeFw0xODEyMDQwOTMzMDBaFw0x
OTAyMjYwOTMzMDBaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
MRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKDApHb29nbGUgTExDMRcw
FQYDVQQDDA53d3cuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BDaV+n43LXDUol6CAGG8Q0foSBLUvIaEHS+Jh0115A6fAj/MbfZUX6V8G+bYdKc6
FsYslWVTNgH2YV8xOgACzoajggFSMIIBTjATBgNVHSUEDDAKBggrBgEFBQcDATAO
BgNVHQ8BAf8EBAMCB4AwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYB
BQUHAQEEXDBaMC0GCCsGAQUFBzAChiFodHRwOi8vcGtpLmdvb2cvZ3NyMi9HVFNH
SUFHMy5jcnQwKQYIKwYBBQUHMAGGHWh0dHA6Ly9vY3NwLnBraS5nb29nL0dUU0dJ
QUczMB0GA1UdDgQWBBRo8LPpmi8fxvqI6vdJkTLt+YwKGDAMBgNVHRMBAf8EAjAA
MB8GA1UdIwQYMBaAFHfCuFCaZ3Z2sS3ChtCDoH6mfrpLMCEGA1UdIAQaMBgwDAYK
KwYBBAHWeQIFAzAIBgZngQwBAgIwMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL2Ny
bC5wa2kuZ29vZy9HVFNHSUFHMy5jcmwwDQYJKoZIhvcNAQELBQADggEBADheeSSb
8wevxEtuYjhFW/J3EHDElhkyF9UOHD5fM+ku1WHHoGBPiTQGg/FDboWq/yugxVPC
4TddJh0NLJq8oS+RppTIJJa8u3tKdowTK+HUlE76WDkUyDKU/CFosLWPioHMlVWB
uyk0M3FpepRVv6hom4H4d0r2dI0oxbzuHJdNtu9OBPPnufxekyz1BoGAiIHcJWQe
mkAeknPPPoSQ0BdB3JD3NhEZaqc/cSv4xWAreUp7Q6GrjCZCQbhVJKdBJqYRoer0
vlnfyqdBWkxpd1mJ5mdA8zwG+T4cne7AsS7i7BGmgx8po5I8XSrR8GdRzCyPsB/P
LewJIdQZ4bHqN4A=
-----END CERTIFICATE-----
```

Just get and print out a cert:
```
➜  get-ca-py git:(master) ✗ ./get_cert_for_humans.py www.google.com
CertX509Store:
    {
      "subject_alt_names": "www.google.com",
      "public_key": {
        "key": "04 36 95 FA 7E 37 2D 70 D4 A2 5E 82 00 61 BC 43 47 E8 48 12 D4 BC 86 84 1D 2F 89 87 4D 75 E4 0E 9F 02 3F CC 6D F6 54 5F A5 7C 1B E6 D8 74 A7 3A 16 C6 2C 95 65 53 36 01 F6 61 5F 31 3A 00 02 CE 86",
        "key_size": 256,
        "parameters": "secp256r1",
        "algorithm": "ec",
        "exponent": null
      },
      "fingerprints": {
        "sha256": "6D B1 DE 0F 4D BB 97 87 89 B9 61 76 35 48 3C BF 48 0B 3B DC B7 61 77 14 52 57 FA 2A AC CF 5F FF",
        "sha1": "30 DD 94 CC A7 0C D3 CA FF 5B 1D 89 E9 A9 0A C5 03 92 90 44"
      },
      "validity": {
        "not_valid_after": "2019-02-26 09:33:00+00:00",
        "is_self_issued": false,
        "is_expired": false,
        "is_self_signed": "no",
        "not_valid_before": "2018-12-04 09:33:00+00:00"
      },
      "version": "v3",
      "extensions": {
        "subjectKeyIdentifier": "68:F0:B3:E9:9A:2F:1F:C6:FA:88:EA:F7:49:91:32:ED:F9:8C:0A:18",
        "authorityKeyIdentifier": "keyid:77:C2:B8:50:9A:67:76:76:B1:2D:C2:86:D0:83:A0:7E:A6:7E:BA:4B",
        "extendedKeyUsage": "TLS Web Server Authentication",
        "subjectAltName": "DNS:www.google.com",
        "crlDistributionPoints": "Full Name:   URI:http://crl.pki.goog/GTSGIAG3.crl",
        "keyUsage": "Digital Signature",
        "certificatePolicies": "Policy: 1.3.6.1.4.1.11129.2.5.3 Policy: 2.23.140.1.2.2",
        "authorityInfoAccess": "CA Issuers - URI:http://pki.goog/gsr2/GTSGIAG3.crt OCSP - URI:http://ocsp.pki.goog/GTSGIAG3",
        "basicConstraints": "CA:FALSE"
      },
      "signature": {
        "value": "38 5E 79 24 9B F3 07 AF C4 4B 6E 62 38 45 5B F2 77 10 70 C4 96 19 32 17 D5 0E 1C 3E 5F 33 E9 2E D5 61 C7 A0 60 4F 89 34 06 83 F1 43 6E 85 AA FF 2B A0 C5 53 C2 E1 37 5D 26 1D 0D 2C 9A BC A1 2F 91 A6 94 C8 24 96 BC BB 7B 4A 76 8C 13 2B E1 D4 94 4E FA 58 39 14 C8 32 94 FC 21 68 B0 B5 8F 8A 81 CC 95 55 81 BB 29 34 33 71 69 7A 94 55 BF A8 68 9B 81 F8 77 4A F6 74 8D 28 C5 BC EE 1C 97 4D B6 EF 4E 04 F3 E7 B9 FC 5E 93 2C F5 06 81 80 88 81 DC 25 64 1E 9A 40 1E 92 73 CF 3E 84 90 D0 17 41 DC 90 F7 36 11 19 6A A7 3F 71 2B F8 C5 60 2B 79 4A 7B 43 A1 AB 8C 26 42 41 B8 55 24 A7 41 26 A6 11 A1 EA F4 BE 59 DF CA A7 41 5A 4C 69 77 59 89 E6 67 40 F3 3C 06 F9 3E 1C 9D EE C0 B1 2E E2 EC 11 A6 83 1F 29 A3 92 3C 5D 2A D1 F0 67 51 CC 2C 8F B0 1F CF 2D EC 09 21 D4 19 E1 B1 EA 37 80",
        "algo": "rsassa_pkcs1v15",
        "algorithm": "sha256_rsa"
      },
      "serial_number": {
        "int": 4546251782128306814,
        "hex": "3F1787E8A53E8A7E"
      },
      "subject": "Common Name: www.google.com, Organization: Google LLC, Locality: Mountain View, State/Province: California, Country: US",
      "issuer": "Common Name: Google Internet Authority G3, Organization: Google Trust Services, Country: US"
    }
```
