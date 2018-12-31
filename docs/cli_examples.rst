CLI Examples
============


Getting certs/cert chains
--------------------------------

Use requests to get cert
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg
    Issuer: Common Name: cyborg
    Subject: Common Name: cyborg
    Subject Alternate Names: cyborg
    Fingerprint SHA1: 67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7
    Fingerprint SHA256: FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA
    Expired: False, Not Valid Before: 2008-11-15 06:32:10+00:00, Not Valid After: 2028-11-15 02:56:10+00:00
    Self Signed: maybe, Self Issued: True

Use socket to get cert
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

      bash-3.2$ ./cert_human_cli.py cyborg --method socket
      Issuer: Common Name: cyborg
      Subject: Common Name: cyborg
      Subject Alternate Names: cyborg
      Fingerprint SHA1: 67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7
      Fingerprint SHA256: FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA
      Expired: False, Not Valid Before: 2008-11-15 06:32:10+00:00, Not Valid After: 2028-11-15 02:56:10+00:00
      Self Signed: maybe, Self Issued: True


Use requests to get cert chain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

      bash-3.2$ ./cert_human_cli.py cyborg --chain

        - CertStore #1
          Issuer: Common Name: cyborg
          Subject: Common Name: cyborg
          Subject Alternate Names: cyborg
          Fingerprint SHA1: 67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7
          Fingerprint SHA256: FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA
          Expired: False, Not Valid Before: 2008-11-15 06:32:10+00:00, Not Valid After: 2028-11-15 02:56:10+00:00
          Self Signed: maybe, Self Issued: True

Use socket to get cert chain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

      bash-3.2$ ./cert_human_cli.py cyborg --chain --method socket

        - CertStore #1
          Issuer: Common Name: cyborg
          Subject: Common Name: cyborg
          Subject Alternate Names: cyborg
          Fingerprint SHA1: 67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7
          Fingerprint SHA256: FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA
          Expired: False, Not Valid Before: 2008-11-15 06:32:10+00:00, Not Valid After: 2028-11-15 02:56:10+00:00
          Self Signed: maybe, Self Issued: True

Get a cert and write it to a file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg --write /tmp/cyborg.pem
    ** Wrote cert in pem format to: '/tmp/cyborg.pem'

Get a cert chain and write it to a file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg --chain --write /tmp/cyborg_chain.pem
    ** Wrote cert chain in pem format to: '/tmp/cyborg_chain.pem'

Validating certs
----------------

Use correct cert to validate host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg --verify /tmp/cyborg.pem
    Issuer: Common Name: cyborg
    Subject: Common Name: cyborg
    Subject Alternate Names: cyborg
    Fingerprint SHA1: 67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7
    Fingerprint SHA256: FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA
    Expired: False, Not Valid Before: 2008-11-15 06:32:10+00:00, Not Valid After: 2028-11-15 02:56:10+00:00
    Self Signed: maybe, Self Issued: True

Use wrong cert to validate host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg --verify /tmp/google.pem
    SSL Validation Failed:
      HTTPSConnectionPool(host='cyborg', port=443)
      Max retries exceeded with url
      / (Caused by SSLError(SSLError("bad handshake
      Error([('SSL routines', 'tls_process_server_certificate', 'certificate verify failed')],)",),))

Print cert info
---------------

Print public key for cert
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg --print_mode key
    Public Key Algorithm: rsa, Size: 2048, Exponent: 65537, Value:
        EC 79 B9 78 66 C2 C9 F1 F6 55 E9 F4 BD C5 91 9B 55 F3 A7 55
        FA F8 30 FE B2 BF 4E A8 01 BA A1 64 6D 63 B6 5A 99 7E 60 A3
        C5 E1 E8 E5 A9 F5 13 99 58 C5 E2 83 D0 99 47 08 F2 8A A4 CB
        9A 8A 29 55 BD A3 A6 76 E3 2D 54 17 D2 DA CD C2 6A 2D FF 5E
        C6 BF AC 0A A5 46 E3 6F E5 36 DC A1 1F 81 42 E8 3B 95 5F 90
        4C 85 F3 3B 01 26 2E 6F C5 1B 47 0A B5 7C 88 14 E9 86 BB 3C
        11 55 D1 14 38 6C C2 3E 47 09 F8 F0 AC 8D 63 43 13 18 AA 2C
        3D D8 64 F1 9F 67 9F 89 FB 5A 60 46 7A 6E 9E DA A3 6E 70 D1
        A8 DC 80 99 24 21 91 D9 2D 1E 53 7F 8C EC D4 05 C0 81 4F 14
        3D EB 63 31 40 04 3D C9 9D E7 FD 9F 69 C9 2C AD B8 92 AD FD
        F8 AB 03 88 4C 2B 2E 03 31 37 25 52 3D 2C 4C 2D FE A2 6A 62
        F6 7E 6B 5C 6C 37 AF 2B 10 DC 6A E4 BC 47 CF 2E 40 47 12 1E
        53 8F 30 A9 34 58 77 07 E1 F6 50 C1 0E 37 99 A5

    Signature Algorithm: sha256_rsa, Value:
        C1 0A 57 A7 FA 15 4C BD 1D EA B6 5E 74 DD 7E 01 83 BF A0 23
        EA D3 96 66 49 06 5D 4D 02 C7 D2 92 08 A6 01 18 36 D8 66 95
        8C D9 19 77 F3 FA 55 14 DF 1B 23 83 77 F4 0F 69 8B D6 0E DA
        2A 08 9C 34 00 5A 43 56 7D 19 18 8A E1 8B B4 80 3A AA BC 35
        B7 99 77 60 85 83 A6 88 6A A1 AD 9B 12 13 F2 4D BF CA 4F 18
        3D 02 9B DE 40 A5 A6 CB F3 E5 6B F7 28 EF 85 B3 B4 D5 03 F3
        E6 08 D6 59 91 92 6D D0 7D D1 C1 B0 48 51 D2 5D A5 1D F1 26
        6B 36 CD 14 5B 6B 13 C8 0D F6 24 83 C2 AE B4 2E 12 C9 E8 60
        B6 0D BD 1F 34 D5 54 E4 6B EA 4D C1 AF 19 B7 77 5C C1 AD 9C
        A2 2E 04 DD 3E 5C 2E 66 DD 17 41 57 E8 28 EB 4E 89 DE D7 AA
        00 80 7D B6 4C 00 76 6B 7A 00 E3 8C 9F 9B C8 BE 06 B9 14 C3
        D4 A7 78 A0 17 C1 B4 17 6E E2 6E 8D AA 79 69 FE 18 39 8A 19
        FF 9C 36 1A 3C A3 66 EF D0 5F 4D 7C 54 FD 4D A1

    Serial Number:
        B7 83 C6 92 09 1E 1A 32 79 D0 7B 5E EE D6 F5 FC 6D E8 CA 01
        50 62 37 91 5E 2A 00 C9 66 82 44 A6

Print extensions for cert
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg --print_mode extensions
    Extensions:
        Extension 1, name=subjectKeyIdentifier, value=E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93
        Extension 2, name=subjectAltName, value=DNS:cyborg

Print all info for cert
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg --print_mode all
    Extensions:
        Extension 1, name=subjectKeyIdentifier, value=E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93
        Extension 2, name=subjectAltName, value=DNS:cyborg

    Public Key Algorithm: rsa, Size: 2048, Exponent: 65537, Value:
        EC 79 B9 78 66 C2 C9 F1 F6 55 E9 F4 BD C5 91 9B 55 F3 A7 55
        FA F8 30 FE B2 BF 4E A8 01 BA A1 64 6D 63 B6 5A 99 7E 60 A3
        C5 E1 E8 E5 A9 F5 13 99 58 C5 E2 83 D0 99 47 08 F2 8A A4 CB
        9A 8A 29 55 BD A3 A6 76 E3 2D 54 17 D2 DA CD C2 6A 2D FF 5E
        C6 BF AC 0A A5 46 E3 6F E5 36 DC A1 1F 81 42 E8 3B 95 5F 90
        4C 85 F3 3B 01 26 2E 6F C5 1B 47 0A B5 7C 88 14 E9 86 BB 3C
        11 55 D1 14 38 6C C2 3E 47 09 F8 F0 AC 8D 63 43 13 18 AA 2C
        3D D8 64 F1 9F 67 9F 89 FB 5A 60 46 7A 6E 9E DA A3 6E 70 D1
        A8 DC 80 99 24 21 91 D9 2D 1E 53 7F 8C EC D4 05 C0 81 4F 14
        3D EB 63 31 40 04 3D C9 9D E7 FD 9F 69 C9 2C AD B8 92 AD FD
        F8 AB 03 88 4C 2B 2E 03 31 37 25 52 3D 2C 4C 2D FE A2 6A 62
        F6 7E 6B 5C 6C 37 AF 2B 10 DC 6A E4 BC 47 CF 2E 40 47 12 1E
        53 8F 30 A9 34 58 77 07 E1 F6 50 C1 0E 37 99 A5

    Signature Algorithm: sha256_rsa, Value:
        C1 0A 57 A7 FA 15 4C BD 1D EA B6 5E 74 DD 7E 01 83 BF A0 23
        EA D3 96 66 49 06 5D 4D 02 C7 D2 92 08 A6 01 18 36 D8 66 95
        8C D9 19 77 F3 FA 55 14 DF 1B 23 83 77 F4 0F 69 8B D6 0E DA
        2A 08 9C 34 00 5A 43 56 7D 19 18 8A E1 8B B4 80 3A AA BC 35
        B7 99 77 60 85 83 A6 88 6A A1 AD 9B 12 13 F2 4D BF CA 4F 18
        3D 02 9B DE 40 A5 A6 CB F3 E5 6B F7 28 EF 85 B3 B4 D5 03 F3
        E6 08 D6 59 91 92 6D D0 7D D1 C1 B0 48 51 D2 5D A5 1D F1 26
        6B 36 CD 14 5B 6B 13 C8 0D F6 24 83 C2 AE B4 2E 12 C9 E8 60
        B6 0D BD 1F 34 D5 54 E4 6B EA 4D C1 AF 19 B7 77 5C C1 AD 9C
        A2 2E 04 DD 3E 5C 2E 66 DD 17 41 57 E8 28 EB 4E 89 DE D7 AA
        00 80 7D B6 4C 00 76 6B 7A 00 E3 8C 9F 9B C8 BE 06 B9 14 C3
        D4 A7 78 A0 17 C1 B4 17 6E E2 6E 8D AA 79 69 FE 18 39 8A 19
        FF 9C 36 1A 3C A3 66 EF D0 5F 4D 7C 54 FD 4D A1

    Serial Number:
        B7 83 C6 92 09 1E 1A 32 79 D0 7B 5E EE D6 F5 FC 6D E8 CA 01
        50 62 37 91 5E 2A 00 C9 66 82 44 A6

    Issuer: Common Name: cyborg
    Subject: Common Name: cyborg
    Subject Alternate Names: cyborg
    Fingerprint SHA1: 67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7
    Fingerprint SHA256: FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA
    Expired: False, Not Valid Before: 2008-11-15 06:32:10+00:00, Not Valid After: 2028-11-15 02:56:10+00:00
    Self Signed: maybe, Self Issued: True
