High level API Examples
==============================================

Different examples of working with certs and cert chains using :obj:`cert_human.CertStore` and :obj:`cert_human.CertChainStore`.

Getting certs
--------------------------------------------------------

Using sockets
^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store = cert_human.CertStore.new_from_host_socket(host="cyborg")
    >>> chain_store = cert_human.CertChainStore.new_from_host_socket(host="cyborg")

Using requests
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store = cert_human.CertStore.new_from_host_requests(host="cyborg")
    >>> chain_store = cert_human.CertChainStore.new_from_host_requests(host="cyborg")

Using a requests response object
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> cert_human.enable_urllib3_patch()
    >>> response = requests.get("https://cyborg")
    >>> store = cert_human.CertStore.new_from_response_obj(response=response)
    >>> chain_store = cert_human.CertChainStore.new_from_response_obj(response=response)

Writing PEM certs to disk
-------------------------------------------------------

.. code-block:: python

    >>> store_path = store.to_disk("/tmp/certs/cyborg.pem", overwrite=True)
    >>> store_path.is_file()
    True

    >>> chain_path = chain_store.to_disk("/tmp/certs/cyborg_chain.pem", overwrite=True)
    >>> chain_path.is_file()
    True

CertStore: Attributes
--------------------------------------------------------

PEM format
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> print(store.pem)
    -----BEGIN CERTIFICATE-----
    MIIC8TCCAdmgAwIBAgIhALeDxpIJHhoyedB7Xu7W9fxt6MoBUGI3kV4qAMlmgkSm
    MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBmN5Ym9yZzAeFw0wODExMTUwNjMy
    MTBaFw0yODExMTUwMjU2MTBaMBExDzANBgNVBAMMBmN5Ym9yZzCCASIwDQYJKoZI
    hvcNAQEBBQADggEPADCCAQoCggEBAOx5uXhmwsnx9lXp9L3FkZtV86dV+vgw/rK/
    TqgBuqFkbWO2Wpl+YKPF4ejlqfUTmVjF4oPQmUcI8oqky5qKKVW9o6Z24y1UF9La
    zcJqLf9exr+sCqVG42/lNtyhH4FC6DuVX5BMhfM7ASYub8UbRwq1fIgU6Ya7PBFV
    0RQ4bMI+Rwn48KyNY0MTGKosPdhk8Z9nn4n7WmBGem6e2qNucNGo3ICZJCGR2S0e
    U3+M7NQFwIFPFD3rYzFABD3Jnef9n2nJLK24kq39+KsDiEwrLgMxNyVSPSxMLf6i
    amL2fmtcbDevKxDcauS8R88uQEcSHlOPMKk0WHcH4fZQwQ43maUCAwEAAaM0MDIw
    HQYDVR0OBBYEFOco2mIkLtDOWE1gNHeFHw9/xvKTMBEGA1UdEQQKMAiCBmN5Ym9y
    ZzANBgkqhkiG9w0BAQsFAAOCAQEAwQpXp/oVTL0d6rZedN1+AYO/oCPq05ZmSQZd
    TQLH0pIIpgEYNthmlYzZGXfz+lUU3xsjg3f0D2mL1g7aKgicNABaQ1Z9GRiK4Yu0
    gDqqvDW3mXdghYOmiGqhrZsSE/JNv8pPGD0Cm95ApabL8+Vr9yjvhbO01QPz5gjW
    WZGSbdB90cGwSFHSXaUd8SZrNs0UW2sTyA32JIPCrrQuEsnoYLYNvR801VTka+pN
    wa8Zt3dcwa2coi4E3T5cLmbdF0FX6CjrTone16oAgH22TAB2a3oA44yfm8i+BrkU
    w9SneKAXwbQXbuJujap5af4YOYoZ/5w2GjyjZu/QX018VP1NoQ==
    -----END CERTIFICATE-----

Issuer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store.issuer
    {'common_name': 'cyborg'}
    >>> store.issuer_str
    'Common Name: cyborg'

Subject
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store.subject
    {'common_name': 'cyborg'}
    >>> store.subject_str
    'Common Name: cyborg'
    >>> store.subject_alt_names
    ['cyborg']


Fingerprints
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store.fingerprint_sha1
    '67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7'
    >>> store.fingerprint_sha256
    'FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA'

Public Key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store.public_key
    'EC79B97866C2C9F1F655E9F4BDC5919B55F3A755FAF830FEB2BF4EA801BAA1646D63B65A997E60A3C5E1E8E5A9F5139958C5E283D0994708F28AA4CB9A8A2955BDA3A676E32D5417D2DACDC26A2DFF5EC6BFAC0AA546E36FE536DCA11F8142E83B955F904C85F33B01262E6FC51B470AB57C8814E986BB3C1155D114386CC23E4709F8F0AC8D63431318AA2C3DD864F19F679F89FB5A60467A6E9EDAA36E70D1A8DC8099242191D92D1E537F8CECD405C0814F143DEB633140043DC99DE7FD9F69C92CADB892ADFDF8AB03884C2B2E03313725523D2C4C2DFEA26A62F67E6B5C6C37AF2B10DC6AE4BC47CF2E4047121E538F30A934587707E1F650C10E3799A5'
    >>> print(store.public_key_str)
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
    >>> store.public_key_algorithm
    'rsa'
    >>> store.public_key_exponent
    65537
    >>> store.public_key_parameters
    >>> store.public_key_size
    2048

Signature
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store.signature
    'C10A57A7FA154CBD1DEAB65E74DD7E0183BFA023EAD3966649065D4D02C7D29208A6011836D866958CD91977F3FA5514DF1B238377F40F698BD60EDA2A089C34005A43567D19188AE18BB4803AAABC35B79977608583A6886AA1AD9B1213F24DBFCA4F183D029BDE40A5A6CBF3E56BF728EF85B3B4D503F3E608D65991926DD07DD1C1B04851D25DA51DF1266B36CD145B6B13C80DF62483C2AEB42E12C9E860B60DBD1F34D554E46BEA4DC1AF19B7775CC1AD9CA22E04DD3E5C2E66DD174157E828EB4E89DED7AA00807DB64C00766B7A00E38C9F9BC8BE06B914C3D4A778A017C1B4176EE26E8DAA7969FE18398A19FF9C361A3CA366EFD05F4D7C54FD4DA1'
    >>> print(store.signature_str)
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
    >>> store.signature_algorithm
    'sha256_rsa'

Serial Number
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store.serial_number
    'B783C692091E1A3279D07B5EEED6F5FC6DE8CA01506237915E2A00C9668244A6'
    >>> store.serial_number_str
    'B7 83 C6 92 09 1E 1A 32 79 D0 7B 5E EE D6 F5 FC 6D E8 CA 01\n50 62 37 91 5E 2A 00 C9 66 82 44 A6'

Validity
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store.is_expired
    False
    >>> store.is_self_issued
    True
    >>> store.is_self_signed
    'maybe'
    >>> store.not_valid_before
    datetime.datetime(2008, 11, 15, 6, 32, 10, tzinfo=datetime.timezone.utc)
    >>> store.not_valid_after
    datetime.datetime(2028, 11, 15, 2, 56, 10, tzinfo=datetime.timezone.utc)
    >>> store.not_valid_before_str
    '2008-11-15 06:32:10+00:00'
    >>> store.not_valid_after_str
    '2028-11-15 02:56:10+00:00'

Extensions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> store.extensions
    {'subjectKeyIdentifier': 'E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93', 'subjectAltName': 'DNS:cyborg'}
    >>> print(store.extensions_str)
    Extension 1, name=subjectKeyIdentifier, value=E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93
    Extension 2, name=subjectAltName, value=DNS:cyborg

Info in string format
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Basic cert info:

.. code-block:: python

    >>> print(store)
    CertStore:
        Issuer: Common Name: cyborg
        Subject: Common Name: cyborg
        Subject Alternate Names: cyborg
        Fingerprint SHA1: 67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7
        Fingerprint SHA256: FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA
        Expired: False, Not Valid Before: 2008-11-15 06:32:10+00:00, Not Valid After: 2028-11-15 02:56:10+00:00
        Self Signed: maybe, Self Issued: True

    >>> print(store.dump_str_info)  # same as print(store)
    Issuer: Common Name: cyborg
    Subject: Common Name: cyborg
    Subject Alternate Names: cyborg
    Fingerprint SHA1: 67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7
    Fingerprint SHA256: FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA
    Expired: False, Not Valid Before: 2008-11-15 06:32:10+00:00, Not Valid After: 2028-11-15 02:56:10+00:00
    Self Signed: maybe, Self Issued: True

Public key info:

.. code-block:: python

    >>> print(store.dump_str_key)
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

Extensions info:

.. code-block:: python

    >>> print(store.dump_str_exts)
    Extensions:
        Extension 1, name=subjectKeyIdentifier, value=E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93
        Extension 2, name=subjectAltName, value=DNS:cyborg

All info blocks as one:

.. code-block:: python

    >>> print(store.dump_str)
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


Exporting all attributes in a CertStore
--------------------------------------------------------

Get all the JSON friendly attributes as a JSON string:

.. code-block:: python

    >>> print(store.dump_json)
    {
      "issuer": {
        "common_name": "cyborg"
      },
      "issuer_str": "Common Name: cyborg",
      "subject": {
        "common_name": "cyborg"
      },
      "subject_str": "Common Name: cyborg",
      "subject_alt_names": [
        "cyborg"
      ],
      "subject_alt_names_str": "cyborg",
      "fingerprint_sha1": "67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF B7",
      "fingerprint_sha256": "FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA",
      "public_key": "EC79B97866C2C9F1F655E9F4BDC5919B55F3A755FAF830FEB2BF4EA801BAA1646D63B65A997E60A3C5E1E8E5A9F5139958C5E283D0994708F28AA4CB9A8A2955BDA3A676E32D5417D2DACDC26A2DFF5EC6BFAC0AA546E36FE536DCA11F8142E83B955F904C85F33B01262E6FC51B470AB57C8814E986BB3C1155D114386CC23E4709F8F0AC8D63431318AA2C3DD864F19F679F89FB5A60467A6E9EDAA36E70D1A8DC8099242191D92D1E537F8CECD405C0814F143DEB633140043DC99DE7FD9F69C92CADB892ADFDF8AB03884C2B2E03313725523D2C4C2DFEA26A62F67E6B5C6C37AF2B10DC6AE4BC47CF2E4047121E538F30A934587707E1F650C10E3799A5",
      "public_key_str": "EC 79 B9 78 66 C2 C9 F1 F6 55 E9 F4 BD C5 91 9B 55 F3 A7 55\nFA F8 30 FE B2 BF 4E A8 01 BA A1 64 6D 63 B6 5A 99 7E 60 A3\nC5 E1 E8 E5 A9 F5 13 99 58 C5 E2 83 D0 99 47 08 F2 8A A4 CB\n9A 8A 29 55 BD A3 A6 76 E3 2D 54 17 D2 DA CD C2 6A 2D FF 5E\nC6 BF AC 0A A5 46 E3 6F E5 36 DC A1 1F 81 42 E8 3B 95 5F 90\n4C 85 F3 3B 01 26 2E 6F C5 1B 47 0A B5 7C 88 14 E9 86 BB 3C\n11 55 D1 14 38 6C C2 3E 47 09 F8 F0 AC 8D 63 43 13 18 AA 2C\n3D D8 64 F1 9F 67 9F 89 FB 5A 60 46 7A 6E 9E DA A3 6E 70 D1\nA8 DC 80 99 24 21 91 D9 2D 1E 53 7F 8C EC D4 05 C0 81 4F 14\n3D EB 63 31 40 04 3D C9 9D E7 FD 9F 69 C9 2C AD B8 92 AD FD\nF8 AB 03 88 4C 2B 2E 03 31 37 25 52 3D 2C 4C 2D FE A2 6A 62\nF6 7E 6B 5C 6C 37 AF 2B 10 DC 6A E4 BC 47 CF 2E 40 47 12 1E\n53 8F 30 A9 34 58 77 07 E1 F6 50 C1 0E 37 99 A5",
      "public_key_parameters": null,
      "public_key_algorithm": "rsa",
      "public_key_size": 2048,
      "public_key_exponent": 65537,
      "signature": "C10A57A7FA154CBD1DEAB65E74DD7E0183BFA023EAD3966649065D4D02C7D29208A6011836D866958CD91977F3FA5514DF1B238377F40F698BD60EDA2A089C34005A43567D19188AE18BB4803AAABC35B79977608583A6886AA1AD9B1213F24DBFCA4F183D029BDE40A5A6CBF3E56BF728EF85B3B4D503F3E608D65991926DD07DD1C1B04851D25DA51DF1266B36CD145B6B13C80DF62483C2AEB42E12C9E860B60DBD1F34D554E46BEA4DC1AF19B7775CC1AD9CA22E04DD3E5C2E66DD174157E828EB4E89DED7AA00807DB64C00766B7A00E38C9F9BC8BE06B914C3D4A778A017C1B4176EE26E8DAA7969FE18398A19FF9C361A3CA366EFD05F4D7C54FD4DA1",
      "signature_str": "C1 0A 57 A7 FA 15 4C BD 1D EA B6 5E 74 DD 7E 01 83 BF A0 23\nEA D3 96 66 49 06 5D 4D 02 C7 D2 92 08 A6 01 18 36 D8 66 95\n8C D9 19 77 F3 FA 55 14 DF 1B 23 83 77 F4 0F 69 8B D6 0E DA\n2A 08 9C 34 00 5A 43 56 7D 19 18 8A E1 8B B4 80 3A AA BC 35\nB7 99 77 60 85 83 A6 88 6A A1 AD 9B 12 13 F2 4D BF CA 4F 18\n3D 02 9B DE 40 A5 A6 CB F3 E5 6B F7 28 EF 85 B3 B4 D5 03 F3\nE6 08 D6 59 91 92 6D D0 7D D1 C1 B0 48 51 D2 5D A5 1D F1 26\n6B 36 CD 14 5B 6B 13 C8 0D F6 24 83 C2 AE B4 2E 12 C9 E8 60\nB6 0D BD 1F 34 D5 54 E4 6B EA 4D C1 AF 19 B7 77 5C C1 AD 9C\nA2 2E 04 DD 3E 5C 2E 66 DD 17 41 57 E8 28 EB 4E 89 DE D7 AA\n00 80 7D B6 4C 00 76 6B 7A 00 E3 8C 9F 9B C8 BE 06 B9 14 C3\nD4 A7 78 A0 17 C1 B4 17 6E E2 6E 8D AA 79 69 FE 18 39 8A 19\nFF 9C 36 1A 3C A3 66 EF D0 5F 4D 7C 54 FD 4D A1",
      "signature_algorithm": "sha256_rsa",
      "x509_version": "v3",
      "serial_number": "B783C692091E1A3279D07B5EEED6F5FC6DE8CA01506237915E2A00C9668244A6",
      "serial_number_str": "B7 83 C6 92 09 1E 1A 32 79 D0 7B 5E EE D6 F5 FC 6D E8 CA 01\n50 62 37 91 5E 2A 00 C9 66 82 44 A6",
      "is_expired": false,
      "is_self_signed": "maybe",
      "is_self_issued": true,
      "not_valid_before_str": "2008-11-15 06:32:10+00:00",
      "not_valid_after_str": "2028-11-15 02:56:10+00:00",
      "extensions": {
        "subjectKeyIdentifier": "E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93",
        "subjectAltName": "DNS:cyborg"
      },
      "extensions_str": "Extension 1, name=subjectKeyIdentifier, value=E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93\nExtension 2, name=subjectAltName, value=DNS:cyborg"
    }

Get all the attributes as a dict:

.. code-block:: python

    >>> pprint.pprint(store.dump)
    {'extensions': {'subjectAltName': 'DNS:cyborg',
                    'subjectKeyIdentifier': 'E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93'},
     'extensions_str': 'Extension 1, name=subjectKeyIdentifier, '
                       'value=E7:28:DA:62:24:2E:D0:CE:58:4D:60:34:77:85:1F:0F:7F:C6:F2:93\n'
                       'Extension 2, name=subjectAltName, value=DNS:cyborg',
     'fingerprint_sha1': '67 FD F1 7A 02 26 C7 AB 77 AD CD CB 63 76 19 AD 83 0C BF '
                         'B7',
     'fingerprint_sha256': 'FA BF 9D EC CF 6C 3F 8A 08 89 29 04 5E 9E B5 A8 28 A9 '
                           'F7 A8 E8 38 14 7F 32 CE 78 DC 26 B0 84 EA',
     'is_expired': False,
     'is_self_issued': True,
     'is_self_signed': 'maybe',
     'issuer': {'common_name': 'cyborg'},
     'issuer_str': 'Common Name: cyborg',
     'not_valid_after': datetime.datetime(2028, 11, 15, 2, 56, 10, tzinfo=datetime.timezone.utc),
     'not_valid_after_str': '2028-11-15 02:56:10+00:00',
     'not_valid_before': datetime.datetime(2008, 11, 15, 6, 32, 10, tzinfo=datetime.timezone.utc),
     'not_valid_before_str': '2008-11-15 06:32:10+00:00',
     'public_key': 'EC79B97866C2C9F1F655E9F4BDC5919B55F3A755FAF830FEB2BF4EA801BAA1646D63B65A997E60A3C5E1E8E5A9F5139958C5E283D0994708F28AA4CB9A8A2955BDA3A676E32D5417D2DACDC26A2DFF5EC6BFAC0AA546E36FE536DCA11F8142E83B955F904C85F33B01262E6FC51B470AB57C8814E986BB3C1155D114386CC23E4709F8F0AC8D63431318AA2C3DD864F19F679F89FB5A60467A6E9EDAA36E70D1A8DC8099242191D92D1E537F8CECD405C0814F143DEB633140043DC99DE7FD9F69C92CADB892ADFDF8AB03884C2B2E03313725523D2C4C2DFEA26A62F67E6B5C6C37AF2B10DC6AE4BC47CF2E4047121E538F30A934587707E1F650C10E3799A5',
     'public_key_algorithm': 'rsa',
     'public_key_exponent': 65537,
     'public_key_parameters': None,
     'public_key_size': 2048,
     'public_key_str': 'EC 79 B9 78 66 C2 C9 F1 F6 55 E9 F4 BD C5 91 9B 55 F3 A7 '
                       '55\n'
                       'FA F8 30 FE B2 BF 4E A8 01 BA A1 64 6D 63 B6 5A 99 7E 60 '
                       'A3\n'
                       'C5 E1 E8 E5 A9 F5 13 99 58 C5 E2 83 D0 99 47 08 F2 8A A4 '
                       'CB\n'
                       '9A 8A 29 55 BD A3 A6 76 E3 2D 54 17 D2 DA CD C2 6A 2D FF '
                       '5E\n'
                       'C6 BF AC 0A A5 46 E3 6F E5 36 DC A1 1F 81 42 E8 3B 95 5F '
                       '90\n'
                       '4C 85 F3 3B 01 26 2E 6F C5 1B 47 0A B5 7C 88 14 E9 86 BB '
                       '3C\n'
                       '11 55 D1 14 38 6C C2 3E 47 09 F8 F0 AC 8D 63 43 13 18 AA '
                       '2C\n'
                       '3D D8 64 F1 9F 67 9F 89 FB 5A 60 46 7A 6E 9E DA A3 6E 70 '
                       'D1\n'
                       'A8 DC 80 99 24 21 91 D9 2D 1E 53 7F 8C EC D4 05 C0 81 4F '
                       '14\n'
                       '3D EB 63 31 40 04 3D C9 9D E7 FD 9F 69 C9 2C AD B8 92 AD '
                       'FD\n'
                       'F8 AB 03 88 4C 2B 2E 03 31 37 25 52 3D 2C 4C 2D FE A2 6A '
                       '62\n'
                       'F6 7E 6B 5C 6C 37 AF 2B 10 DC 6A E4 BC 47 CF 2E 40 47 12 '
                       '1E\n'
                       '53 8F 30 A9 34 58 77 07 E1 F6 50 C1 0E 37 99 A5',
     'serial_number': 'B783C692091E1A3279D07B5EEED6F5FC6DE8CA01506237915E2A00C9668244A6',
     'serial_number_str': 'B7 83 C6 92 09 1E 1A 32 79 D0 7B 5E EE D6 F5 FC 6D E8 '
                          'CA 01\n'
                          '50 62 37 91 5E 2A 00 C9 66 82 44 A6',
     'signature': 'C10A57A7FA154CBD1DEAB65E74DD7E0183BFA023EAD3966649065D4D02C7D29208A6011836D866958CD91977F3FA5514DF1B238377F40F698BD60EDA2A089C34005A43567D19188AE18BB4803AAABC35B79977608583A6886AA1AD9B1213F24DBFCA4F183D029BDE40A5A6CBF3E56BF728EF85B3B4D503F3E608D65991926DD07DD1C1B04851D25DA51DF1266B36CD145B6B13C80DF62483C2AEB42E12C9E860B60DBD1F34D554E46BEA4DC1AF19B7775CC1AD9CA22E04DD3E5C2E66DD174157E828EB4E89DED7AA00807DB64C00766B7A00E38C9F9BC8BE06B914C3D4A778A017C1B4176EE26E8DAA7969FE18398A19FF9C361A3CA366EFD05F4D7C54FD4DA1',
     'signature_algorithm': 'sha256_rsa',
     'signature_str': 'C1 0A 57 A7 FA 15 4C BD 1D EA B6 5E 74 DD 7E 01 83 BF A0 '
                      '23\n'
                      'EA D3 96 66 49 06 5D 4D 02 C7 D2 92 08 A6 01 18 36 D8 66 '
                      '95\n'
                      '8C D9 19 77 F3 FA 55 14 DF 1B 23 83 77 F4 0F 69 8B D6 0E '
                      'DA\n'
                      '2A 08 9C 34 00 5A 43 56 7D 19 18 8A E1 8B B4 80 3A AA BC '
                      '35\n'
                      'B7 99 77 60 85 83 A6 88 6A A1 AD 9B 12 13 F2 4D BF CA 4F '
                      '18\n'
                      '3D 02 9B DE 40 A5 A6 CB F3 E5 6B F7 28 EF 85 B3 B4 D5 03 '
                      'F3\n'
                      'E6 08 D6 59 91 92 6D D0 7D D1 C1 B0 48 51 D2 5D A5 1D F1 '
                      '26\n'
                      '6B 36 CD 14 5B 6B 13 C8 0D F6 24 83 C2 AE B4 2E 12 C9 E8 '
                      '60\n'
                      'B6 0D BD 1F 34 D5 54 E4 6B EA 4D C1 AF 19 B7 77 5C C1 AD '
                      '9C\n'
                      'A2 2E 04 DD 3E 5C 2E 66 DD 17 41 57 E8 28 EB 4E 89 DE D7 '
                      'AA\n'
                      '00 80 7D B6 4C 00 76 6B 7A 00 E3 8C 9F 9B C8 BE 06 B9 14 '
                      'C3\n'
                      'D4 A7 78 A0 17 C1 B4 17 6E E2 6E 8D AA 79 69 FE 18 39 8A '
                      '19\n'
                      'FF 9C 36 1A 3C A3 66 EF D0 5F 4D 7C 54 FD 4D A1',
     'subject': {'common_name': 'cyborg'},
     'subject_alt_names': ['cyborg'],
     'subject_alt_names_str': 'cyborg',
     'subject_str': 'Common Name: cyborg',
     'x509_version': 'v3'}



CertChainStore: Attributes
--------------------------------------------------------

.. code-block:: python

    >>> print(chain_store.pem)  # concatted string of pem from each cert in chain store
    >>> chain_store.asn1  # list of each cert in cert chain in asn1 format
    >>> chain_store.der  # list of each cert in cert chain in der format
    >>> chain_store.dump_str  # concatted and indexed output of dump_str on each cert in chain store
    >>> chain_store.dump_str_exts  # concatted and indexed output of dump_str_exts on each cert in chain store
    >>> chain_store.dump_str_info  # concatted and indexed output of dump_str_info on each cert in chain store
    >>> chain_store.dump_str_key  # concatted and indexed output of dump_str_key on each cert in chain store
    >>> chain_store.dump_json  # json string with list of dicts from dump_json on each cert in chain store
    >>> chain_store.dump  # list of dict from dump on each cert in chain store
