Low level API Examples
==============================================

Different examples of getting certs and cert chains manually using cert_human.

Using cert_human.get_response to get cert and cert chain
--------------------------------------------------------

:obj:`cert_human.get_response` does a number of things:

* It will automatically construct a url based on ``host`` and ``port`` arguments as follows:

  * if no ``://`` in host, prepend host with the default scheme ``https://``
  * if no ``:int`` in host, append host with the default port ``:443``

* You can supply a value to the ``host`` argument a number of different ways:

  * ``google.com``
  * ``google.com:443``
  * ``https://google.com:443``
  * ``https://www.google.com``

* Uses a context manager to disable warnings from requests about SSL certificate validation.
* Uses a context manager to patch urllib3 to add SSL certificate attributes to the HTTPSResponse object.
* Makes a request to a server using :func:`requests.get`.
* Returns the response object, with the SSL certificate objects available via:

  * ``response.raw.peer_cert``: The servers actual certificate as an :obj:`OpenSSL.crypto.X509` object.
  * ``response.raw.peer_cert_chain``: The servers certificate chain as a list of :obj:`OpenSSL.crypto.X509` objects
  * ``response.raw.peer_cert_dict``: A dictionary that seems to only contain the subject info from the servers certificate, and therefore has limited usefulness, but is included for completeness sake.

Valid certs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can get a valid cert and cert chain (signed by known CA):

.. code-block:: python

    >>> # get the response object
    >>> response = cert_human.get_response(host="www.google.com")

    >>> # access the cert chain from the response.raw object
    >>> print(response.raw.peer_cert_chain)
    [<OpenSSL.crypto.X509 object at 0x104d1a5f8>, <OpenSSL.crypto.X509 object at 0x104d1a6a0>]

    >>> # access the cert from the response.raw object
    >>> print(response.raw.peer_cert.get_subject().get_components())
    [(b'C', b'US'), (b'ST', b'California'), (b'L', b'Mountain View'), (b'O', b'Google LLC'), (b'CN', b'www.google.com')]

    >>> # convert the cert from x509 object to PEM string
    >>> pem = cert_human.x509_to_pem(response.raw.peer_cert)

    >>> # write the PEM to a file
    >>> path = cert_human.write_file(path="/tmp/certs/google.pem", text=pem, overwrite=True, mkparent=True, protect=True)
    >>> path.is_file()
    True

Invalid certs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can get an invalid cert (self-signed/self-issued/signed by unknown CA):

.. code-block:: python

    >>> # get the response object
    >>> response = cert_human.get_response(host="cyborg")

    >>> # access the cert from the response.raw object
    >>> print(response.raw.peer_cert.get_subject().get_components())
    [(b'CN', b'cyborg')]

    >>> # access the cert chain from the response.raw object
    >>> print(x.raw.peer_cert_chain)
    [<OpenSSL.crypto.X509 object at 0x10e7a7908>]

    >>> # convert the cert from x509 object to PEM string
    >>> pem = cert_human.x509_to_pem(response.raw.peer_cert)

    >>> # write the PEM to a file
    >>> path = cert_human.write_file(path="/tmp/certs/cyborg.pem", text=pem, overwrite=True, mkparent=True, protect=True)
    >>> path.is_file()
    True

Invalid certs with warnings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Make a request to a site that has an invalid cert and don't silence warnings (I don't know why you'd do this, but it's there anyways):

.. code-block:: python

    >>> response = cert_human.get_response(host="cyborg", nowarn=False)
    /Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages/urllib3/connectionpool.py:847: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
      InsecureRequestWarning)

Using cert_human.ssl_socket to get cert and cert chain
--------------------------------------------------------

:obj:`cert_human.ssl_socket` does a number of things:

* Allows fetching a cert or cert chain using a socket.socket wrapped with OpenSSL.SSL.Context.
* This means you don't need to patch :obj:`urllib3.connectionpool.HTTPSConnectionPool` so that requests can access the certificate attributes on the raw object.
* By default does not allow SSLv2 connections.

Valid or invalid certs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Getting certs with this method performs NO verification, so you can just get your cert on.

.. code-block:: python

    >>> # get the cert and cert chain
    >>> with cert_human.ssl_socket(host="cyborg") as sock:
    ...     cert = sock.get_peer_certificate()
    ...     cert_chain = sock.get_peer_cert_chain()
    ...

    >>> print(cert_chain)
    [<OpenSSL.crypto.X509 object at 0x10bccd6d8>]

    >>> # access whatever cert info manually from the OpenSSL.crypto.x509 object
    >>> print(cert.get_subject().get_components())
    [(b'CN', b'cyborg')]

    >>> # convert the cert from x509 object to PEM string
    >>> pem = cert_human.x509_to_pem(cert)

    >>> # write the PEM to a file
    >>> path = cert_human.write_file(path="/tmp/certs/cyborg.pem", text=pem, overwrite=True, mkparent=True, protect=True)
    >>> path.is_file()
    True

.. code-block:: python

    >>> # get the cert and cert chain
    >>> with cert_human.ssl_socket(host="google.com") as sock:
    ...     cert = sock.get_peer_certificate()
    ...     cert_chain = sock.get_peer_cert_chain()

    >>> print(cert_chain)
    [<OpenSSL.crypto.X509 object at 0x10bccd7b8>, <OpenSSL.crypto.X509 object at 0x10bccd860>]

    >>> # access whatever cert info manually from the OpenSSL.crypto.x509 object
    >>> print(cert.get_subject().get_components())
    [(b'C', b'US'), (b'ST', b'California'), (b'L', b'Mountain View'), (b'O', b'Google LLC'), (b'CN', b'*.google.com')]

    >>> # convert the cert from x509 object to PEM string
    >>> pem = cert_human.x509_to_pem(cert)

    >>> # write the PEM to a file
    >>> path = cert_human.write_file(path="/tmp/certs/cyborg.pem", text=pem, overwrite=True, mkparent=True, protect=True)
    >>> path.is_file()
    True

Using requests methods to get cert and cert chain
--------------------------------------------------

These examples just patch urllib3 for requests so you can use any normal :obj:`requests` method to get a response.

Valid certs using urllib3 patch tools
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Using the :obj:`cert_human.urllib3_patch` context manager:

.. code-block:: python

    >>> # get the response with the cert attributes set
    >>> with cert_human.urllib3_patch():
    ...    response = requests.get("https://www.google.com")
    ...
    >>> print(response.raw.peer_cert.get_subject().get_components())
    [(b'C', b'US'), (b'ST', b'California'), (b'L', b'Mountain View'), (b'O', b'Google LLC'), (b'CN', b'www.google.com')]

Using :obj:`cert_human.enable_urllib3_patch` to patch urllib3:

.. code-block:: python

    >>> # patch urllib3
    >>> cert_human.enable_urllib3_patch()

    >>> # get a response using whatever method in requests
    >>> response = requests.get("https://www.google.com")

    >>> # access whatever cert info manually from the OpenSSL.crypto.x509 object
    >>> print(response.raw.peer_cert.get_subject().get_components())
    [(b'C', b'US'), (b'ST', b'California'), (b'L', b'Mountain View'), (b'O', b'Google LLC'), (b'CN', b'www.google.com')]

    >>> # convert the cert from x509 object to PEM string
    >>> pem = cert_human.x509_to_pem(response.raw.peer_cert)

    >>> # write the PEM to a file
    >>> path = cert_human.write_file(path="/tmp/certs/google.pem", text=pem, overwrite=True, mkparent=True, protect=True)
    >>> path.is_file()
    True

    >>> # optionally disable the urllib3 patch once you no longer need
    >>> # to get responses with the cert attributes attached
    >>> cert_human.disable_urllib3_patch()

Invalid certs using urllib3 patch tools
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Same as valid certs using urllib3 patch tools, but you need to set verify=False in your requests method (and optionally disable requests warnings as well):

.. code-block:: python

    >>> cert_human.enable_urllib3_patch()
    >>> response = requests.get("https://cyborg", verify=False)
    /Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages/urllib3/connectionpool.py:847: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
      InsecureRequestWarning)
    >>> print(response.raw.peer_cert.get_subject().get_components())
    [(b'CN', b'cyborg')]
