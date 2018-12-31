API Reference
=============

Classes
-------

Store Classes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. _store_classes:
.. autoclass:: cert_human.CertStore
    :members:
    :undoc-members:
    :show-inheritance:
    :private-members:
    :member-order: bysource

.. autoclass:: cert_human.CertChainStore
    :members:
    :undoc-members:
    :show-inheritance:
    :private-members:
    :member-order: bysource

WithCert Classes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. _withcert_classes:
.. autoclass:: cert_human.HTTPSConnectionWithCert
    :members:
    :undoc-members:
    :show-inheritance:
    :private-members:
    :member-order: bysource

.. autoclass:: cert_human.HTTPSResponseWithCert
    :members:
    :undoc-members:
    :show-inheritance:
    :private-members:
    :member-order: bysource

Exception Classes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. autoclass:: cert_human.CertHumanError
    :members:
    :undoc-members:
    :show-inheritance:
    :private-members:
    :member-order: bysource

Functions
---------

Get Cert Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. _getcert_functions:
.. autofunction:: cert_human.get_response
.. autofunction:: cert_human.ssl_socket

WithCert Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. _withcert_functions:
.. autofunction:: cert_human.enable_urllib3_patch
.. autofunction:: cert_human.disable_urllib3_patch
.. autofunction:: cert_human.urllib3_patch
.. autofunction:: cert_human.using_urllib3_patch
.. autofunction:: cert_human.check_urllib3_patch

Conversion Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. autofunction:: cert_human.pem_to_x509
.. autofunction:: cert_human.pems_to_x509
.. autofunction:: cert_human.x509_to_pem
.. autofunction:: cert_human.x509_to_der
.. autofunction:: cert_human.x509_to_asn1
.. autofunction:: cert_human.der_to_asn1

Utility Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. autofunction:: cert_human.utf8
.. autofunction:: cert_human.indent
.. autofunction:: cert_human.clsname
.. autofunction:: cert_human.jdump
.. autofunction:: cert_human.hexify
.. autofunction:: cert_human.space_out
.. autofunction:: cert_human.wrap_it
.. autofunction:: cert_human.find_certs
.. autofunction:: cert_human.write_file
