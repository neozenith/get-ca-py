|Maintenance yes|
|MIT license|
|Open Source? Yes!|
|made-with-python|

#######################################
Cert Human: SSL Certificates for Humans
#######################################

**************************
Description
**************************

Somebody said something about over-engineering. So I obviously had to chime in.

No, but seriously, I was in the midst of rewriting `another project of mine <https://github.com/tanium/pytan>`_, and I wanted to incorporate a method to get an SSL certificate from a server, show the user the same kind of information as you'd see in a browser, prompt them for validity, then write it to disk for use in further requests using :obj:`requests` to a server.

I was unable to find any great / easy ways that incorporated all of these concepts into one neat thing. So I made a thing.

Originally this was based off of the lovely over-engineered solution in `get-ca-py <https://github.com/neozenith/get-ca-py>`_ by `Josh Peak <https://github.com/neozenith>`_.

I wound up wanting a more offically supported way of patching urllib3 to have access to the certificate attributes in the raw attribute of a :obj:`requests.Response` object. So I wrote :ref:`Replacement Connect and Response subclasses <withcert_classes>` for :obj:`urllib3.HTTPSConnectionPool`, and a :ref:`patcher, unpatcher, and context manager <withcert_functions>` to enable/disable the new classes.

I also wanted some generalized utility functions to get the certificates, so I wrote some :ref:`get certificate functions <getcert_functions>`.

I then wanted an easier, more *human* way of accessing all of the information in the certificates. And that wound up turning into a whole thing. So :ref:`CertStore and CertChainStore classes <store_classes>` were born.

**************************
Installation
**************************

pip blah blah blah


**************************
TODO items
**************************

* I have no test suite setup. I know. That's horrible. But I've already spent too much time on this. I'll get to it eventually.

.. |MIT license| image:: https://img.shields.io/badge/License-MIT-blue.svg
   :target: https://lbesson.mit-license.org/

.. |Open Source? Yes!| image:: https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github
   :target: https://github.com/lifehackjim/cert_human

.. |Maintenance yes| image:: https://img.shields.io/badge/Maintained%3F-yes-green.svg
   :target: https://github.com/lifehackjim/cert_human/graphs/commit-activity

.. |made-with-python| image:: https://img.shields.io/badge/Made%20with-Python-1f425f.svg
   :target: https://www.python.org/

###################
Table of Contents
###################

.. toctree::
   :maxdepth: 4
   :numbered:

   cli.rst
   api.rst

###################
Indices and tables
###################

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
