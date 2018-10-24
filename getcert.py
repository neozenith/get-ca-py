#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Get Certificates from a request and dump them.
"""

import argparse
import sys

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

"""
Inspired by the answers from this Stackoverflow question:
https://stackoverflow.com/questions/16903528/how-to-get-response-ssl-certificate-from-requests-in-python

What follows is a series of patching the low level libraries in requests.
"""

"""
https://stackoverflow.com/a/47931103/622276
"""

sock_requests = requests.packages.urllib3.contrib.pyopenssl.WrappedSocket


def new_getpeercertchain(self, *args, **kwargs):
    x509 = self.connection.get_peer_cert_chain()
    return x509


sock_requests.getpeercertchain = new_getpeercertchain

"""
https://stackoverflow.com/a/16904808/622276
"""

HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__


def new_HTTPResponse__init__(self, *args, **kwargs):
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        self.peercertchain = self._connection.sock.getpeercertchain()
    except AttributeError:
        pass


HTTPResponse.__init__ = new_HTTPResponse__init__

HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response


def new_HTTPAdapter_build_response(self, request, resp):
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peercertchain = resp.peercertchain
    except AttributeError:
        pass
    return response


HTTPAdapter.build_response = new_HTTPAdapter_build_response

"""
Attempt to wrap in a somewhat usable CLI
"""


def cli(args):
    parser = argparse.ArgumentParser(description="Request any URL and dump the certificate chain")
    parser.add_argument("url", metavar="URL", type=str, nargs=1, help="Valid https URL to be handled by requests")
    return vars(parser.parse_args(args))


if __name__ == "__main__":
    cli_args = cli(sys.argv[1:])

    url = cli_args["url"][0]
    req = requests.get(url, verify=False)
    for cert in req.peercertchain:
        print(cert.get_issuer().get_components())
        print(cert.get_notAfter())
