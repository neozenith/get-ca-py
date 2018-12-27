#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Patch tools to add certs to urllib3 connections."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import urllib3


HTTPSConnectionPool = urllib3.connectionpool.HTTPSConnectionPool
ConnectionCls = HTTPSConnectionPool.ConnectionCls
ResponseCls = HTTPSConnectionPool.ResponseCls


class HTTPSConnectionWithCert(ConnectionCls):

    def connect(self):
        """Add cert info from the socket connection to a HTTPSConnection object.

        Adds the following attributes:
            peer_cert: x509 certificate of the server
            peer_cert_chain: x509 certificate chain of the server
            peer_cert_dict: dictionary containing commonName and subjectAltName
        """
        super(HTTPSConnectionWithCert, self).connect()
        self.peer_cert = self.sock.connection.get_peer_certificate()
        self.peer_cert_chain = self.sock.connection.get_peer_cert_chain()
        self.peer_cert_dict = self.sock.getpeercert()


class HTTPSResponseWithCert(ResponseCls):

    def __init__(self, *args, **kwargs):
        """Add cert info from a HTTPSConnection object to a HTTPSResponse object.

        This allows accessing the attributes in a HTTPSConnectionWithCert from a
        requests.Response object like so:
            response.raw.peer_cert
            response.raw.peer_cert_chain
            response.raw.peer_cert_dict
        """
        super(HTTPSResponseWithCert, self).__init__(*args, **kwargs)
        self.peer_cert = self._connection.peer_cert
        self.peer_cert_chain = self._connection.peer_cert_chain
        self.peer_cert_dict = self._connection.peer_cert_dict


def enable_with_cert():
    """Patch HTTPSConnectionPool to use the WithCert Connect/Response classes."""
    HTTPSConnectionPool.ConnectionCls = HTTPSConnectionWithCert
    HTTPSConnectionPool.ResponseCls = HTTPSResponseWithCert


def disable_with_cert():
    """Unpatch HTTPSConnectionPool to use the default Connect/Response classes."""
    HTTPSConnectionPool.ConnectionCls = ConnectionCls
    HTTPSConnectionPool.ResponseCls = ResponseCls


def using_with_cert():
    """Check if HTTPSConnectionPool is using the WithCert Connect/Response classes."""
    connect = HTTPSConnectionPool.ConnectionCls == HTTPSConnectionWithCert
    response = HTTPSConnectionPool.ResponseCls == HTTPSResponseWithCert
    return all([connect, response])


def check_with_cert():
    """Throw exception if HTTPSConnectionPool is not using the WithCert Connect/Response classes."""
    if not using_with_cert():
        error = "Not using WithCert classes in {}, use enable_with_cert()"
        error = error.format(HTTPSConnectionPool)
        raise Exception(error)
