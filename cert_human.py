# -*- coding: utf-8 -*-
"""Utilities for getting and processing certificates."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import asn1crypto.x509
import binascii
import json
import inspect
import requests
import re
import textwrap
import six
import socket
import urllib3
import warnings

from contextlib import contextmanager
from urllib3.contrib import pyopenssl

try:
    import pathlib
except Exception:
    import pathlib2 as pathlib

PEM_TYPE = pyopenssl.OpenSSL.crypto.FILETYPE_PEM
ASN1_TYPE = pyopenssl.OpenSSL.crypto.FILETYPE_ASN1
load_certificate = pyopenssl.OpenSSL.crypto.load_certificate

HTTPSConnectionPool = urllib3.connectionpool.HTTPSConnectionPool
ConnectionCls = HTTPSConnectionPool.ConnectionCls
ResponseCls = HTTPSConnectionPool.ResponseCls

# TODO(!)
"""
add requirements
update readme
"""


class CertX509Store(object):
    """Make SSL certs and their attributes generally more accessible.

    The whole point of this was to be able to provide the same kind of information that is seen
    when looking at an SSL cert in a browser. This can be used to prompt the user for validity
    before doing "something", i.e.:

      - if no cert provided, get the cert and prompt user for validity before continuing
      - if no cert provided, get cert, prompt for valididty, then write to disk for using in
        further connections.
      - ... to print it out and hang it on the wall???
    """

    def __init__(self, x509):
        """Constructor.

        Args:
            x509 (:obj:`asn1crypto.x509.Certificate`): SSL cert in x509 format.
        """
        self._x509 = x509
        self._pem = self.x509_to_pem(x509)
        self._der = self.x509_to_der(x509)
        self._asn1 = self.x509_to_asn1(x509)

    def __str__(self):
        """Show dump_str_info."""
        ret = "{cls}:\n{info}"
        ret = ret.format(cls=clsname(self), info=indent(self.dump_str_info))
        return ret

    def __repr__(self):
        """Use str() for repr()."""
        return self.__str__()

    @property
    def x509(self):
        """Return the original x509 cert object.

        Returns:
            (:obj:`OpenSSL.crypto.X509`): the x509 object provided to object instantiation.
        """
        return self._x509

    @property
    def pem(self):
        """Return the PEM version of the original x509 cert object.

        Returns:
            (:obj:`six.string_types`): The PEM string.
        """
        return self._pem

    @property
    def der(self):
        """Return the DER version of the original x509 cert object.

        Returns:
            (:obj:`six.binary_type`): The DER bytes string.
        """
        return self._der

    @property
    def asn1(self):
        """Return the ASN1 version of the original x509 cert object.

        Returns:
            (:obj:`asn1crypto.x509.Certificate`): The asn1crypto Certificate object.
        """
        return self._asn1

    @property
    def dump(self):
        """Dump dictionary with all attributes of self.

        Returns:
            (:obj:`dict`): all cert attributes as dict.
        """
        return dict(
            issuer=self.issuer,
            issuer_str=self.issuer_str,
            subject=self.subject,
            subject_str=self.subject_str,
            subject_alt_names=self.subject_alt_names,
            subject_alt_names_str=self.subject_alt_names_str,
            fingerprint_sha1=self.fingerprint_sha1,
            fingerprint_sha256=self.fingerprint_sha256,
            public_key=self.public_key,
            public_key_str=self.public_key_str,
            public_key_parameters=self.public_key_parameters,
            public_key_algorithm=self.public_key_algorithm,
            public_key_size=self.public_key_size,
            public_key_exponent=self.public_key_exponent,
            signature=self.signature,
            signature_str=self.signature_str,
            signature_algorithm=self.signature_algorithm,
            x509_version=self.x509_version,
            serial_number=self.serial_number,
            serial_number_str=self.serial_number_str,
            is_expired=self.is_expired,
            is_self_signed=self.is_self_signed,
            is_self_issued=self.is_self_issued,
            not_valid_before=self.not_valid_before,
            not_valid_before_str=self.not_valid_before_str,
            not_valid_after=self.not_valid_after,
            not_valid_after_str=self.not_valid_after_str,
            extensions=self.extensions,
            extensions_str=self.extensions_str,
        )

    @property
    def dump_json_friendly(self):
        """Dump dict with all attributes of self that are JSON friendly.

        Returns:
            (:obj:`dict`): JSON friendly attributes.
        """
        return dict(
            issuer=self.issuer,
            issuer_str=self.issuer_str,
            subject=self.subject,
            subject_str=self.subject_str,
            subject_alt_names=self.subject_alt_names,
            subject_alt_names_str=self.subject_alt_names_str,
            fingerprint_sha1=self.fingerprint_sha1,
            fingerprint_sha256=self.fingerprint_sha256,
            public_key=self.public_key,
            public_key_str=self.public_key_str,
            public_key_parameters=self.public_key_parameters,
            public_key_algorithm=self.public_key_algorithm,
            public_key_size=self.public_key_size,
            public_key_exponent=self.public_key_exponent,
            signature=self.signature,
            signature_str=self.signature_str,
            signature_algorithm=self.signature_algorithm,
            x509_version=self.x509_version,
            serial_number=self.serial_number,
            serial_number_str=self.serial_number_str,
            is_expired=self.is_expired,
            is_self_signed=self.is_self_signed,
            is_self_issued=self.is_self_issued,
            not_valid_before_str=self.not_valid_before_str,
            not_valid_after_str=self.not_valid_after_str,
            extensions=self.extensions,
            extensions_str=self.extensions_str,
        )

    @property
    def dump_json(self):
        """Dump JSON string with all attributes of self that are JSON friendly.

        Returns:
            (:obj:`six.string_types`): JSON string.
        """
        return jdump(self.dump_json_friendly)

    @property
    def dump_str(self):
        """Dump a human friendly str of the all the important bits.

        Returns:
            (:obj:`six.string_types`): human friendly cert str.
        """
        items = [
            self.dump_str_exts,
            self.dump_str_key,
            self.dump_str_info,
        ]
        return "\n\n".join(items)

    @property
    def dump_str_info(self):
        """Dump a human friendly str of the important cert info bits.

        Returns:
            (:obj:`six.string_types`): human friendly cert info str.
        """
        tmpl = "{}: {}".format
        items = [
            tmpl("Issuer", self.issuer_str),
            tmpl("Subject", self.subject_str),
            tmpl("Subject Alternate Names", self.subject_alt_names_str),
            tmpl("Fingerprint SHA1", self.fingerprint_sha1),
            tmpl("Fingerprint SHA256", self.fingerprint_sha256),
            ", ".join([
                tmpl("Expired", self.is_expired),
                tmpl("Not Valid Before", self.not_valid_before_str),
                tmpl("Not Valid After", self.not_valid_after_str),
            ]),
            ", ".join([
                tmpl("Self Signed", self.is_self_signed),
                tmpl("Self Issued", self.is_self_issued),
            ]),
        ]
        return "\n".join(items)

    @property
    def dump_str_exts(self):
        """Dump a human friendly str of the extensions.

        Returns:
            (:obj:`six.string_types`): human friendly cert extensions info str.
        """
        exts = "Extensions:\n{v}".format
        items = [
            exts(v=indent(self.extensions_str)),
        ]
        return "\n".join(items)

    @property
    def dump_str_key(self):
        """Dump a human friendly str of the public_key important bits.

        Returns:
            (:obj:`six.string_types`): human friendly cert public key info str.
        """
        key = "Public Key Algorithm: {a}, Size: {s}, Exponent: {e}, Value:\n{v}".format
        sig = "Signature Algorithm: {a}, Value:\n{v}".format
        sn = "Serial Number:\n{v}".format

        items = [
            key(
                a=self.public_key_algorithm,
                s=self.public_key_size,
                e=self.public_key_exponent,
                v=indent(self.public_key_str),
            ),
            "",
            sig(a=self.signature_algorithm, v=indent(self.signature_str)),
            "",
            sn(v=indent(self.serial_number_str)),
        ]
        return "\n".join(items)

    @property
    def issuer(self):
        """Get issuer parts.

        Returns:
            (:obj:`dict`): Issuer parts as dict.
        """
        return dict(self._cert_native["issuer"])

    @property
    def issuer_str(self):
        """Get issuer parts as string.

        Returns:
            (:obj:`six.string_types`): Issuer parts as str.
        """
        return self.asn1["tbs_certificate"]["issuer"].human_friendly

    @property
    def subject(self):
        """Get subject parts.

        Returns:
            (:obj:`dict`): Subject parts as dict.
        """
        return dict(self._cert_native["subject"])

    @property
    def subject_str(self):
        """Get subject parts as string.

        Returns:
            (:obj:`six.string_types`): Subject parts as str.
        """
        return self.asn1["tbs_certificate"]["subject"].human_friendly

    @property
    def subject_alt_names(self):
        """Get subject alternate names.

        Returns:
            (:obj:`list`): list of subject alternate names.
        """
        try:
            return self.asn1.subject_alt_name_value.native
        except Exception:
            return []

    @property
    def subject_alt_names_str(self):
        """Get subject alternate names as string.

        Returns:
            (:obj:`six.string_types`): CSV of of subject alternate names.
        """
        return ", ".join(self.subject_alt_names)

    @property
    def fingerprint_sha1(self):
        """SHA1 Fingerprint.

        Returns:
            (:obj:`six.string_types`): String of SHA1 fingerprint.
        """
        return self.asn1.sha1_fingerprint

    @property
    def fingerprint_sha256(self):
        """SHA256 Fingerprint.

        Returns:
            (:obj:`six.string_types`): String of SHA256 fingerprint.
        """
        return self.asn1.sha256_fingerprint

    @property
    def public_key(self):
        """Public key.

        Returns:
            (:obj:`six.string_types`): the hex str of the public key.
        """
        pkn = self._public_key_native["public_key"]
        return hexify(pkn["modulus"] if isinstance(pkn, dict) else pkn)

    @property
    def public_key_str(self):
        """Public key as string.

        Returns:
            (:obj:`six.string_types`): the hex str of the public key spaced and wrapped.
        """
        return wrap_it(obj=space_out(obj=self.public_key, join=" "), width=60)

    @property
    def public_key_parameters(self):
        """Public key parameters.

        Returns:
            (:obj:`six.string_types`): the parameters of public key, really only for 'ec' algorithm.
        """
        return self._public_key_native["algorithm"]["parameters"]

    @property
    def public_key_algorithm(self):
        """Public key algorithm.

        Returns:
            (:obj:`six.string_types`): the algorithm of public key ('ec', 'rsa', 'dsa').
        """
        return self._public_key_native["algorithm"]["algorithm"]

    @property
    def public_key_size(self):
        """Public key size.

        Returns:
            (:obj:`six.integer_types`): the size of the public key in bits.
        """
        return self.x509.get_pubkey().bits()

    @property
    def public_key_exponent(self):
        """Public key exponent (only for 'rsa' algorithm).

        Returns:
            (:obj:`six.integer_types`): the exponent of the rsa key.
        """
        pkn = self._public_key_native["public_key"]
        return pkn["public_exponent"] if isinstance(pkn, dict) else None

    @property
    def signature(self):
        """Signature of the certificate body by the issuer's private key.

        Returns:
            (:obj:`six.string_types`): the hex str of the signature.
        """
        return hexify(self.asn1.signature)

    @property
    def signature_str(self):
        """Signature as string.

        Returns:
            (:obj:`six.string_types`): the hex str of the signature spaced and wrapped.
        """
        return wrap_it(obj=space_out(obj=self.signature, join=" "), width=60)

    @property
    def signature_algorithm(self):
        """Algorithm used to sign the public key certificate.

        Returns:
            (:obj:`six.string_types`): the signature algorithm.
        """
        return self._cert_native["signature"]["algorithm"]

    @property
    def x509_version(self):
        """The x509 version this certificate is using.

        Returns:
            (:obj:`six.string_types`): x509 version prepended with 'v'.
        """
        return self._cert_native["version"]

    @property
    def serial_number(self):
        """The serial number for this certificate.

        Returns:
            (:obj:`six.string_types` or :obj:`six.integer_types`): Serial number as int
                if algorithm is 'ec', or hex str of the serial number.
        """
        ret = self._cert_native["serial_number"]
        return hexify(ret) if not self._is_ec else ret

    @property
    def serial_number_str(self):
        """The serial number for this certificate.

        Returns:
            (:obj:`six.string_types` or :obj:`six.integer_types`): Serial number as int
                if algorithm is 'ec', or spaced and wrapped hex str of the serial number.
        """
        if self._is_ec:
            return self.serial_number
        return wrap_it(obj=space_out(obj=self.serial_number, join=" "), width=60)

    @property
    def is_expired(self):
        """Determine if this certificate is expired.

        Returns:
            (:obj:`bool`): value of self.x509.has_expired().
        """
        return self.x509.has_expired()

    @property
    def is_self_signed(self):
        """Determine if this certificate is self_sign.

        Returns:
            (:obj:`six.string_types`): value of self.asn1.self_signed ('yes', 'maybe', or 'no').
        """
        return self.asn1.self_signed

    @property
    def is_self_issued(self):
        """Determine if this certificate is self issued.

        Returns:
            (:obj:`bool`): value of self.asn1.self_issued.
        """
        return self.asn1.self_issued

    @property
    def not_valid_before(self):
        """Certificate valid start date as datetime object.

        Returns:
            (:obj:`datetime.datetime`): datetime.datetime object of valid start date.
        """
        return self._cert_native["validity"]["not_before"]

    @property
    def not_valid_before_str(self):
        """Certificate valid start date as str.

        Returns:
            (:obj:`six.string_types`): string of valid start date.
        """
        return "{}".format(self.not_valid_before)

    @property
    def not_valid_after(self):
        """Certificate valid end date as datetime object.

        Returns:
            (:obj:`datetime.datetime`): datetime.datetime object of valid end date.
        """
        return self._cert_native["validity"]["not_after"]

    @property
    def not_valid_after_str(self):
        """Certificate valid end date as str.

        Returns:
            (:obj:`six.string_types`): string of valid end date.
        """
        return "{}".format(self.not_valid_after)

    @property
    def extensions(self):
        """Certificate extensions as dict.

        This was a doozy to figure out. I finally just resorted to using the str of each
        extension as OpenSSL returns it. Parsing the extensions was not an easy task to approach.

        Returns:
            (:obj:`dict`): extension names mapped to their str values as returned by OpenSSL.
        """
        ret = {}
        for ext in self._extensions:
            name, obj = ext
            obj_str = self._extension_str(obj)
            ret[name] = obj_str
        return ret

    @property
    def extensions_str(self):
        """Certificate extensions as str.

        Returns:
            (:obj:`six.string_types`): Text block of all extensions by index, name, and value.
        """
        ret = []
        for idx, ext in enumerate(self._extensions):
            name, obj = ext
            obj_str = self._extension_str(obj)
            m = "Extension {i}, name={name}, value={value}"
            m = m.format(i=idx + 1, name=name, value=obj_str)
            ret.append(m)
        return "\n".join(ret)

    @classmethod
    def new_from_host_socket(cls, host, port=443, timeout=5):
        """Make instance of this cls using socket module to get the cert.

        Args:
            host (:obj:`six.string_types`): hostname to connect to.
            port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
            timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host
                connect/response. Default: 5.

        Returns:
            (:obj:`CertX509Store`): Instance of this class with PEM cert from
                cls.get_x509_using_socket().
        """
        x509 = cls.get_x509_using_socket(host, port, timeout=timeout)
        return cls(x509)

    @classmethod
    def new_from_host_requests(cls, host, port=443, verify=False, timeout=5):
        """Make instance of this cls using requests module to get the cert.

        Args:
            host (:obj:`six.string_types`): hostname to connect to.
            port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
            timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host
                connect/response. Default: 5.

        Returns:
            (:obj:`CertX509Store`): Instance of this class with x509 cert from
                cls.get_x509_using_requests().
        """
        x509 = cls.get_x509_using_requests(host=host, port=port, verify=verify, timeout=timeout)
        return cls(x509)

    @classmethod
    def new_from_pem_str(cls, pem):
        """Make instance of this cls from a string containing a PEM.

        Args:
            pem (:obj:`six.string_types`): PEM string to convert to x509.

        Returns:
            (:obj:`CertX509Store`): Instance of this class with PEM cert converted to x509.
        """
        x509 = cls.pem_to_x509(pem)
        return cls(x509)

    @classmethod
    def new_from_response_obj(cls, response):
        """Make instance of this cls using a requests.Response object.

        Notes:
            This relies on the fact that enable_urllib3_patch() has been used to add the SSL
            attributes to the response.raw object.

        Args:
            response (:obj:`requests.Response`): response object to get raw.peer_cert from

        Returns:
            (:obj:`CertX509Store`): Instance of this class with x509 cert from
                response.raw.peer_crt.
        """
        x509 = response.raw.peer_cert
        return cls(x509)

    @classmethod
    def get_x509_using_socket(cls, host, port=443, sslv2=False, timeout=5):
        """Get an x509 cert from host:port using the socket module.

        Args:
            host (:obj:`six.string_types`): hostname to connect to.
            port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
            sslv2 (:obj:`bool`, optional): Allow SSL v2 connections. Defaults to: False.
            timeout (:obj:`six.integer_types`, optional): Timeout in seconds for
                host connect/response. Default: 5.

        Returns:
            (:obj:`asn1crypto.x509.Certificate`): x509 certificate from
                ssl_socket.get_peer_certificate()
        """
        with ssl_socket(host=host, port=port, sslv2=sslv2, timeout=timeout) as ssl_sock:
            ret = ssl_sock.get_peer_certificate()
        return ret

    @classmethod
    def get_x509_using_requests(cls, host, port=443, verify=False, timeout=5):
        """Get an x509 cert from host:port using the requests module.

        Notes:
            This relies on the fact that enable_urllib3_patch() has been used to add the SSL
            attributes to the response.raw object.

        Args:
            host (:obj:`six.string_types`): hostname to connect to.
            port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
            timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host
                connect/response. Default: 5.

        Returns:
            (:obj:`asn1crypto.x509.Certificate`): x509 certificate from
                get_response().raw.peer_cert.
        """
        response = get_response(host=host, port=port, verify=verify, timeout=timeout)
        return response.raw.peer_cert

    @classmethod
    def pem_to_x509(cls, pem):
        """Convert from PEM to x509.

        Args:
            pem (:obj:`six.string_types`): PEM string to convert to x509 certificate object.

        Returns:
            (:obj:`OpenSSL.crypto.X509`): x509 certificate object.
        """
        return load_certificate(PEM_TYPE, pem)

    def pem_to_disk(self, path, overwrite=False, mkparent=True, protect=True):
        """Write self.pem to disk.

        Args:
            path (:obj:`six.string_types`): Path to write self.pem to.
        """
        write_file(
            path=path,
            text=self.pem,
            overwrite=overwrite,
            mkparent=mkparent,
            protect=protect,
        )

    @classmethod
    def x509_to_pem(cls, x509):
        """Convert from x509 to PEM.

        Args:
            x509 (:obj:`OpenSSL.crypto.X509`): x509 certificate object to convert to PEM.

        Returns:
            (:obj:`six.string_types`): PEM string.
        """
        pem = pyopenssl.OpenSSL.crypto.dump_certificate(PEM_TYPE, x509)
        return utf8(pem)

    @classmethod
    def x509_to_der(cls, x509):
        """Convert from x509 to DER.

        Args:
            x509 (:obj:`OpenSSL.crypto.X509`): x509 certificate object to convert to DER.

        Returns:
            (:obj:`six.binary_type`): DER bytes string.
        """
        return pyopenssl.OpenSSL.crypto.dump_certificate(ASN1_TYPE, x509)

    @classmethod
    def x509_to_asn1(cls, x509):
        """Convert from x509 to asn1crypto.x509.Certificate.

        Args:
            x509 (:obj:`OpenSSL.crypto.X509`): x509 object to convert to
                asn1crypto.x509.Certificate.

        Returns:
            (:obj:`asn1crypto.x509.Certificate`): x509 object.
        """
        return cls.der_to_asn1(cls.x509_to_der(x509))

    @classmethod
    def der_to_asn1(cls, der):
        """Convert from DER to asn1crypto.x509.Certificate().

        Args:
            der (:obj:`six.binary_type`): DER bytes string to convert to
                asn1crypto.x509.Certificate.

        Returns:
            (:obj:`asn1crypto.x509.Certificate`): x509 object.
        """
        return asn1crypto.x509.Certificate.load(der)

    def _extension_str(self, ext):
        """Format the string of an extension using str(extension).

        Returns:
            (:obj:`six.string_types`): Cleaned up format of str(extension).
        """
        lines = [x for x in format(ext).splitlines() if x]
        j = " " if len(lines) < 5 else "\n"
        return j.join(lines)

    @property
    def _extensions(self):
        """Chew up the extensions in self.x509.

        Returns:
            (:obj:`list` of `list`): list mapping of extension name to extension object.
        """
        exts = [self.x509.get_extension(i) for i in range(self.x509.get_extension_count())]
        return [[utf8(e.get_short_name()), e] for e in exts]

    @property
    def _public_key_native(self):
        """Utility for easy access to the dict in self.asn1.public_key.

        Returns:
            (:obj:`dict`): native python object from self.asn1.public_key.
        """
        return self.asn1.public_key.native

    @property
    def _cert_native(self):
        """Utility for easy access to the dict in self.asn1.

        Returns:
            (:obj:`dict`): native python object from self.asn1.
        """
        return self.asn1.native["tbs_certificate"]

    @property
    def _is_ec(self):
        """Determine if this certificates public key algorithm is Elliptic Curve ('ec').

        Returns:
            (:obj:`bool`): if self.public_key_algorithm == "ec"
        """
        return self.public_key_algorithm == "ec"


class CertX509ChainStore(object):
    """Make SSL cert chains and their attributes generally more accessible.

    This is really just a list container for a cert chain, which is just a list of x509 certs.
    """

    def __init__(self, cert_chain):
        """Constructor.

        Args:
            x509 (:obj:`list` of :obj:`asn1crypto.x509.Certificate`): List of SSL certs
                in x509 format.
        """
        self._x509 = cert_chain
        self._certs = [CertX509Store(c) for c in cert_chain]

    def __str__(self):
        """Show most useful information of all certs in cert chain."""
        ret = "{cls} with {num} certs:{certs}"
        ret = ret.format(cls=clsname(self), num=len(self), certs=self.dump_str_info)
        return ret

    def __repr__(self):
        """Use str() for repr()."""
        return self.__str__()

    def __getitem__(self, i):
        """Passthru to self._certs list container."""
        return self._certs[i]

    def __len__(self):
        """Passthru to self._certs list container."""
        return len(self._certs)

    def append(self, value):
        if isinstance(value, six.string_types):
            self._certs.append(CertX509Store.new_from_pem(value))
        elif isinstance(value, CertX509Store):
            self._certs.append(value)

    @property
    def certs(self):
        """Expose self._certs list container."""
        return self._certs

    @property
    def pem(self):
        """Return all of the joined PEM strings for each cert in self.

        Returns:
            (:obj:`six.string_types`): all PEM strings joined.
        """
        return "".join([c.pem for c in self])

    def pem_to_disk(self, path, overwrite=False, mkparent=True, protect=True):
        """Write self.pem to disk.

        Args:
            path (:obj:`six.string_types`): Path to write self.pem to.
        """
        write_file(
            path=path,
            text=self.pem,
            overwrite=overwrite,
            mkparent=mkparent,
            protect=protect,
        )

    @property
    def dump_json_friendly(self):
        """Dump dict with all attributes of each cert in self that are JSON friendly.

        Returns:
            (:obj:`list` of :obj:`dict`): JSON friendly attributes.
        """
        return [o.dump_json_friendly for o in self]

    @property
    def dump_json(self):
        """Dump JSON string with all attributes of each cert in self that are JSON friendly.

        Returns:
            (:obj:`six.string_types`): JSON string.
        """
        return jdump(self.dump_json_friendly)

    @property
    def dump(self):
        """Dump dictionary with all attributes of each cert in self.

        Returns:
            (:obj:`list` of :obj:`dict`): all cert attributes as dict.
        """
        return [o.dump for o in self]

    @property
    def dump_str(self):
        """Dump a human friendly str of the all the important bits for each cert in self.

        Returns:
            (:obj:`six.string_types`): human friendly certs str.
        """
        tmpl = "{c} #{i}\n{s}".format
        items = [
            tmpl(c=clsname(c), i=i + 1, s=indent(c.dump_str))
            for i, c in enumerate(self._certs)
        ]
        return "\n  " + "\n  ".join(items)

    @property
    def dump_str_info(self):
        """Dump a human friendly str of the important cert info bits for each cert in self.

        Returns:
            (:obj:`six.string_types`): human friendly certs info str.
        """
        tmpl = "-{di} {c} #{i}\n{s}\n".format
        items = [
            tmpl(
                di="-" * i + "/" if i else "",
                c=clsname(c),
                i=i + 1,
                s=indent(c.dump_str_info),
            )
            for i, c in enumerate(self._certs)
        ]
        return "\n  " + "\n  ".join(items)

    @property
    def dump_str_key(self):
        """Dump a human friendly str of the public_key important bits for each cert in self.

        Returns:
            (:obj:`six.string_types`): human friendly certs public key info str.
        """
        tmpl = "{c} #{i}\n{s}".format
        items = [
            tmpl(c=clsname(c), i=i + 1, s=indent(c.dump_str_key))
            for i, c in enumerate(self._certs)
        ]
        return "\n  " + "\n  ".join(items)

    @property
    def dump_str_exts(self):
        """Dump a human friendly str of the extensions for each cert in self.

        Returns:
            (:obj:`six.string_types`): human friendly certs extensions info str.
        """
        tmpl = "{c} #{i}\n{s}".format
        items = [
            tmpl(c=clsname(c), i=i + 1, s=indent(c.dump_str_exts))
            for i, c in enumerate(self._certs)
        ]
        return "\n  " + "\n  ".join(items)

    @classmethod
    def new_from_pem_str(cls, pem):
        """Make instance of this cls from a string containing multiple PEM certs.

        Args:
            pem (:obj:`six.string_types`): PEM string with multiple pems to convert to x509.

        Returns:
            (:obj:`CertX509ChainStore`): Instance of this class with PEM certs converted to x509.
        """
        x509 = cls.pem_to_x509(pem)
        return cls(x509)

    @classmethod
    def new_from_host_socket(cls, host, port=443, timeout=5):
        """Make instance of this cls using socket module to get the cert chain.

        Args:
            host (:obj:`six.string_types`): hostname to connect to.
            port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
            timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host
                connect/response. Default: 5.

        Returns:
            (:obj:`CertX509Store`): Instance of this class with PEM cert from
                cls.get_x509_using_socket().
        """
        x509 = cls.get_x509_using_socket(host, port, timeout=timeout)
        return cls(x509)

    def new_from_host_requests(cls, host, port=443, verify=False, timeout=5):
        """Make instance of this cls using requests module to get the cert chain.

        Args:
            host (:obj:`six.string_types`): hostname to connect to.
            port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
            timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host
                connect/response. Default: 5.

        Returns:
            (:obj:`CertX509ChainStore`): Instance of this class with x509 cert chains from
                cls.get_x509_using_requests().
        """
        x509 = cls.get_x509_using_requests(host=host, port=port, verify=verify, timeout=timeout)
        return cls(x509)

    @classmethod
    def new_from_response_obj(cls, response):
        """Make instance of this cls using a requests.Response.raw object.

        Notes:
            This relies on the fact that enable_urllib3_patch() has been used to add the SSL
            attributes to the response.raw object.

        Args:
            response (:obj:`requests.Response`): response object to get raw.peer_cert_chain from

        Returns:
            (:obj:`CertX509ChainStore`): Instance of this class with x509 cert chains from
                response.raw.peer_cert_chain.
        """
        x509 = response.raw.peer_cert_chain
        return cls(x509)

    @classmethod
    def get_x509_using_requests(cls, host, port=443, verify=False, timeout=5):
        """Get an x509 cert chain from host:port using the requests module.

        Notes:
            This relies on the fact that enable_urllib3_patch() has been used to add the SSL
            attributes to the response.raw object.

        Args:
            host (:obj:`six.string_types`): hostname to connect to.
            port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
            timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host
                connect/response. Default: 5.

        Returns:
            (:obj:`asn1crypto.x509.Certificate`): x509 certificate chain from
                get_response().raw.peer_cert_chain.
        """
        response = get_response(host=host, port=port, verify=verify, timeout=timeout)
        return response.raw.peer_cert_chain

    @classmethod
    def get_x509_using_socket(cls, host, port=443, sslv2=False, timeout=5):
        """Get an x509 cert chain from host:port using the socket module.

        Args:
            host (:obj:`six.string_types`): hostname to connect to.
            port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
            sslv2 (:obj:`bool`, optional): Allow SSL v2 connections. Defaults to: False.
            timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host
                connect/response. Default: 5.

        Returns:
            (:obj:`asn1crypto.x509.Certificate`): x509 certificate from
                ssl_socket.get_peer_certificate()
        """
        with ssl_socket(host=host, port=port, sslv2=sslv2, timeout=timeout) as ssl_sock:
            ret = ssl_sock.get_peer_cert_chain()
        return ret

    @classmethod
    def pem_to_x509(cls, pem):
        """Convert from PEM with multiple certs to x509.

        Args:
            pem (:obj:`six.string_types`): PEM string with multiple certificates to convert
                to x509 certificate object.

        Returns:
            (:obj:`list` of :obj:`OpenSSL.crypto.X509`): List of x509 certificate object.
        """
        pems = find_certs(txt=pem)
        return [load_certificate(PEM_TYPE, pem) for pem in pems]


def get_response(host, port=443, verify=False, timeout=5, scheme="https://", nowarn=True,
                 **kwargs):
    """Get a requests.Response object with cert attributes.

    The point of this is to fetch a requests.Response object that has certificate attributes.

    Args:
        host (:obj:`six.string_types`): hostname to connect to. can be any of: "scheme://host:port",
            "scheme://host", or "host".
        port (:obj:`six.integer_types`, optional): port to connect to on host.
            If no :PORT in host, this will be added to host. Default: 443
        verify (:obj:`bool`, optional): Enable cert validation in requests. If this is False,
            warnings from requests will also be silenced. Default: False.
        timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host connect/response.
            Default: 5.
        scheme (:obj:`str`, optional): Scheme to add to host if no "://" in host.
            Default: "https://".
        nowarn (:obj:`bool`, optional): Disable HTTPWarning warnings issued by requests.
        **kwargs: passed thru to requests.get()

    Returns:
        response (:obj:`requests.Response`): requests object with certificate attributes
            accessible from response.raw.
    """
    if "://" not in host:
        url = "https://{host}".format(host=host)
    if not re.search(r":\d+", host):
        url = "{url}:{port}".format(url=url, port=port)

    req_kwargs = {}
    req_kwargs["url"] = url
    req_kwargs.update(kwargs)
    req_kwargs.update(dict(timeout=timeout, verify=verify))

    with warnings.catch_warnings():
        with urllib3_patch():
            if nowarn:
                category = requests.packages.urllib3.exceptions.HTTPWarning
                warnings.simplefilter(action="ignore", category=category)
            return requests.get(**req_kwargs)


@contextmanager
def ssl_socket(host, port=443, sslv2=False, timeout=5, *args, **kwargs):
    """Context manager to create an SSL socket.

    Args:
        host (:obj:`six.string_types`): hostname to connect to.
        port (:obj:`six.integer_types`, optional): port to connect to on host. Defaults to: 443.
        sslv2 (:obj:`bool`, optional): Allow SSL v2 connections. Defaults to: False.
        timeout (:obj:`six.integer_types`, optional): Timeout in seconds for host connect/response.
            Default: 5.

    Yields:
        (:obj:`OpenSSL.SSL.Connection`): The wrapped SSL socket.
    """
    method = pyopenssl.OpenSSL.SSL.TLSv1_METHOD  # Use TLS Method
    ssl_context = pyopenssl.OpenSSL.SSL.Context(method)

    if not sslv2:
        options = pyopenssl.OpenSSL.SSL.OP_NO_SSLv2  # Don't accept SSLv2
        ssl_context.set_options(options)

    sock = socket.socket(*args, **kwargs)
    sock.settimeout(timeout)
    ssl_sock = pyopenssl.OpenSSL.SSL.Connection(ssl_context, sock)
    ssl_sock.connect((host, port))
    ssl_sock.do_handshake()

    try:
        yield ssl_sock
    finally:
        ssl_sock.close()


def utf8(obj):
    """Decode wrapper.

    Args:
        obj (:obj:`six.string_types`): The text to decode to utf-8.

    Returns:
        obj (:obj:`six.string_types`): The utf-8 str.
    """
    try:
        return obj.decode("utf-8")
    except Exception:
        return obj


def indent(txt, n=4):
    """Text indenter.

    Args:
        txt (:obj:`six.string_types`): The text to indent.
        n (:obj:`six.integer_types`, optional): Number of spaces to indent txt. Defaults to: 4.

    Returns:
        (:obj:`six.string_types`): The indented text.
    """
    txt = "{}".format(txt)
    return "\n".join(["{s}{line}".format(s=" " * n, line=l) for l in txt.splitlines()])


def clsname(obj):
    """Get objects class name.

    Args:
        obj (:obj:`object` or :obj:`class`): The object or class to get the name of.

    Returns:
        obj (:obj:`six.string_types`): The name of obj.
    """
    if inspect.isclass(obj) or obj.__module__ in set(['builtins', '__builtin__']):
        return obj.__name__
    return obj.__class__.__name__


def jdump(obj, indent=2):
    """Dump obj to JSON str.

    Args:
        obj (:obj:`dict` or :obj:`list`): The object to dump to JSON.
        indent (:obj:`six.integer_types`, optional): Indent to use in JSON output. Defaults to: 2.

    Returns:
        (:obj:`six.string_types`): The JSON string.
    """
    return json.dumps(obj, indent=indent)


def hexify(obj):
    """Convert bytes, int, or str to hex.

    Args:
        obj (:obj:`six.string_types` or :obj:`six.binary_type` or :obj:`six.integer_types`):
            The object to convert into hex.

    Returns:
        obj (:obj:`six.string_types`): The hex string of obj.
    """
    if isinstance(obj, six.string_types) or isinstance(obj, six.binary_type):
        ret = binascii.hexlify(obj)
    elif isinstance(obj, six.integer_types):
        ret = format(obj, "X")
    ret = (utf8(ret) if isinstance(ret, six.binary_type) else ret).upper()
    return ret


def space_out(obj, join=" ", every=2, zerofill=True):
    """Split obj out every n and re-join using join.

    Args:
        obj (:obj:`six.string_types`): The string to split.
        join (:obj:`str`, optional): The string to use when rejoining the spaced out values.
            Defaults to: " ".
        every (:obj:`six.integer_types`, optional): The number of characters to split on.
            Defaults to: 2.
        zerofill (:obj:`bool`, optional): Zero fill the string before splitting if the string
            length is not even. This gets around oddly sized hex strings. Defaults to: True.

    Returns:
        obj (:obj:`six.string_types`): The spaced out string.
    """
    if len(obj) % 2 and zerofill:
        obj = obj.zfill(len(obj) + 1)
    if join is not None:
        obj = join.join(obj[i:i+every] for i in range(0, len(obj), every))
    return obj


def wrap_it(obj, width=60):
    """Wrap str obj to width.

    Args:
        obj (:obj:`six.string_types`): The str object to wrap.
        width (:obj:`six.integer_types`, optional): The width to wrap obj at. Defaults to: 60.

    Returns:
        obj (:obj:`six.string_types`): The wrapped text.
    """
    return "\n".join(textwrap.wrap(obj, width)) if width else obj


def write_file(path, text, overwrite=False, mkparent=True, protect=True):
    """Write text to path.

    Args:
        path (:obj:`six.string_types` or (:obj:`pathlib.Path`): The path to write text to.
        text (:obj:`six.string_types`): The text to write to path.
        overwrite (:obj:`bool`, optional): If path exists, overwrite it. Defaults to: False.
        mkparent (:obj:`bool`, optional): If parent directory of path does not exist,
            create it. Defaults to: True.
        protect (:obj:`bool`, optional): Change the permissions of the file to 0600 and the parent
            directory to 0700 after writing the file.
    """
    path = pathlib.Path(path)
    parent = path.parent

    if path.is_file() and overwrite is False:
        error = "File '{path}' already exists and overwrite is False"
        error = error.format(path=path)
        raise Exception(error)

    if not parent.isdir():
        if mkparent:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            error = "Directory '{path}' does not exist and mkparent is False"
            error = error.format(path=parent)
            raise Exception(error)

    path.write_text(text)

    if protect:
        parent.chmod(0o700)
        path.chmod(0o600)


class HTTPSConnectionWithCert(ConnectionCls):

    def connect(self):
        super(HTTPSConnectionWithCert, self).connect()
        self._set_cert_attrs()

    def _set_cert_attrs(self):
        """Add cert info from the socket connection to a HTTPSConnection object.

        Adds the following attributes:
            peer_cert: x509 certificate of the server
            peer_cert_chain: x509 certificate chain of the server
            peer_cert_dict: dictionary containing commonName and subjectAltName
        """
        self.peer_cert = self.sock.connection.get_peer_certificate()
        self.peer_cert_chain = self.sock.connection.get_peer_cert_chain()
        self.peer_cert_dict = self.sock.getpeercert()


class HTTPSResponseWithCert(ResponseCls):

    def __init__(self, *args, **kwargs):
        super(HTTPSResponseWithCert, self).__init__(*args, **kwargs)
        self._set_cert_attrs()

    def _set_cert_attrs(self):
        """Add cert info from a HTTPSConnection object to a HTTPSResponse object.

        This allows accessing the attributes in a HTTPSConnectionWithCert from a
        requests.Response object like so:
            response.raw.peer_cert
            response.raw.peer_cert_chain
            response.raw.peer_cert_dict
        """
        self.peer_cert = self._connection.peer_cert
        self.peer_cert_chain = self._connection.peer_cert_chain
        self.peer_cert_dict = self._connection.peer_cert_dict


def enable_urllib3_patch():
    """Patch HTTPSConnectionPool to use the WithCert Connect/Response classes.

    Changes ConnectionCls and ResponseCls in HTTPSConnectionPool back to the WithCert classes.
    """
    HTTPSConnectionPool.ConnectionCls = HTTPSConnectionWithCert
    HTTPSConnectionPool.ResponseCls = HTTPSResponseWithCert


def disable_urllib3_patch():
    """Unpatch HTTPSConnectionPool to use the default Connect/Response classes.

    Changes ConnectionCls and ResponseCls in HTTPSConnectionPool back to their original classes.
    """
    HTTPSConnectionPool.ConnectionCls = ConnectionCls
    HTTPSConnectionPool.ResponseCls = ResponseCls


@contextmanager
def urllib3_patch():
    """Context manager to enable/disable cert patch.

    Yields:
        None
    """
    enable_urllib3_patch()
    yield
    disable_urllib3_patch()


def using_urllib3_patch():
    """Check if HTTPSConnectionPool is using the WithCert Connect/Response classes.

    Returns:
        (:obj:`bool`): if HTTPSConnectionPool is using the WithCert classes.
    """
    connect = HTTPSConnectionPool.ConnectionCls == HTTPSConnectionWithCert
    response = HTTPSConnectionPool.ResponseCls == HTTPSResponseWithCert
    return all([connect, response])


def check_urllib3_patch():
    """Throw exception if HTTPSConnectionPool is not using the WithCert Connect/Response classes.

    Raises:
        Exception: if using_urllib3_patch() returns False.
    """
    if not using_urllib3_patch():
        error = "Not using WithCert classes in {}, use enable_urllib3_patch()"
        error = error.format(HTTPSConnectionPool)
        raise Exception(error)


def find_certs(txt):
    """Split text with multiple certificates into a list of certificates.

    Args:
        txt (:obj:`str`): the text to find certificates in.

    Returns:
        (:obj:`list`): List of certificates found in txt.
    """
    pattern = r"-----BEGIN.*?-----.*?-----END.*?-----"
    pattern = re.compile(pattern, re.DOTALL)
    return pattern.findall(txt)
