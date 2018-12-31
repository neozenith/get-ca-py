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
import warnings

from contextlib import contextmanager
from requests.packages.urllib3.contrib import pyopenssl
from requests.packages import urllib3

from .__version__ import __title__, __description__, __url__, __version__  # noqa
from .__version__ import __author__, __author_email__, __license__  # noqa
from .__version__ import __copyright__  # noqa

try:
    import pathlib
except Exception:
    import pathlib2 as pathlib

PEM_TYPE = pyopenssl.OpenSSL.crypto.FILETYPE_PEM
ASN1_TYPE = pyopenssl.OpenSSL.crypto.FILETYPE_ASN1

HTTPSConnectionPool = urllib3.connectionpool.HTTPSConnectionPool
ConnectionCls = HTTPSConnectionPool.ConnectionCls
ResponseCls = HTTPSConnectionPool.ResponseCls


class HTTPSConnectionWithCert(ConnectionCls):

    def connect(self):
        super(HTTPSConnectionWithCert, self).connect()
        self._set_cert_attrs()

    def _set_cert_attrs(self):
        """Add cert info from the socket connection to a HTTPSConnection object.

        Adds the following attributes:

          - peer_cert: x509 certificate of the server
          - peer_cert_chain: x509 certificate chain of the server
          - peer_cert_dict: dictionary containing commonName and subjectAltName
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

          - :obj:`requests.Response`.raw.peer_cert
          - :obj:`requests.Response`.raw.peer_cert_chain
          - :obj:`requests.Response`.raw.peer_cert_dict
        """
        self.peer_cert = self._connection.peer_cert
        self.peer_cert_chain = self._connection.peer_cert_chain
        self.peer_cert_dict = self._connection.peer_cert_dict


def enable_urllib3_patch():
    """Patch HTTPSConnectionPool to use the WithCert Connect/Response classes.

    Examples:

        Make a request using :obj:`requests` and patch urllib3 until you want to unpatch it:

        >>> cert_human.enable_urllib3_patch()
        >>> response1 = requests.get("https://www.google.com")
        >>> response2 = requests.get("https://cyborg", verify=False)  # self-signed, don't verify
        >>> print(response1.raw.peer_cert.get_subject().get_components())
        >>> print(response2.raw.peer_cert.get_subject().get_components())
        >>> # optionally disable the urllib3 patch once you no longer need
        >>> # to make requests with the cert attributes attached
        >>> cert_human.disable_urllib3_patch()

    Notes:

        Changes :attr:`urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls` and
        :attr:`urllib3.connectionpool.HTTPConnectionPool.ResponseCls` in
        :obj:`urllib3.connectionpool.HTTPSConnectionPool` to the WithCert classes.

    """
    HTTPSConnectionPool.ConnectionCls = HTTPSConnectionWithCert
    HTTPSConnectionPool.ResponseCls = HTTPSResponseWithCert


def disable_urllib3_patch():
    """Unpatch HTTPSConnectionPool to use the default Connect/Response classes.

    Notes:

        Changes :attr:`urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls` and
        :attr:`urllib3.connectionpool.HTTPConnectionPool.ResponseCls` in
        :obj:`urllib3.connectionpool.HTTPSConnectionPool` back to their original classes.
    """
    HTTPSConnectionPool.ConnectionCls = ConnectionCls
    HTTPSConnectionPool.ResponseCls = ResponseCls


@contextmanager
def urllib3_patch():
    """Context manager to enable/disable cert patch.

    Examples:

        Make a request using :obj:`requests` using this context manager to patch urllib3:

        >>> import requests
        >>> with cert_human.urllib3_patch():
        ...   response = requests.get("https://www.google.com")
        ...
        >>> print(response.raw.peer_cert.get_subject().get_components())
    """
    enable_urllib3_patch()
    yield
    disable_urllib3_patch()


def using_urllib3_patch():
    """Check if HTTPSConnectionPool is using the WithCert Connect/Response classes.

    Returns:
        (:obj:`bool`)
    """
    connect = HTTPSConnectionPool.ConnectionCls == HTTPSConnectionWithCert
    response = HTTPSConnectionPool.ResponseCls == HTTPSResponseWithCert
    return all([connect, response])


def check_urllib3_patch():
    """Throw exception if HTTPSConnectionPool is not using the WithCert Connect/Response classes.

    Raises:
        (:obj:`CertHumanError`): if using_urllib3_patch() returns False.
    """
    if not using_urllib3_patch():
        error = "Not using WithCert classes in {}, use enable_urllib3_patch()"
        error = error.format(HTTPSConnectionPool)
        raise CertHumanError(error)


def get_response(host, port=443, verify=False, timeout=5, scheme="https://", nowarn=True,
                 **kwargs):
    """Get a requests.Response object with cert attributes.

    Examples:

        Make a request to a site that has a valid cert:

        >>> response = cert_human.get_response(host="www.google.com")
        >>> print(response.raw.peer_cert.get_subject().get_components())
        >>> print(response.raw.peer_cert_chain)
        >>> print(response.raw.peer_cert_dict)

        Make a request to a site that has an invalid cert (self-signed):

        >>> response = cert_human.get_response(host="cyborg")
        >>> print(response.raw.peer_cert.get_subject().get_components())

    Notes:
        This is to fetch a requests.Response object that has certificate attributes. Workflow:

        * Uses a context manager to disable warnings about SSL certificate validation.
        * Uses a context manager to patch urllib3 to add SSL certificate attributes to the
          HTTPSResponse object, which is then accessible via the :obj:`requests.Response`.raw
          object.
        * Makes a request to a server using :func:`requests.get`

    Args:
        host (:obj:`str`): hostname to connect to. can be any of: "scheme://host:port",
            "scheme://host", or "host".
        port (:obj:`str`, optional): port to connect to on host.
            If no :PORT in host, this will be added to host. Defaults to: 443
        verify (:obj:`bool`, optional): Enable cert validation in requests. Defaults to: False.
        timeout (:obj:`str`, optional):
            Timeout in seconds for host connect/response. Defaults to: 5.
        scheme (:obj:`str`, optional):
            Scheme to add to host if no "://" in host. Defaults to: "https://".
        nowarn (:obj:`bool`, optional): Disable HTTPWarning warnings issued by requests.
        kwargs: passed thru to requests.get()

    Returns:
        (:obj:`requests.Response`)
    """
    if "://" not in host:
        url = "https://{host}".format(host=host)
    if not re.search(r":\d+", host):
        url = "{url}:{port}".format(url=url, port=port)

    req_kwargs = dict(url=url, timeout=timeout, verify=verify)
    req_kwargs.update(kwargs)

    with warnings.catch_warnings():
        with urllib3_patch():
            if nowarn:
                category = requests.packages.urllib3.exceptions.HTTPWarning
                warnings.simplefilter(action="ignore", category=category)
            return requests.get(**req_kwargs)


@contextmanager
def ssl_socket(host, port=443, sslv2=False, *args, **kwargs):
    """Context manager to create an SSL socket.

    Examples:

        Use sockets and OpenSSL to make a request using this context manager:

        >>> with cert_human.ssl_socket(host="cyborg", port=443) as sock:
        ...   cert = sock.get_peer_certificate()
        ...   cert_chain = sock.get_peer_cert_chain()
        ...
        >>> print(cert.get_subject().get_components())
        >>> print(cert_chain)

    Args:
        host (:obj:`str`): hostname to connect to.
        port (:obj:`str`, optional): port to connect to on host. Defaults to: 443.
        sslv2 (:obj:`bool`, optional): Allow SSL v2 connections. Defaults to: False.

    Yields:
        (:obj:`OpenSSL.SSL.Connection`)
    """
    method = pyopenssl.OpenSSL.SSL.TLSv1_METHOD  # Use TLS Method
    ssl_context = pyopenssl.OpenSSL.SSL.Context(method)

    if not sslv2:
        options = pyopenssl.OpenSSL.SSL.OP_NO_SSLv2  # Don't accept SSLv2
        ssl_context.set_options(options)

    sock = socket.socket(*args, **kwargs)
    ssl_sock = pyopenssl.OpenSSL.SSL.Connection(ssl_context, sock)
    ssl_sock.connect((host, port))

    try:
        ssl_sock.do_handshake()
        yield ssl_sock
    finally:
        ssl_sock.close()


class CertStore(object):
    """Make SSL certs and their attributes generally more accessible.

    Examples:

        >>> cert = CertStore(x509)  # x509 cert from any number of methods.
        >>> # not echoing any of these due to length
        >>> print(cert)  # print the basic info for this cert
        >>> x = cert.issuer  # get a dict of the issuer info.
        >>> print(cert.issuer_str)  # print the issuer in str form.
        >>> x = cert.subject  # get a dict of the subject info.
        >>> print(cert.subject_str)  # print the subject in str form.
        >>> print(cert.dump_str_exts). # print the extensions in str form.
        >>> print(cert.pem) # print the PEM version.
        >>> print(cert.public_key_str)  # print the public key.
        >>> print(cert.dump_str_key)  # print a bunch of public key info.
        >>> print(cert.dump_str_info)  # print the same information that str(cert) prints.
        >>> x = cert.dump  # get a dict of ALL attributes.
        >>> x = cert.dump_json_friendly  # get a dict of only the JSON friendly attributes.
        >>> print(cert.dump_json)  # print a json str of only the JSON friendly attributes.
        >>> # and so on

    Notes:

        The whole point of this was to be able to provide the same kind of information that is seen
        when looking at an SSL cert in a browser. This can be used to prompt the user for validity
        before doing "something". Examples:

        * If no cert provided, get the cert and prompt user for validity before continuing
        * If no cert provided, get cert, prompt for validity, then write to disk for using in
          further connections.
        * ... to print it out and hang it on the wall???
    """

    def __init__(self, x509):
        """Constructor.

        Args:
            x509 (x509.Certificate): SSL cert in x509 format.
        """
        self._x509 = x509
        self._pem = x509_to_pem(x509)
        self._der = x509_to_der(x509)
        self._asn1 = x509_to_asn1(x509)

    def __str__(self):
        """Show dump_str_info."""
        ret = "{cls}:\n{info}"
        ret = ret.format(cls=clsname(self), info=indent(self.dump_str_info))
        return ret

    def __repr__(self):
        """Use str() for repr()."""
        return self.__str__()

    @classmethod
    def new_from_host_socket(cls, host, port=443, sslv2=False):
        """Make instance of this cls using socket module to get the cert.

        Examples:

            >>> cert = cert_human.CertStore.new_from_host_socket("cyborg")
            >>> print(cert)

        Args:
            host (:obj:`str`): hostname to connect to.
            port (:obj:`str`, optional): port to connect to on host. Defaults to: 443.
            sslv2 (:obj:`bool`, optional): Allow SSL v2 connections. Defaults to: False.

        Returns:
            (:obj:`CertStore`)
        """
        with ssl_socket(host=host, port=port, sslv2=sslv2) as ssl_sock:
            return cls(ssl_sock.get_peer_certificate())

    @classmethod
    def new_from_host_requests(cls, host, port=443, verify=False, timeout=5):
        """Make instance of this cls using requests module to get the cert.

        Examples:

            >>> cert = cert_human.CertStore.new_from_host_requests("cyborg")
            >>> print(cert)

        Args:
            host (:obj:`str`): hostname to connect to.
            port (:obj:`str`, optional): port to connect to on host. Defaults to: 443.
            timeout (:obj:`str`, optional):
                Timeout in seconds for host connect/response. Defaults to: 5.

        Returns:
            (:obj:`CertStore`)
        """
        response = get_response(host=host, port=port, verify=verify, timeout=timeout)
        return cls(response.raw.peer_cert)

    @classmethod
    def new_from_response_obj(cls, response):
        """Make instance of this cls using a requests.Response object.

        Examples:

            >>> cert.enable_urllib3_patch()
            >>> response = requests.get("https://cyborg", verify=False)
            >>> cert = cert_human.CertStore.new_from_response_obj(response)
            >>> print(cert)

        Notes:
            This relies on the fact that :func:`enable_urllib3_patch` has been used to add the SSL
            attributes to :obj:`requests.Response`.raw object.

        Args:
            response (:obj:`requests.Response`): response object to get raw.peer_cert from

        Returns:
            (:obj:`CertStore`)
        """
        return cls(response.raw.peer_cert)

    @classmethod
    def new_from_pem_str(cls, pem):
        """Make instance of this cls from a string containing a PEM.

        Args:
            pem (:obj:`str`): PEM string to convert to x509.

        Returns:
            (:obj:`CertStore`)
        """
        return cls(pem_to_x509(pem))

    @property
    def pem(self):
        """Return the PEM version of the original x509 cert object.

        Returns:
            (:obj:`str`)
        """
        return self._pem

    @property
    def x509(self):
        """Return the original x509 cert object.

        Returns:
            (:obj:`OpenSSL.crypto.X509`)
        """
        return self._x509

    @property
    def der(self):
        """Return the DER bytes version of the original x509 cert object.

        Returns:
            (:obj:`bytes`)
        """
        return self._der

    @property
    def asn1(self):
        """Return the ASN1 version of the original x509 cert object.

        Returns:
            (:obj:`x509.Certificate`)
        """
        return self._asn1

    def to_disk(self, path, overwrite=False, mkparent=True, protect=True):
        """Write self.pem to disk.

        Examples:

            >>> # get a cert using sockets:
            >>> cert = cert_human.CertStore.new_from_host_socket("cyborg")
            >>> # or, get a cert using requests:
            >>> cert = cert_human.CertStore.new_from_host_requests("cyborg")

            >>> # ideally, do some kind of validation with the user here
            >>> # i.e. use ``print(cert.dump_str)`` to show the same kind of information
            >>> # that a browser would show

            >>> # then write to disk:
            >>> cert_path = cert.to_disk("~/cyborg.pem")

            >>> # use requests with the newly written cert, no SSL warnings or SSL validation
            >>> # errors happen even though it's self signed:
            >>> response = requests.get("https://cyborg", verify=cert_path)

        Args:
            path (:obj:`str` or :obj:`pathlib.Path`): Path to write self.pem to.

        Returns:
            (:obj:`pathlib.Path`)
        """
        return write_file(
            path=path,
            text=self.pem,
            overwrite=overwrite,
            mkparent=mkparent,
            protect=protect,
        )

    @property
    def issuer(self):
        """Get issuer parts.

        Returns:
            (:obj:`dict`)
        """
        return dict(self._cert_native["issuer"])

    @property
    def issuer_str(self):
        """Get issuer parts as string.

        Returns:
            (:obj:`str`)
        """
        return self.asn1["tbs_certificate"]["issuer"].human_friendly

    @property
    def subject(self):
        """Get subject parts.

        Returns:
            (:obj:`dict`)
        """
        return dict(self._cert_native["subject"])

    @property
    def subject_str(self):
        """Get subject parts as string.

        Returns:
            (:obj:`str`)
        """
        return self.asn1["tbs_certificate"]["subject"].human_friendly

    @property
    def subject_alt_names(self):
        """Get subject alternate names.

        Returns:
            (:obj:`list` of :obj:`str`)
        """
        try:
            return self.asn1.subject_alt_name_value.native
        except Exception:
            return []

    @property
    def subject_alt_names_str(self):
        """Get subject alternate names as CSV string.

        Returns:
            (:obj:`str`)
        """
        return ", ".join(self.subject_alt_names)

    @property
    def fingerprint_sha1(self):
        """SHA1 Fingerprint.

        Returns:
            (:obj:`str`)
        """
        return self.asn1.sha1_fingerprint

    @property
    def fingerprint_sha256(self):
        """SHA256 Fingerprint.

        Returns:
            (:obj:`str`)
        """
        return self.asn1.sha256_fingerprint

    @property
    def public_key(self):
        """Public key in hex format.

        Returns:
            (:obj:`str`)
        """
        pkn = self._public_key_native["public_key"]
        return hexify(pkn["modulus"] if isinstance(pkn, dict) else pkn)

    @property
    def public_key_str(self):
        """Public key as in hex format spaced and wrapped.

        Returns:
            (:obj:`str`)
        """
        return wrap_it(obj=space_out(obj=self.public_key, join=" "), width=60)

    @property
    def public_key_parameters(self):
        """Public key parameters, only for 'ec' certs.

        Returns:
            (:obj:`str`)
        """
        return self._public_key_native["algorithm"]["parameters"]

    @property
    def public_key_algorithm(self):
        """Algorithm of public key ('ec', 'rsa', 'dsa').

        Returns:
            (:obj:`str`)
        """
        return self._public_key_native["algorithm"]["algorithm"]

    @property
    def public_key_size(self):
        """Size of public key in bits.

        Returns:
            (:obj:`int`)
        """
        return self.x509.get_pubkey().bits()

    @property
    def public_key_exponent(self):
        """Public key exponent, only for 'rsa' certs.

        Returns:
            (:obj:`int`)
        """
        pkn = self._public_key_native["public_key"]
        return pkn["public_exponent"] if isinstance(pkn, dict) else None

    @property
    def signature(self):
        """Signature in hex format.

        Returns:
            (:obj:`str`).
        """
        return hexify(self.asn1.signature)

    @property
    def signature_str(self):
        """Signature in hex format spaced and wrapped.

        Returns:
            (:obj:`str`)
        """
        return wrap_it(obj=space_out(obj=self.signature, join=" "), width=60)

    @property
    def signature_algorithm(self):
        """Algorithm used to sign the public key certificate.

        Returns:
            (:obj:`str`)
        """
        return self._cert_native["signature"]["algorithm"]

    @property
    def x509_version(self):
        """The x509 version this certificate is using.

        Returns:
            (:obj:`str`)
        """
        return self._cert_native["version"]

    @property
    def serial_number(self):
        """The serial number for this certificate.

        Returns:
            (:obj:`str` or :obj:`int`): int if algorithm is 'ec', or hex str.
        """
        ret = self._cert_native["serial_number"]
        return hexify(ret) if not self._is_ec else ret

    @property
    def serial_number_str(self):
        """The serial number for this certificate.

        Returns:
            (:obj:`str` or :obj:`int`): int if algorithm is 'ec', or spaced and wrapped hex str.
        """
        if self._is_ec:
            return self.serial_number
        return wrap_it(obj=space_out(obj=self.serial_number, join=" "), width=60)

    @property
    def is_expired(self):
        """Determine if this certificate is expired.

        Returns:
            (:obj:`bool`)
        """
        return self.x509.has_expired()

    @property
    def is_self_signed(self):
        """Determine if this certificate is self_sign.

        Returns:
            (:obj:`str`): ('yes', 'maybe', or 'no').
        """
        return self.asn1.self_signed

    @property
    def is_self_issued(self):
        """Determine if this certificate is self issued.

        Returns:
            (:obj:`bool`)
        """
        return self.asn1.self_issued

    @property
    def not_valid_before(self):
        """Certificate valid start date as datetime object.

        Returns:
            (:obj:`datetime.datetime`)
        """
        return self._cert_native["validity"]["not_before"]

    @property
    def not_valid_before_str(self):
        """Certificate valid start date as str.

        Returns:
            (:obj:`str`)
        """
        return "{}".format(self.not_valid_before)

    @property
    def not_valid_after(self):
        """Certificate valid end date as datetime object.

        Returns:
            (:obj:`datetime.datetime`)
        """
        return self._cert_native["validity"]["not_after"]

    @property
    def not_valid_after_str(self):
        """Certificate valid end date as str.

        Returns:
            (:obj:`str`)
        """
        return "{}".format(self.not_valid_after)

    @property
    def extensions(self):
        """Certificate extensions as dict.

        Notes:

            Parsing the extensions was not easy. I sort of gave up at one point.
            I finally resorted to using the str() of each extension as OpenSSL returns it.

        Returns:
            (:obj:`dict`)
        """
        ret = {}
        for ext in self._extensions:
            name, obj = ext
            obj_str = self._extension_str(obj)
            ret[name] = obj_str
        return ret

    @property
    def extensions_str(self):
        """Certificate extensions as str with index, name, and value.

        Returns:
            (:obj:`str`)
        """
        ret = []
        for idx, ext in enumerate(self._extensions):
            name, obj = ext
            obj_str = self._extension_str(obj)
            m = "Extension {i}, name={name}, value={value}"
            m = m.format(i=idx + 1, name=name, value=obj_str)
            ret.append(m)
        return "\n".join(ret)

    @property
    def dump(self):
        """Dump dictionary with all attributes of self.

        Returns:
            (:obj:`dict`)
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
            (:obj:`dict`)
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
            (:obj:`str`)
        """
        return jdump(self.dump_json_friendly)

    @property
    def dump_str(self):
        """Dump a human friendly str of the all the important bits.

        Returns:
            (:obj:`str`)
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
            (:obj:`str`)
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
            (:obj:`str`)
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
            (:obj:`str`)
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

    def _extension_str(self, ext):
        """Format the string of an extension using str(extension).

        Returns:
            (:obj:`str`)
        """
        lines = [x for x in format(ext).splitlines() if x]
        j = " " if len(lines) < 5 else "\n"
        return j.join(lines)

    @property
    def _extensions(self):
        """List mapping of extension name to extension object.

        Returns:
            (:obj:`list` of :obj:`list`)
        """
        exts = [self.x509.get_extension(i) for i in range(self.x509.get_extension_count())]
        return [[utf8(e.get_short_name()), e] for e in exts]

    @property
    def _public_key_native(self):
        """Utility for easy access to the dict in self.asn1.public_key.

        Returns:
            (:obj:`dict`)
        """
        return self.asn1.public_key.native

    @property
    def _cert_native(self):
        """Utility for easy access to the dict in self.asn1.

        Returns:
            (:obj:`dict`)
        """
        return self.asn1.native["tbs_certificate"]

    @property
    def _is_ec(self):
        """Determine if this certificates public key algorithm is Elliptic Curve ('ec').

        Returns:
            (:obj:`bool`)
        """
        return self.public_key_algorithm == "ec"


class CertChainStore(object):
    """Make SSL cert chains and their attributes generally more accessible.

    This is really just a list container for a cert chain, which is just a list of x509 certs.
    """

    def __init__(self, x509):
        """Constructor.

        Args:
            x509 (:obj:`list` of :obj:`x509.Certificate`): List of SSL certs in x509 format.
        """
        self._x509 = x509
        self._certs = [CertStore(c) for c in x509]

    def __str__(self):
        """Show most useful information of all certs in cert chain."""
        ret = "{cls} with {num} certs:{certs}"
        ret = ret.format(cls=clsname(self), num=len(self), certs=self.dump_str_info)
        return ret

    def __repr__(self):
        """Use str() for repr()."""
        return self.__str__()

    def __getitem__(self, i):
        """Passthru to self._certs[n]."""
        return self._certs[i]

    def __len__(self):
        """Passthru to len(self._certs)."""
        return len(self._certs)

    def append(self, value):
        """Passthru to self._certs.append() with automatic conversion for PEM or X509.

        Args:
            value (:obj:`str` or :obj:`x509.Certificate` or :obj:`CertStore`)
        """
        if isinstance(value, six.string_types):
            self._certs.append(CertStore.new_from_pem(value))
        elif isinstance(value, asn1crypto.x509.Certificate):
            self._certs.append(CertStore(value))
        elif isinstance(value, CertStore):
            self._certs.append(value)

    @classmethod
    def new_from_host_socket(cls, host, port=443, sslv2=False):
        """Make instance of this cls using socket module to get the cert chain.

        Examples:

            >>> cert_chain = cert_human.CertChainStore.new_from_host_socket("cyborg")
            >>> print(cert_chain)

        Args:
            host (:obj:`str`): hostname to connect to.
            port (:obj:`str`, optional): port to connect to on host. Defaults to: 443.
            sslv2 (:obj:`bool`, optional): Allow SSL v2 connections. Defaults to: False.

        Returns:
            (:obj:`CertChainStore`)
        """
        with ssl_socket(host=host, port=port, sslv2=sslv2) as ssl_sock:
            return cls(ssl_sock.get_peer_cert_chain())

    @classmethod
    def new_from_host_requests(cls, host, port=443, verify=False, timeout=5):
        """Make instance of this cls using requests module to get the cert chain.

        Examples:

            >>> cert_chain = cert_human.CertChainStore.new_from_host_requests("cyborg")
            >>> print(cert_chain)

        Args:
            host (:obj:`str`): hostname to connect to.
            port (:obj:`str`, optional): port to connect to on host. Defaults to: 443.
            timeout (:obj:`str`, optional):
                Timeout in seconds for host connect/response. Defaults to: 5.

        Returns:
            (:obj:`CertChainStore`)
        """
        response = get_response(host=host, port=port, verify=verify, timeout=timeout)
        return cls(response.raw.peer_cert_chain)

    @classmethod
    def new_from_response_obj(cls, response):
        """Make instance of this cls using a requests.Response.raw object.

        Examples:

            >>> cert.enable_urllib3_patch()
            >>> response = requests.get("https://cyborg", verify=False)
            >>> cert_chain = cert_human.CertChainStore.new_from_response_obj(response)
            >>> print(cert_chain)

        Notes:
            This relies on the fact that :func:`enable_urllib3_patch` has been used to add the SSL
            attributes to the :obj:`requests.Response`.raw object.

        Args:
            response (:obj:`requests.Response`): response object to get raw.peer_cert_chain from

        Returns:
            (:obj:`CertChainStore`)
        """
        x509 = response.raw.peer_cert_chain
        return cls(x509)

    @classmethod
    def new_from_pem_str(cls, pem):
        """Make instance of this cls from a string containing multiple PEM certs.

        Args:
            pem (:obj:`str`): PEM string with multiple pems to convert to x509.

        Returns:
            (:obj:`CertChainStore`)
        """
        return cls(pems_to_x509(pem))

    @property
    def certs(self):
        """Expose self._certs list container."""
        return self._certs

    @property
    def pem(self):
        """Return all of the joined PEM strings for each cert in self.

        Returns:
            (:obj:`str`): all PEM strings joined.
        """
        return "".join([c.pem for c in self])

    @property
    def x509(self):
        """Return the original x509 cert chain.

        Returns:
            (:obj:`list` of :obj:`x509.Certificate`)
        """
        return self._x509

    @property
    def der(self):
        """Return the DER bytes version of the original x509 cert object.

        Returns:
            (:obj:`list` of :obj:`bytes`)
        """
        return [c.der for c in self]

    @property
    def asn1(self):
        """Return the ASN1 version of the original x509 cert object.

        Returns:
            (:obj:`list` of :obj:`x509.Certificate`)
        """
        return [c.asn1 for c in self]

    def to_disk(self, path, overwrite=False, mkparent=True, protect=True):
        """Write self.pem to disk.

        Args:
            path (:obj:`str` or :obj:`pathlib.Path`): Path to write self.pem to.

        Returns:
            (:obj:`pathlib.Path`)
        """
        return write_file(
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
            (:obj:`list` of :obj:`dict`)
        """
        return [o.dump_json_friendly for o in self]

    @property
    def dump_json(self):
        """Dump JSON string with all attributes of each cert in self that are JSON friendly.

        Returns:
            (:obj:`str`)
        """
        return jdump(self.dump_json_friendly)

    @property
    def dump(self):
        """Dump dictionary with all attributes of each cert in self.

        Returns:
            (:obj:`list` of :obj:`dict`)
        """
        return [o.dump for o in self]

    @property
    def dump_str(self):
        """Dump a human friendly str of the all the important bits for each cert in self.

        Returns:
            (:obj:`str`)
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
            (:obj:`str`)
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
            (:obj:`str`)
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
            (:obj:`str`)
        """
        tmpl = "{c} #{i}\n{s}".format
        items = [
            tmpl(c=clsname(c), i=i + 1, s=indent(c.dump_str_exts))
            for i, c in enumerate(self._certs)
        ]
        return "\n  " + "\n  ".join(items)


def utf8(obj):
    """Decode wrapper.

    Args:
        obj (:obj:`str`): The text to decode to utf-8.

    Returns:
        (:obj:`str`)
    """
    try:
        return obj.decode("utf-8")
    except Exception:
        return obj


def indent(txt, n=4):
    """Text indenter.

    Args:
        txt (:obj:`str`): The text to indent.
        n (:obj:`str`, optional): Number of spaces to indent txt. Defaults to: 4.

    Returns:
        (:obj:`str`)
    """
    txt = "{}".format(txt)
    return "\n".join(["{s}{line}".format(s=" " * n, line=l) for l in txt.splitlines()])


def clsname(obj):
    """Get objects class name.

    Args:
        obj (:obj:`object`): The object or class to get the name of.

    Returns:
        (:obj:`str`)
    """
    if inspect.isclass(obj) or obj.__module__ in set(['builtins', '__builtin__']):
        return obj.__name__
    return obj.__class__.__name__


def jdump(obj, indent=2):
    """Dump obj to JSON str.

    Args:
        obj (:obj:`dict` or :obj:`list`): The object to dump to JSON.
        indent (:obj:`str`, optional): Indent to use in JSON output. Defaults to: 2.

    Returns:
        (:obj:`str`)
    """
    return json.dumps(obj, indent=indent)


def hexify(obj):
    """Convert bytes, int, or str to hex.

    Args:
        obj (:obj:`str` or :obj:`int` or :obj:`bytes`): The object to convert into hex.

    Returns:
        (:obj:`str`)
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
        obj (:obj:`str`): The string to split.
        join (:obj:`str`, optional):
            The string to use when rejoining the spaced out values. Defaults to: " ".
        every (:obj:`str`, optional):
            The number of characters to split on. Defaults to: 2.
        zerofill (:obj:`bool`, optional): Zero fill the string before splitting if the string
            length is not even. This gets around oddly sized hex strings. Defaults to: True.

    Returns:
        (:obj:`str`)
    """
    if len(obj) % 2 and zerofill:
        obj = obj.zfill(len(obj) + 1)
    if join is not None:
        obj = join.join(obj[i:i+every] for i in range(0, len(obj), every))
    return obj


def wrap_it(obj, width=60):
    """Wrap str obj to width.

    Args:
        obj (:obj:`str`): The str object to wrap.
        width (:obj:`str`, optional): The width to wrap obj at. Defaults to: 60.

    Returns:
        (:obj:`str`)
    """
    return "\n".join(textwrap.wrap(obj, width)) if width else obj


def write_file(path, text, overwrite=False, mkparent=True, protect=True):
    """Write text to path.

    Args:
        path (:obj:`str` or :obj:`pathlib.Path`): The path to write text to.
        text (:obj:`str`): The text to write to path.
        overwrite (:obj:`bool`, optional): If path exists, overwrite it. Defaults to: False.
        mkparent (:obj:`bool`, optional):
            If parent directory of path does not exist, create it. Defaults to: True.
        protect (:obj:`bool`, optional):
            Set permissions of file to 0600 and parent directory to 0700.

    Raises:
        (:obj:`CertHumanError`):
            path exists and overwrite is false, or parent directory not exist and mkparent is False.

    Returns:
        (:obj:`pathlib.Path`)
    """
    path = pathlib.Path(path).expanduser().absolute()
    parent = path.parent

    if path.is_file() and overwrite is False:
        error = "File '{path}' already exists and overwrite is False"
        error = error.format(path=path)
        raise CertHumanError(error)

    if not parent.is_dir():
        if mkparent:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            error = "Directory '{path}' does not exist and mkparent is False"
            error = error.format(path=parent)
            raise CertHumanError(error)

    path.write_text(text)

    if protect:
        try:
            parent.chmod(0o700)
            path.chmod(0o600)
        except Exception:
            pass
    return path


def find_certs(txt):
    """Split text with multiple certificates into a list of certificates.

    Args:
        txt (:obj:`str`): the text to find certificates in.

    Returns:
        (:obj:`list` of :obj:`str`)
    """
    pattern = r"-----BEGIN.*?-----.*?-----END.*?-----"
    pattern = re.compile(pattern, re.DOTALL)
    return pattern.findall(txt)


def pem_to_x509(pem):
    """Convert from PEM to x509.

    Args:
        pem (:obj:`str`): PEM string to convert to x509 certificate object.

    Returns:
        (:obj:`OpenSSL.crypto.X509`)
    """
    return pyopenssl.OpenSSL.crypto.load_certificate(PEM_TYPE, pem)


def pems_to_x509(pem):
    """Convert from PEM with multiple certs to x509.

    Args:
        pem (:obj:`str`): PEM string with multiple certificates to convert
            to x509 certificate object.

    Returns:
        (:obj:`list` of :obj:`OpenSSL.crypto.X509`)
    """
    return [pem_to_x509(pem) for pem in find_certs(txt=pem)]


def x509_to_pem(x509):
    """Convert from x509 to PEM.

    Args:
        x509 (:obj:`OpenSSL.crypto.X509`): x509 certificate object to convert to PEM.

    Returns:
        (:obj:`str`)
    """
    pem = pyopenssl.OpenSSL.crypto.dump_certificate(PEM_TYPE, x509)
    return utf8(pem)


def x509_to_der(x509):
    """Convert from x509 to DER.

    Args:
        x509 (:obj:`OpenSSL.crypto.X509`): x509 certificate object to convert to DER.

    Returns:
        (:obj:`bytes`)
    """
    return pyopenssl.OpenSSL.crypto.dump_certificate(ASN1_TYPE, x509)


def x509_to_asn1(x509):
    """Convert from x509 to asn1crypto.x509.Certificate.

    Args:
        x509 (:obj:`OpenSSL.crypto.X509`): x509 object to convert to :obj:`x509.Certificate`.

    Returns:
        (x509.Certificate)
    """
    return der_to_asn1(x509_to_der(x509))


def der_to_asn1(der):
    """Convert from DER to asn1crypto.x509.Certificate.

    Args:
        der (:obj:`bytes`): DER bytes string to convert to :obj:`x509.Certificate`.

    Returns:
        (x509.Certificate)
    """
    return asn1crypto.x509.Certificate.load(der)


class CertHumanError(Exception):
    """Exception wrapper."""
    pass
