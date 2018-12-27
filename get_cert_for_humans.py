#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""SSL Certificates for humans."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import asn1crypto.x509
import binascii
import json
import requests
import re
import ssl
import warnings
import with_cert_patch

from urllib3.contrib import pyopenssl

PEM_TYPE = pyopenssl.OpenSSL.crypto.FILETYPE_PEM
ASN1_TYPE = pyopenssl.OpenSSL.crypto.FILETYPE_ASN1


def get_response(host, port=443, verify=False, timeout=5, **kwargs):
    """Get a requests.Response object with cert attributes.

    Notes:
        By default verify is off, supply path to cert file to verify host against cert file.
        Warnings get silenced when verify is off, since we're probably using this to get a cert.
        Can supply host as: 'https://host:port', 'host:port', or 'host'
    """
    with_cert_patch.check_with_cert()

    if "://" not in host:
        url = "https://{host}".format(host=host)
    if not re.search(r":\d+", host):
        url = "{url}:{port}".format(url=url, port=port)

    if not verify:
        with warnings.catch_warnings():
            category = requests.packages.urllib3.exceptions.HTTPWarning
            warnings.simplefilter(action="ignore", category=category)
            response = requests.get(url, verify=verify, timeout=timeout)
    else:
        response = requests.get(url, verify=verify, timeout=timeout)
    return response


def utf8(t):
    """Decode wrapper."""
    try:
        return t.decode("utf-8")
    except Exception:
        return t


def indent(t, n=4):
    """Text indenter."""
    return "\n".join(["{s}{line}".format(s=" " * n, line=l) for l in t.splitlines()])


def clsname(o):
    """Get objects class name."""
    return o.__class__.__name__


def jdump(o, i=2):
    """Dump obj to json str."""
    return json.dumps(o, indent=i)


def hexify(o):
    # magic dance due to python2/3 differences that i dont care to dive into
    try:
        return o.hex()
    except Exception:
        pass
    try:
        return binascii.hexlify(o)
    except Exception:
        pass
    try:
        return format(o, 'X')
    except Exception:
        pass
    try:
        return "{:#x}".format(o)
    except Exception:
        pass
    return o


def hexify_spaced(o, j=" ", e=2):
    return spaced(hexify(o), j=j, e=e).upper()


def spaced(o, j=" ", e=2):
    return j.join(o[i:i+e] for i in range(0, len(o), e))


class CertX509Store(object):
    """Make x509 certs and their attributes generally more accessible."""

    def __init__(self, x509):
        self.x509 = x509
        self.pem = self.x509_to_pem(x509)
        self.der = self.x509_to_der(x509)
        self.asn1 = self.x509_to_asn1(x509)

    def __str__(self):
        ret = "{cls}:\n{j}"
        ret = ret.format(cls=clsname(self), j=indent(self.dump_json_human))
        return ret

    def __repr__(self):
        return self.__str__()

    @property
    def dump_json_human(self):
        """Dump dictionary of self to json str."""
        return jdump(self.dump_dict_human)

    @property
    def dump_json(self):
        """Dump dictionary of self to json str."""
        return jdump(self.dump_dict)

    @property
    def dump_dict_human(self):
        """Dump dictionary with most useful attributes of self in mostly human readable form."""
        ret = dict(
            issuer=self.issuer_human,
            subject=self.subject_human,
            subject_alt_names=self.subject_alt_names_human,
            fingerprints=self.fingerprints,
            public_key=self.public_key,
            signature=self.signature,
            version=self.version,
            serial_number=self.serial_number,
            validity=self.validity_human,
            extensions=self.extensions_x509_dict,
        )
        return ret

    @property
    def dump_dict(self):
        """Dump dictionary with most useful attributes of self."""
        ret = dict(
            issuer=self.issuer,
            subject=self.subject,
            subject_alt_names=self.subject_alt_names,
            fingerprints=self.fingerprints,
            public_key=self.public_key,
            signature=self.signature,
            version=self.version,
            serial_number=self.serial_number,
            validity=self.validity,
            extensions=self.extensions_x509_dict,
        )
        return ret

    @classmethod
    def new_from_host_ssl(cls, host, port=443):
        """Spawn an instance of this cls using ssl to get the cert."""
        return cls(cls.pem_to_x509(cls.get_pem_from_host_ssl(host, port)))

    @classmethod
    def new_from_host_pyopenssl(cls, host, port=443):
        """Spawn an instance of this cls using pyopenssl to get the cert."""
        return cls(cls.get_x509_using_pyopenssl((host, port)))

    @classmethod
    def new_from_host_requests(cls, host, port=443, verify=False):
        """Spawn an instance of this cls using requests to get the cert."""
        return cls(cls.get_x509_using_requests(host=host, port=port, verify=verify))

    @classmethod
    def new_from_pem_str(cls, pem):
        """Spawn an instance of this cls from a pem string."""
        return cls(cls.pem_to_x509(pem))

    @classmethod
    def new_from_response(cls, response):
        """Spawn an instance of this cls from raw.peer_cert on a requests.Response object."""
        with_cert_patch.check_with_cert()
        return cls(response.raw.peer_cert)

    @classmethod
    def get_pem_using_ssl(cls, host, port=443):
        return ssl.get_server_certificate((host, int(port)))

    @classmethod
    def get_x509_using_pyopenssl(cls, host, port=443):
        return pyopenssl.OpenSSL.crypto.get_server_certificate((host, port))

    @classmethod
    def get_x509_using_requests(cls, host, port=443, verify=False):
        with_cert_patch.check_with_cert()
        return get_response(host=host, port=port, verify=verify).raw.peer_cert

    @classmethod
    def pem_to_x509(cls, pem):
        return pyopenssl.OpenSSL.crypto.load_certificate(PEM_TYPE, pem)

    @classmethod
    def x509_to_pem(cls, x509):
        """Convert from x509 to pem format."""
        ret = pyopenssl.OpenSSL.crypto.dump_certificate(PEM_TYPE, x509)
        ret = utf8(ret)
        return ret

    @classmethod
    def x509_to_der(cls, x509):
        """Convert from x509 to ASN1 format."""
        ret = pyopenssl.OpenSSL.crypto.dump_certificate(ASN1_TYPE, x509)
        return ret

    @classmethod
    def der_to_asn1(cls, der):
        """Convert from der to asn1crypto.x509.Certificate()."""
        return asn1crypto.x509.Certificate.load(der)

    @classmethod
    def x509_to_asn1(cls, x509):
        """Convert from x509 to asn1crypto.x509.Certificate()."""
        return cls.der_to_asn1(cls.x509_to_der(x509))

    def pem_to_disk(self, path):
        """Write self.pem to disk."""
        with open(path, "w") as fh:
            fh.write(self.pem)

    @property
    def issuer(self):
        """Get issuer parts in dict form."""
        return dict(self.asn1.native["tbs_certificate"]["issuer"])

    @property
    def issuer_human(self):
        """Get issuer parts in human form."""
        return self.asn1["tbs_certificate"]["issuer"].human_friendly

    @property
    def subject(self):
        """Get subject parts in dict form."""
        return dict(self.asn1.native["tbs_certificate"]["subject"])

    @property
    def subject_human(self):
        """Get subject parts in human form."""
        return self.asn1["tbs_certificate"]["subject"].human_friendly

    @property
    def subject_alt_names(self):
        try:
            return self.asn1.subject_alt_name_value.native
        except Exception:
            return []

    @property
    def subject_alt_names_human(self):
        return ", ".join(self.subject_alt_names)

    @property
    def fingerprints(self):
        ret = dict(
            sha1=self.asn1.sha1_fingerprint,
            sha256=self.asn1.sha256_fingerprint,
        )
        return ret

    @property
    def public_key(self):
        ret = dict(
            algorithm=self.asn1.public_key.native["algorithm"]["algorithm"],
            parameters=self.asn1.public_key.native["algorithm"]["parameters"],
            key_size=self.x509.get_pubkey().bits(),
        )
        if isinstance(self.asn1.public_key.native["public_key"], dict):
            ret.update(dict(
                key=hexify_spaced(self.asn1.public_key.native["public_key"]["modulus"]),
                exponent=self.asn1.public_key.native["public_key"]["public_exponent"],
            ))
        else:
            ret.update(dict(
                key=hexify_spaced(self.asn1.public_key.native["public_key"]),
                exponent=None,
            ))
        return ret

    @property
    def signature(self):
        ret = dict(
            algorithm=self.asn1.native["tbs_certificate"]["signature"]["algorithm"],
            algo=self.asn1.signature_algo,
            value=hexify_spaced(self.asn1.signature),
        )
        return ret

    @property
    def version(self):
        return self.asn1.native["tbs_certificate"]["version"]

    @property
    def serial_number(self):
        sn = self.asn1.native["tbs_certificate"]["serial_number"]
        return {"hex": hexify(sn), "int": sn}

    @property
    def validity(self):
        ret = dict(
            not_valid_before=self.asn1.native["tbs_certificate"]["validity"]["not_before"],
            not_valid_after=self.asn1.native["tbs_certificate"]["validity"]["not_after"],
            is_expired=self.x509.has_expired(),
            is_self_signed=self.asn1.self_signed,
            is_self_issued=self.asn1.self_issued,
        )
        return ret

    @property
    def validity_human(self):
        ret = dict(
            not_valid_before=format(self.asn1.native["tbs_certificate"]["validity"]["not_before"]),
            not_valid_after=format(self.asn1.native["tbs_certificate"]["validity"]["not_after"]),
            is_expired=self.x509.has_expired(),
            is_self_signed=self.asn1.self_signed,
            is_self_issued=self.asn1.self_issued,
        )
        return ret

    @property
    def extensions_x509_str(self):
        ret = []
        for idx, ext in enumerate(self._extensions_x509):
            name, obj = ext
            obj_str = self._extension_str(obj)
            m = "Extension {i}, name={name}, value={value}"
            m = m.format(i=idx + 1, name=name, value=obj_str)
            ret.append(m)
        return "\n".join(ret)

    def _extension_str(self, ext):
        lines = [x for x in format(ext).splitlines() if x]
        j = " " if len(lines) < 5 else "\n"
        return j.join(lines)

    @property
    def extensions_x509_dict(self):
        ret = {}
        for ext in self._extensions_x509:
            name, obj = ext
            obj_str = self._extension_str(obj)
            ret[name] = obj_str
        return ret

    @property
    def _extensions_x509(self):
        exts = [self.x509.get_extension(i) for i in range(self.x509.get_extension_count())]
        return [[utf8(e.get_short_name()), e] for e in exts]


class CertX509ChainStore(object):

    def __init__(self, cert_chain):
        self._x509 = cert_chain
        self.certs = [CertX509Store(c) for c in cert_chain]

    def __str__(self):
        ret = "{cls} with {num} certs:{certs}"
        j = "\n  "
        certs = j + j.join("#{i} {c}".format(i=i + 1, c=c) for i, c in enumerate(self.certs))
        ret = ret.format(cls=clsname(self), num=len(self), certs=certs)
        return ret

    def __repr__(self):
        return self.__str__()

    def __getitem__(self, i):
        return self.certs[i]

    def __len__(self):
        return len(self.certs)

    @property
    def dump_json(self):
        return jdump([o.dump_dict for o in self])

    @classmethod
    def get_x509_using_requests(cls, host, port=443, verify=False):
        with_cert_patch.check_with_cert()
        return get_response(host=host, port=port, verify=verify).raw.peer_cert_chain

    @classmethod
    def new_from_host_requests(cls, host, port=443, verify=False):
        """Spawn an instance of this cls using requests to get the cert_chain."""
        return cls(cls.get_x509_using_requests(host=host, port=port, verify=verify))

    @classmethod
    def new_from_response(cls, response):
        """Spawn an instance of this cls from raw.peer_cert on a requests.Response object."""
        with_cert_patch.check_with_cert()
        return cls(response.raw.peer_cert_chain)


if __name__ == "__main__":
    import sys
    import argparse

    def cli(args):
        parser = argparse.ArgumentParser(
            description="Request a URL and get the server cert and server cert chain",
        )
        parser.add_argument(
            "host",
            metavar="HOST",
            action="store",
            type=str,
            help="Host to get cert and cert chain from",
        )
        parser.add_argument(
            "--port",
            default=443,
            action="store",
            required=False,
            type=int,
            help="Port on host to connect to",
        )
        parser.add_argument(
            "--timeout",
            default=5,
            action="store",
            required=False,
            type=int,
            help="Timeout for connect",
        )
        parser.add_argument(
            "--verify",
            dest="verify",
            action="store",
            default=False,
            required=False,
            help="Use this cert when connecting to --url",
        )
        parser.add_argument(
            "--write_path",
            dest="write_path",
            action="store",
            default="",
            required=False,
            help="Write server certificate to this file",
        )
        return parser.parse_args(args)

    cli_args = cli(sys.argv[1:])

    with_cert_patch.enable_with_cert()
    response = get_response(**vars(cli_args))
    cert = CertX509Store.new_from_response(response)

    if cli_args.write_path:
        cert.pem_to_disk(cli_args.write_path)
        print("** Wrote cert in pem format to: '{}'".format(cli_args.write_path))
    else:
        print(cert)
    cert_chain = CertX509ChainStore.new_from_response(response)
