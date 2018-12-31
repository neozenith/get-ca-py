#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Command line interface to request a URL and get the server cert or cert chain."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import cert_human
import sys


if __name__ == "__main__":

    def cli(argv):
        fmt = argparse.ArgumentDefaultsHelpFormatter
        parser = argparse.ArgumentParser(description=__doc__, formatter_class=fmt)
        parser.add_argument(
            "host",
            metavar="HOST",
            action="store",
            type=str,
            help="Host to get cert or cert chain from",
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
            "--method",
            dest="method",
            action="store",
            default="requests",
            required=False,
            choices=["requests", "socket"],
            help="Use requests.get a SSL socket to get cert or cert chain.",
        )
        parser.add_argument(
            "--chain",
            dest="chain",
            action="store_true",
            default=False,
            required=False,
            help="Print/write the cert chain instead of the cert.",
        )
        parser.add_argument(
            "--print_mode",
            dest="print_mode",
            action="store",
            default="info",
            required=False,
            choices=["info", "key", "extensions", "all"],
            help="When no --write specified, print this type of information for the cert."
        )
        parser.add_argument(
            "--write",
            dest="write",
            action="store",
            default="",
            required=False,
            help="File to write cert/cert chain to",
        )
        parser.add_argument(
            "--overwrite",
            dest="overwrite",
            action="store_true",
            default=False,
            required=False,
            help="When writing to --write and file exists, overwrite.",
        )
        parser.add_argument(
            "--verify",
            dest="verify",
            action="store",
            default="",
            required=False,
            help="PEM file to verify host, empty will disable verify, for --method requests.",
        )
        return parser.parse_args(argv)

    cli_args = cli(argv=sys.argv[1:])

    if cli_args.chain:
        store_cls = cert_human.CertChainStore
        store_target = "cert chain"
    else:
        store_cls = cert_human.CertStore
        store_target = "cert"

    if cli_args.method == "requests":
        verify = False if not cli_args.verify else cli_args.verify
        try:
            store_obj = store_cls.new_from_host_requests(
                host=cli_args.host,
                port=cli_args.port,
                verify=verify,
            )
        except cert_human.requests.exceptions.SSLError as exc:
            exc = "\n  ".join([x.strip() for x in format(exc).split(":")])
            m = "SSL Validation Failed:\n  {exc}".format(exc=exc)
            print(m)
            store_obj = None
    elif cli_args.method == "socket":
        store_obj = store_cls.new_from_host_socket(
            host=cli_args.host,
            port=cli_args.port,
        )

    if store_obj:
        if cli_args.write:
            store_obj.to_disk(path=cli_args.write, overwrite=cli_args.overwrite)
            m = "** Wrote {t} in pem format to: '{p}'"
            m = m.format(t=store_target, p=cli_args.write)
            print(m)
        else:
            print_map = {
                "info": "dump_str_info",
                "key": "dump_str_key",
                "all": "dump_str",
                "extensions": "dump_str_exts",
            }
            mode_out = getattr(store_obj, print_map[cli_args.print_mode])
            print(mode_out)
