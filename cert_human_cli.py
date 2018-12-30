#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""SSL Certificates for humans."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import cert_utils
import sys


if __name__ == "__main__":

    def cli(argv):
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
            help="Use this cert when connecting to --host (only for --get_mode=requests)",
        )
        parser.add_argument(
            "--get_mode",
            dest="get_mode",
            action="store",
            default="requests",
            required=False,
            choices=["requests", "ssl", "socket"],
            help=(
                "Mode to use when retrieving the cert/cert chain. 'requests' to use requests.get "
                "with cert patches applied. 'ssl' to use ssl.get_server_certificate."
            ),
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
            help="When no --write_path specified, print this type of information for the cert."
        )
        parser.add_argument(
            "--write_path",
            dest="write_path",
            action="store",
            default="",
            required=False,
            help="Write server certificate to this file",
        )
        parser.add_argument(
            "--overwrite",
            dest="overwrite",
            action="store_true",
            default=False,
            required=False,
            help="When writing to --write_path and file exists, overwrite.",
        )
        return parser.parse_args(argv)

    cli_args = cli(argv=sys.argv[1:])

    print_map = {
        "info": "dump_str_info",
        "key": "dump_str_key",
        "all": "dump_str",
        "extensions": "dump_str_exts",
    }

    response = cert_utils.get_response(
        host=cli_args.host,
        port=cli_args.port,
        verify=cli_args.verify,
        timeout=cli_args.timeout,
    )

    cert = cert_utils.CertX509Store.new_from_response_obj(response)
    cert_chain = cert_utils.CertX509ChainStore.new_from_response_obj(response)
    if cli_args.chain:
        target = cert_chain
        target_txt = "cert chain"
    else:
        target = cert
        target_txt = "cert"

    if cli_args.write_path:
        target.pem_to_disk(path=cli_args.write_path, overwrite=cli_args.overwrite)
        m = "** Wrote {t} in pem format to: '{p}'"
        m = m.format(t=target_txt, p=cli_args.write_path)
        print(m)
    else:
        mode_out = getattr(target, print_map[cli_args.print_mode])
        m = "Printing {m} for {t}:\n{o}"
        m = m.format(m=cli_args.print_mode, t=target_txt, o=mode_out)
        print(m)
