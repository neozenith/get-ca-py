#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tool to build HTML documentation using Sphinx to a local directory."""
from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import shutil
import sys

from sphinx.application import Sphinx

try:
    import pathlib
except Exception:
    import pathlib2 as pathlib


THIS_FILE = pathlib.Path(__file__).absolute()
THIS_PATH = THIS_FILE.parent
TOOL_PATH = THIS_PATH.parent
OUTPUT_PATH = THIS_PATH / "_build"  # "~/{p}/docs".format(p=TOOL_PATH.name)

if TOOL_PATH not in sys.path:
    sys.path.insert(0, format(TOOL_PATH))


if __name__ == "__main__":

    def cli(argv):
        fmt = argparse.ArgumentDefaultsHelpFormatter
        parser = argparse.ArgumentParser(description=__doc__, formatter_class=fmt, add_help=True)
        parser.add_argument(
            "--output_path",
            action="store",
            required=False,
            default=format(OUTPUT_PATH),
            help="Path to use when building docs",
        )
        parser.add_argument(
            "--builder",
            action="store",
            required=False,
            default="html",
            help="Sphinx builder to use",
            choices=["html", "coverage", "linkcheck"],
        )
        parser.add_argument(
            "--clean",
            action="store_true",
            required=False,
            default=False,
            help="If --output_path exists, remove it before building"
        )
        parser.add_argument(
            "--all",
            action="store_true",
            required=False,
            default=False,
            help="Re-build all files, not just changed files",
        )
        parser.add_argument(
            "--nitpicky",
            action="store_true",
            required=False,
            default=False,
            help="Have sphinx warn about all missing references",
        )
        parser.add_argument(
            "--verbose",
            action="store",
            required=False,
            default=0,
            help="Verbosity level of sphinx",
            type=int,
        )
        parser.add_argument(
            "--warnings",
            action="store_true",
            required=False,
            default=False,
            help="Have sphinx keep warnings in output",
        )
        return parser.parse_args(argv)

    cli_args = cli(argv=sys.argv[1:])

    output_path = pathlib.Path(cli_args.output_path).expanduser().absolute()

    if cli_args.clean and output_path.exists():
        m = "Removing pre-existing --output_path '{p}'"
        m = m.format(p=format(output_path))
        print(m)
        shutil.rmtree(output_path)

    confoverrides = {}

    if cli_args.nitpicky:
        confoverrides["nitpicky"] = True

    if cli_args.warnings:
        confoverrides["keep_warnings"] = True

    sargs = {}
    sargs["srcdir"] = format(THIS_PATH)
    sargs["confdir"] = format(THIS_PATH)
    sargs["outdir"] = format(output_path)
    sargs["doctreedir"] = format(output_path / ".doctrees")
    sargs["buildername"] = cli_args.builder
    sargs["confoverrides"] = confoverrides
    sargs["status"] = sys.stdout  # or None
    sargs["warning"] = sys.stdout  # or None
    sargs["freshenv"] = False
    sargs["warningiserror"] = False
    sargs["tags"] = None
    sargs["verbosity"] = cli_args.verbose
    sargs["parallel"] = 0
    app = Sphinx(**sargs)

    bargs = {}
    bargs["force_all"] = cli_args.all
    bargs["filenames"] = None
    app.build(**bargs)
