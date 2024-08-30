#!/usr/bin/python3
# zippeks - a simple zipx compressor / decompressor, with AES encryption
# Copyright (C) 2024  macmarrum (at) outlook (dot) ie
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import logging.config
import os
from getpass import getpass

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from pathlib import Path
from typing import cast

import pyzipper

UTF8 = 'UTF-8'


def get_config_dir() -> Path:
    if os.name == 'nt':
        return Path(os.environ['APPDATA'])
    elif os.name == 'posix':
        return Path(os.environ.get('XDG_CONFIG_HOME', '~/.config')).expanduser()
    else:
        raise RuntimeError(f"unknown os.name: {os.name}")


zippeks_toml_path = get_config_dir() / 'macmarrum' / 'zippeks.toml'
try:
    with zippeks_toml_path.open('rb') as fi:
        conf = tomllib.load(fi)
except FileNotFoundError:
    conf = {}

logger = logging.getLogger('macmarrum.zippeks')
if conf.get('logging'):
    logging.config.dictConfig(conf['logging'])
else:
    logging.basicConfig(level=logging.INFO)


def zipx(source: Path, archive_path: Path, kwargs: dict = None, password: bytes = None):
    should_skip_encryption = not kwargs and not password
    kwargs = kwargs or dict(
        encryption=pyzipper.WZ_AES,
        compression=pyzipper.ZIP_DEFLATED,
        compresslevel=9
    )
    if should_skip_encryption:
        kwargs.pop('encryption', None)
    with pyzipper.AESZipFile(archive_path, 'w', **kwargs) as zf:
        if password:
            zf.setpassword(password)
        _add_to_zf(source, zf)
    logger.info(f"{archive_path} {archive_path.stat().st_size}")


def _add_to_zf(source: Path, zf: pyzipper.ZipFile):
    zf.write(source)
    logger.debug(f"{source}")
    if source.is_dir():
        for p in source.iterdir():
            _add_to_zf(p, zf)


def unzipx(archive_path: Path, output_dir: Path, password: bytes = None):
    with pyzipper.AESZipFile(archive_path) as zf:
        if password:
            zf.setpassword(password)
        for member in zf.infolist():
            member = cast(pyzipper.ZipInfo, member)
            target = output_dir / member.filename
            if target.exists():
                logger.warning(f"skipping - target exists: {target}")
            else:
                zf.extract(member, output_dir)
                logger.info(f"{target} {target.stat().st_size}")


def _create(args):
    if args.archive.exists():
        logger.error(f"archive exists: {args.archive}")
        return
    password = getpass() if args.password else conf.get('password', None)
    password_b = password.encode(UTF8) if password else None
    if not password:
        logger.warning('empty or no password -> no encryption')
    zipx(args.source, args.archive, password=password_b)


def _extract(args):
    if not args.output_dir.is_dir():
        logger.error(f"output_dir is not a directory: {args.output_dir}")
        return
    password = getpass() if args.password else conf.get('password', None)
    password_b = password.encode(UTF8) if password else None
    if not password:
        logger.warning('empty or no password')
    unzipx(args.archive, args.output_dir, password=password_b)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='action', required=True)
    create_parser = subparsers.add_parser('create', aliases=['c'])
    create_parser.set_defaults(func=_create)
    create_parser.add_argument('archive', type=Path)
    create_parser.add_argument('source', type=Path)
    create_parser.add_argument('--password', '-p', action='store_true', help='prompt for a password')
    extract_parser = subparsers.add_parser('extract', aliases=['x'])
    extract_parser.set_defaults(func=_extract)
    extract_parser.add_argument('archive', type=Path)
    extract_parser.add_argument('output_dir', type=Path)
    extract_parser.add_argument('--password', '-p', action='store_true', help='prompt for a password')
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
