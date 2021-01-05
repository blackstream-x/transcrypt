#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""

transcrypt.py

Encrypt files using pyscrypt (https://github.com/ricmoo/pyscrypt)

Copyright (c) 2021 Rainer Schwarzbach

License: MIT, see LICENSE file

"""


import argparse
import base64
import getpass
import io
import logging
import pathlib
import sys


import pyscrypt


#
# Constants
#


MESSAGE_FORMAT = '%(levelname)-8s\u2551 %(message)s'

RETURNCODE_OK = 0
RETURNCODE_ERROR = 1


#
# Functions
#


def encrypt(arguments):
    """Encrypt the input file,
    and write the result either to the output file,
    or Ascii85-emcode to stdout
    """
    if arguments.input_file:
        source_data = arguments.input_file.read_bytes()
    else:
        source_data = sys.stdin.buffer.read()
    #
    encryption_password = getpass.getpass(
        'Enter encryption password: ').encode('utf-8')
    # Encrypt using the password
    temp_file = io.BytesIO()
    scrypt_file = pyscrypt.ScryptFile(
        temp_file,
        encryption_password,
        1024, 1, 1)
    scrypt_file.write(source_data)
    scrypt_file.finalize()
    if arguments.output_file:
        arguments.output_file.write_bytes(temp_file.getvalue())
    else:
        sys.stdout.buffer.write(
            base64.a85encode(temp_file.getvalue(), wrapcol=76))
        sys.stdout.write('\n')
    #
    return True


def decrypt(arguments):
    """Decrypt the input file"""
    if arguments.input_file:
        source_data = arguments.input_file.read_bytes()
    else:
        source_data = sys.stdin.buffer.read()
    #
    try:
        source_data = base64.a85decode(source_data)
    except ValueError:
        pass
    #
    decryption_password = getpass.getpass(
        'Enter decryption password: ').encode('utf-8')
    scrypt_file = pyscrypt.ScryptFile(
        io.BytesIO(source_data),
        password=decryption_password)
    try:
        decrypted_data = scrypt_file.read()
    except pyscrypt.file.InvalidScryptFileFormat as error:
        logging.error('Error while decrypting input: %s', error)
        return False
    #
    if arguments.output_file:
        arguments.output_file.write_bytes(decrypted_data)
    else:
        sys.stdout.buffer.write(decrypted_data)
    #
    return True


def __get_arguments():
    """Parse command line arguments"""
    argument_parser = argparse.ArgumentParser(
        description='Encrypt the input file to a scrypt file.'
        ' If the scrypt file is written to stdout, it is encoded'
        ' using Ascii85.')
    argument_parser.set_defaults(loglevel=logging.INFO)
    argument_parser.add_argument(
        '-v', '--verbose',
        action='store_const',
        const=logging.DEBUG,
        dest='loglevel',
        help='Output all messages including debug level')
    argument_parser.add_argument(
        '-q', '--quiet',
        action='store_const',
        const=logging.WARNING,
        dest='loglevel',
        help='Limit message output to warnings and errors')
    argument_parser.add_argument(
        '-d', '--decrypt',
        action='store_true',
        help='Decrypt instead of encrypting. Accepts Ascii85 encoded input.')
    argument_parser.add_argument(
        '-i', '--input-file',
        type=pathlib.Path,
        help='The input file (default: standard input).')
    argument_parser.add_argument(
        '-o', '--output-file',
        type=pathlib.Path,
        help='The output file (default: standard output).')
    return argument_parser.parse_args()


def main(arguments):
    """Main routine, calling functions from above as required.
    Returns a returncode which is used as the script's exit code.
    """
    logging.basicConfig(format=MESSAGE_FORMAT,
                        level=arguments.loglevel)
    if arguments.decrypt:
        success = decrypt(arguments)
    else:
        success = encrypt(arguments)
    #
    if success:
        return RETURNCODE_OK
    #
    return RETURNCODE_ERROR


if __name__ == '__main__':
    # Call main() with the provided command line arguments
    # and exit with its returncode
    sys.exit(main(__get_arguments()))


# vim: fileencoding=utf-8 sw=4 ts=4 sts=4 expandtab autoindent syntax=python:
