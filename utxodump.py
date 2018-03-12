#!/usr/bin/env python
#
# Dump utxo data from the chainstate leveldb database in CSV output format.
# Dumps all fields except the script pub key.

import argparse
import csv
import codecs
import os
import sys
from typing import Tuple

import leveldb

# Prefix for coins.
COIN = 67

# The obfuscation key.
OBFUSCATE_KEY = bytearray(b'\x0e\x00obfuscate_key')


def get_obfuscate_key(conn: leveldb.LevelDB) -> bytearray:
    """Load the obfuscation key from the database."""
    secret = conn.Get(OBFUSCATE_KEY)
    assert secret[0] == 8 and len(secret) == 9
    return secret[1:]


def decrypt(ciphertext, key):
    """Decrypt data using an XOR cipher."""
    for i, c in enumerate(ciphertext):
        ciphertext[i] = c ^ key[i % len(key)]


def decode_varint(val: bytearray) -> Tuple[int, int]:
    """Decode a varint. Returns the value and number of bytes consumed."""
    n = 0
    for i, c in enumerate(val):
        n = (n << 7) | (c & 0x7f)
        if c & 0x80:
            n += 1
        else:
            return n, i + 1


def decompress_amount(x: int) -> int:
    """Decompress an output amount."""
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    n = 0
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e:
        n *= 10
        e -= 1
    return n


def decode_key(key: bytearray) -> Tuple[str, int]:
    """Decode key to (txid, vout)."""
    assert key[0] == COIN
    txid = codecs.encode(key[1:33][::-1], 'hex').decode('utf8')
    compressed_vout = key[33:]
    vout, declen = decode_varint(compressed_vout)
    assert declen == len(compressed_vout)
    return txid, vout


def decode_val(val: bytearray) -> Tuple[int, int, int]:
    """Decode val to (height, coinbase, amount)."""
    code, consumed = decode_varint(val)
    coinbase = code & 1
    height = code >> 1
    txval, _ = decode_varint(val[consumed:])
    return height, coinbase, decompress_amount(txval)


def locate_chainstate(testnet: bool) -> str:
    """Guess where the chainstate directory is."""
    datadir = os.path.expanduser('~/.bitcoin')
    if testnet:
        datadir = os.path.join(datadir, 'testnet3')
    return os.path.join(datadir, 'chainstate')


def dump_csv(conn: leveldb.LevelDB, secret: bytearray, writer: csv.writer):
    writer.writerow(['txid', 'vout', 'height', 'coinbase', 'amount'])
    for k, v in conn.RangeIter(b'C', b'D', include_value=True):
        txid, vout = decode_key(k)
        decrypt(v, secret)
        height, coinbase, amount = decode_val(v)
        writer.writerow([txid, vout, height, coinbase, amount])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t',
        '--testnet',
        action='store_true',
        help='Testnet mode (ignored if --datadir is used)')
    parser.add_argument('-d', '--datadir', help='Path to data directory')
    args = parser.parse_args()

    conn = leveldb.LevelDB(args.datadir or locate_chainstate(args.testnet))
    secret = get_obfuscate_key(conn)

    writer = csv.writer(sys.stdout)
    try:
        dump_csv(conn, secret, writer)
    except (IOError, KeyboardInterrupt):
        pass


if __name__ == '__main__':
    main()
