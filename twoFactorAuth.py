#!/usr/bin/env python

"""
    Generate two-factor authentication (2FA) tokens by
    implement the Time-Based One-Time Password (TOTP) algorithm
    and HMAC-Based One-Time Password (HOTP) Algorithm.

    Based on http://tools.ietf.org/html/rfc4226
             http://tools.ietf.org/html/rfc6238
"""

import base64
import hashlib
import hmac
import struct
import time

"""
    Shared secret used: h3nr2nsfytkmhnxz
"""


def HOTP(secret, counter, digits=6, digestmod=hashlib.sha1):
    """
        HOTP generate one-time password values based on HMAC.

        It accept a secret key (K) and a counter value (C).
        Optional digit parameter are to control the response length.

        Returns the OATH integer code with {digits} length

        :param {secret}   : [String] base32-encoded string act as secret key.
        :param {counter}  : [Integer] counter for getting different OATH token.
        :param {digits}   : [Integer] response length parameter.
        :param {digestmod}: [Function] method for generating digest
                            default (hashlib.sha1) used in HOTP algorithm.
    """

    try:
        key = base64.b32decode(secret, casefold=True)
    except(TypeError):
        raise TypeError('Invalid secret')

    # convert time into bytes with big-endian byte order
    counter_bytes = struct.pack(b'>Q', counter)

    hmac_digest_maker = hmac.new(key=key,
                                 msg=counter_bytes,
                                 digestmod=hashlib.sha1)
    hmac_digest = hmac_digest_maker.digest()

    return truncate(hmac_digest, digits=digits)


def TOPT(secret='h3nr2nsfytkmhnxz',
         clock=None,
         window=30,
         digits=6,
         digestmod=hashlib.sha1):
    """
        TOPT is time-based variant of HOTP.

        It accept only a secret key (K), since it is time-based the
        counter is generated from time and window. Optional parameter
        are used to control response length.

        Returns the OATH integer code with {digits} length.

        :param {secret}   : [String] base32-encoded string act as secret key.
        :param {clock}    : [Integer] clock used in generating counter value.
        :param {window}   : [Integer] time step in seconds.
        :param {digits}   : [Integer] response length parameter.
        :param {digestmod}: [Function] method for generating digest
                            default (hashlib.sha1) used in HOTP algorithm.
    """

    if clock is None:
        clock = time.time()
    counter = int(clock) // window

    return HOTP(secret, counter, digits=digits, digestmod=digestmod)


def truncate(hmac_digest, digits=6):
    """
        Truncate represents the function that converts an HMAC
        value into an HOTP value as defined in Section 5.3.

        http://tools.ietf.org/html/rfc4226#section-5.3

        :param {hmac_digest}: OATH code in 20-Byte string format.
        :param {digits}     : [Integer] response length parameter.
    """

    # convert the text into it's character code
    char_code = ord(hmac_digest[-1])

    # Convert the char code into base 16
    offset = char_code & 15

    # unpacking the bytes array into usable unsigned int variable
    oathcode = struct.unpack(b'>I', hmac_digest[offset:(offset + 4)])

    """
        Base 32 conversion

        Number info: 0x7fffffff

        Decimal       : 2147483647
        Binary        : 1111111111111111111111111111111
        Hexadecimal   : 0x7fffffff
        Dotted decimal: 127.255.255.255
    """

    token = oathcode[0] & 0x7fffffff

    # generate the token of {digits} response length
    print token % (10 ** digits)


if __name__ == '__main__':
    TOPT()
