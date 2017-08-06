#!/usr/bin/env python

"""
	Shared secret used: ibfz25pke5x2zocm
"""

import struct
import sys
import time

class twoFactorAuth():
	""" 
		Generate two-factor authentication (2FA) tokens by 
		implement the Time-Based One-Time Password (TOTP) algorithm
		and HMAC-Based One-Time Password (HOTP) Algorithm.

	"""

	def __init__(self):
		"""
			Constructor Fucntion: Taking shared secret code as argument from system

		"""		
		self.sSecret = ''.join(sys.argv[1:])
		print self.sSecret


if __name__ == '__main__':