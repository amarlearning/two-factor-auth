# -*- coding: utf-8 -*- 

#!/usr/bin/env python

"""
	Shared secret used: 4twol5ttsikd4apz
"""
import struct
import re
import sys
import base64
import calendar, time
import hashlib
from clint.textui import colored, puts

# class TwoFatorAuth():
# 	""" 
# 		docstring for TwoFatorAuth : Generate two-factor authentication (2FA) tokens by 
# 		implement the Time-Based One-Time Password (TOTP) algorithm.

# 	"""

# 	def __init__(self):
# 		"""
# 			Constructor Fucntion: Taking shared secret code as argument from system

# 		"""		
# 		self.sSecret = ''.join(sys.argv[1:])

# 	def base32decode(self):
# 		""" 
# 			Constructor Fucntion: Taking shared secret code as argument from system

# 		"""
# 		self.sSecret = re.sub(re.compile(r'\s+'), '', self.sSecret)
# 		self.sSecret = self.sSecret.upper()		
# 		self.sSecret = base64.b32decode(self.sSecret)
# 		print self.sSecret

# if __name__ == '__main__':
# 	TwoFatorAuth().base32decode()


def main():
	secretCode = ''.join(sys.argv[1:])
	secretCode = base64.b32decode(re.sub(re.compile(r'\s+'), '', secretCode).upper())
	inputTime = calendar.timegm(time.gmtime()) / 30
	b = struct.pack(">i", inputTime)
	hashString = hashlib.sha1(secretCode + hashlib.sha1(secretCode + b).hexdigest()).hexdigest()
	print hashString
	print calendar.timegm(time.gmtime()) % 30

	LAST_BYTE = hashString[-1]
	hashString = hashString[int(LAST_BYTE): int(LAST_BYTE)+4]

	print int(hashString)

if __name__ == '__main__':
	main()