#!/usr/bin/env python

from hashlib import pbkdf2_hmac
import itertools
import string

#From: https://stackoverflow.com/questions/14945095/how-to-escape-string-for-generated-c
def cstring(s, encoding='ascii'):
	if isinstance(s, unicode):
		s = s.encode(encoding)

	result = ''
	for c in s:
		if not (32 <= ord(c) < 127) or c in ('\\', '"'):
			result += '\\%03o' % ord(c)
		else:
			result += c

	return '"' + result + '"'

intarr = lambda y: ', '.join(map(lambda x: str(ord(x)), y))

_randfd = open('/dev/urandom', 'rb')
_maketrans = string.maketrans('', '')
def randgen(l, delchrs=None):
	if delchrs is None:
		return _randfd.read(l)

	s = ''
	while len(s) < l:
		s += string.translate(_randfd.read(l - len(s)), _maketrans,
		    delchrs)
	return s

if __name__ == '__main__':
	for saltl in xrange(8, 64, 8):
		for itr in itertools.chain(xrange(100, 1000, 100), xrange(1000,
		    10000, 1000)):
			for passlen in xrange(8, 80, 8):
				salt = randgen(saltl)
				passwd = randgen(passlen, '\x00')
				hmacout = pbkdf2_hmac('sha512', passwd, salt,
				    itr)
				print '\t{ %s, %d, %s, %d, %s, %d },' % \
				    (cstring(salt), saltl, cstring(passwd),
				    itr, cstring(hmacout), len(hmacout))
