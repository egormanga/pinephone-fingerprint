#!/usr/bin/env python3

import os, hmac, array, fcntl, struct, crccheck

class PIA:
	_I2C_SLAVE = 0x0703
	_I2C_FUNCS = 0x0705
	_I2C_FUNC_I2C = 0x1

	HEADER = bytearray(b"\x55\xAA\x00")
	MAX_LENGTH = 0x110
	READ_LENGTH = (8 + MAX_LENGTH + 2)
	CMD_TRANSMIT = 0x01
	CMD_CONFIGURE = 0x02

	def __init__(self, devpath="/dev/i2c-2", address=0x28):
		self.devpath, self.address = devpath, address
		self.crc = crccheck.crc.CrcCcitt()
		self._fd = None
		self.open()

	def __del__(self):
		self.close()

	def open(self):
		self._fd = os.open(self.devpath, os.O_RDWR)

		buf = array.array('I', [0])
		try: fcntl.ioctl(self._fd, self._I2C_FUNCS, buf, True)
		except OSError: self.close(); raise

		if (not buf[0] & self._I2C_FUNC_I2C):
			self.close()
			raise ValueError(f"I2C is not supported on {self.devpath}.")

		fcntl.ioctl(self._fd, self._I2C_SLAVE, self.address)

	def close(self):
		if (self._fd is not None):
			os.close(self._fd)
			self._fd = None

	def read(self, length):
		return os.read(self._fd, length)

	def write(self, data):
		return os.write(self._fd, data)

	def send(self, command, data):
		length = len(data)
		if (length > self.MAX_LENGTH): raise ValueError(f"Message is too long ({length} > {self.MAX_LENGTH})")

		header = (self.HEADER + struct.pack('>BxxH', command, length))
		payload = (header + data)
		checksum = self.crc.calc(payload)
		payload += struct.pack('>H', checksum)

		print('<', *(f"{i:02x}" for i in payload))

		# write the data
		self.write(bytes((self.CMD_TRANSMIT, *payload)))

		# adjust the tx pointer
		for i in range(len(payload)):
			self.read(1)

	def receive(self):
		# sync with the sensor
		x55 = bool()
		while (True):
			self.write(b"\1\0")
			b = self.read(1)
			if (x55 and b == b'\xAA'): break
			x55 = (b == b'\x55')

		# read the response
		res = bytearray(b"\x55\xAA")
		for i in range(self.READ_LENGTH):
			self.write(b"\1\0")
			res += self.read(1)

		print('>', *(f"{i:02x}" for i in res))

		return res

	def parse(self, command, response):
		if (response[:3] != self.HEADER): raise ValueError("Incorrect header", response[:3])
		if (response[3] & 0x7f != command): raise ValueError(f"Incorrect command (expected {command:#04x})", response[3])
		if (not response[3] & 0x80): raise ValueError("Command failed", response)
		if (response[4] == 0xF1): raise ValueError("Secure Level error", response)
		if (response[4] == 0xF2): raise ValueError("Reserved Bytes error", response)
		if (response[4] == 0xF3): raise ValueError("Checksum error", response)

		result = response[5]
		length = struct.unpack('>H', response[6:6+2])[0]
		data = response[8:8+length]
		checksum = struct.unpack('>H', response[8+length:8+length+2])[0]
		crc = self.crc.calc(response[:8+length])
		if (checksum != crc): raise ValueError("Incorrect checksum", checksum, crc)

		return (result, data)

	def call(self, command, data=b''):
		self.send(command, bytes(data))
		response = self.receive()
		return self.parse(command, response)

	def enroll(self, uid):
		pid = 0x01
		if (len(uid) != 32): raise ValueError("UID length must be 32.")
		result, data = self.call(pid, uid)
		match result:
			case 0x00: return True
			case 0x02: raise PIAError(result, "Canceled")
			case 0x08: raise PIAError(result, "Data storage full")
			case 0x0B: raise PIAError(result, "Invalid UID")
			case 0x19: raise PIAStatus(result, "Redundant fingerprint")
			case 0x20: raise PIAStatus(result, "Bad image")
			case 0x21: raise PIAStatus(result, "Good image captured")
			case 0x25: raise PIAStatus(result, "Wait for finger press")
			case 0x27: raise PIAStatus(result, "Press too fast")
			case 0x28: raise PIAStatus(result, "Partial image")
			case _: raise PIAError(result)

	def verify(self, hmac_msg):
		pid = 0x02
		if (len(hmac_msg) != 32): raise ValueError("HMAC Message length must be 32.")
		result, data = self.call(pid, hmac_msg)
		match result:
			case 0x00: return data
			case 0x01: raise PIAError(result, "Not match")
			case 0x02: raise PIAError(result, "Canceled")
			case 0x03: raise PIAError(result, "No template stored")
			case 0x05: raise PIAError(result, "Partial image")
			case 0x06: raise PIAError(result, "Press too fast")
			case 0x07: raise PIAError(result, "Bad image")
			case 0x0B: raise PIAError(result, "Invalid HMAC Message")
			case _: raise PIAError(result)

	def delete(self, index=None):
		""" index: int or None to delete all. """
		pid = 0x03
		result, data = self.call(pid, bytes((index,)) if (index is not None) else b'')
		match result:
			case 0x00: return True
			case 0x0B: raise PIAError(result, "Index not found")
			case _: raise PIAError(result)

	def cancel(self):
		pid = 0x04
		self.send(pid, b'')
		# no response

	def get_list(self):
		pid = 0x05
		result, data = self.call(pid)
		match result:
			case 0x00: return data
			case _: raise PIAError(result)

	def calibrate(self):
		pid = 0x07
		result, data = self.call(pid)
		match result:
			case 0x00: return True
			case _: raise PIAError(result)

	def write_hmac_key(self, key):
		pid = 0x70
		if (len(key) != 64): raise ValueError("Key length must be 64.")
		result, data = self.call(pid, key)
		match result:
			case 0x00: return True
			case 0x0B: raise PIAError(result, "Invalid HMAC Key")
			case _: raise PIAError(result)

	def get_firmware_version(self):
		pid = 0x7F
		result, data = self.call(pid)
		match result:
			case 0x00: return data
			case _: raise PIAError(result)

	def run_enrollment(self, uid):
		while (True):
			try: return self.enroll(uid)
			except PIAStatus as ex: print(f"Status: {ex.args[-1]}")

	def run_verification(self, uid):  # note: uid should normally be stored in a database and picked up using the reported finger id, instead.
		hmac_key = b"test"*16 # XXX FIXME should be stored too
		hmac_msg = os.urandom(32) # FIXME: use Crypto
		data = self.verify(hmac_msg)
		digest = hmac.digest(hmac_key, bytes.fromhex("55AA 00 82 00 00 0021") + data[:1] + uid + hmac_msg, 'sha256')
		if (not hmac.compare_digest(data[1:], digest)): raise PIAHMACError()
		return data[0]

class PIAError(Exception): pass
class PIAStatus(PIAError): pass
class PIAHMACError(PIAError): pass

def main():
	fp = PIA()
	print(fp.get_firmware_version())
	print(fp.get_list())

if (__name__ == '__main__'): exit(main())

# by Sdore, 2022
#  www.sdore.me
