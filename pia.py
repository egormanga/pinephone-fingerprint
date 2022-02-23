#!/usr/bin/env python3

import struct, crccheck, periphery

class PIA(periphery.I2C):
	HEADER = bytearray(b"\x55\xaa\x00")
	MAX_LENGTH = 0x110
	READ_LENGTH = (8 + MAX_LENGTH + 2)
	CMD_TRANSMIT = 0x01
	CMD_CONFIGURE = 0x02

	def __init__(self, devpath="/dev/i2c-2", address=0x28):
		super().__init__(devpath=devpath)
		self.address = address
		self.crc = crccheck.crc.CrcCcitt()

	def init(self):
		self.transfer(self.address, [self.Message([self.CMD_CONFIGURE, 0b01])])

	def send(self, command, data):
		length = len(data)
		if (length > self.MAX_LENGTH): raise ValueError(f"Message is too long ({length} > {self.MAX_LENGTH})")

		header = (self.HEADER + struct.pack('>BxxH', command, length))
		payload = (header + data)
		checksum = self.crc.calc(payload)
		payload += struct.pack('>H', checksum)

		print('<', *(f"{i:02x}" for i in payload))
		packet = [j for i in payload for j in (self.CMD_TRANSMIT, i)]
		message = self.Message(packet)
		response = self.Message([self.CMD_TRANSMIT]*(self.READ_LENGTH*2), read=True)
		self.transfer(self.address, [message, response])
		print('>', *(f"{i:02x}" for i in response.data))

		return bytearray(response.data)

	def parse(self, command, response):
		if (response[:3] != self.HEADER): raise ValueError("Incorrect header", response)
		if (response[3] & 0x7f != command): raise ValueError(f"Incorrect command (expected {command:#x02})", response)
		if (not response[3] & 0x80): raise ValueError("Command failed", response)
		if (response[4] == 0xF1): raise ValueError("Secure Level error", response)
		if (response[4] == 0xF2): raise ValueError("Reserved Bytes error", response)
		if (response[4] == 0xF3): raise ValueError("Checksum error", response)

		result = response[5]
		length = struct.unpack('>H', response[6:8])
		data = response[8:length+8]
		checksum = response[length:length+1]

		if (checksum != self.crc.calc(response[:8+length])): raise ValueError("Incorrect checksum", response)

		return (result, data)

	def call(self, command, data=b''):
		response = self.send(command, data)
		return self.parse(command, response)

	def get_list(self):
		result, data = self.call(0x05)
		assert (result == 0x00)
		return data

	def get_firmware_version(self):
		result, data = self.call(0x7F)
		assert (result == 0x00)
		return data

def main():
	fp = PIA()
	fp.init()
	print(fp.get_firmware_version())

if (__name__ == '__main__'): exit(main())

# by Sdore, 2022
#  www.sdore.me
