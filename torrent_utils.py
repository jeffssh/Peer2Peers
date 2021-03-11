#!/usr/bin/env python3
import hashlib
import ipaddress
import struct
import socket
import hexdump
import binascii
import requests
import os
import binascii
import json

# taken from https://wiki.theory.org/Decoding_bencoded_data_with_python
# fixed to work with python3 bytearrays
# could precompute ords but this is more readable
def bdecode(data):
	# try to be nice and work on strings too
	# done this way to prevent encoding/decoding issues
	if type(data) == str:
		b = bytearray()
		b.extend(map(ord, data))
		chunks = b
	else:
		chunks = bytearray(data)
	chunks.reverse()
	root = _dechunk(chunks)
	return root


def _dechunk(chunks):
	item = chunks.pop()
	if item == ord('d'): 
		item = chunks.pop()
		h = {}
		while item != ord('e'):
			chunks.append(item)
			key = _dechunk(chunks)
			h[key] = _dechunk(chunks)
			item = chunks.pop()
		return h
	elif item == ord('l'):
		item = chunks.pop()
		l = []
		while item != ord('e'):
			chunks.append(item)
			l.append(_dechunk(chunks))
			item = chunks.pop()
		return list
	elif item == ord('i'):
		item = chunks.pop()
		num = ''
		while item != ord('e'):
			num  += chr(item)
			item = chunks.pop()
		return int(num)
	elif item < 0x3A and item >= 0x30: # is this a decimal?
		num = ''
		while item < 0x3A and item >= 0x30 :
			num += chr(item)
			item = chunks.pop()
		line = ''
		for i in range(int(num)):
			line += chr(chunks.pop())
		return line
	else:
		print(item)
		raise "Invalid input!"


class Torrent:
	def __init__(self,torrent_file):
		self.torrent_file = torrent_file
		self.torrent = None
		self.peers = None
		# fingerprint for others, not trying to be subtle
		self.peer_id = b"Peer2Peers" + os.urandom(10)
		self.__load_torrent_file(torrent_file)
		self.info_hash = self.torrent['info_hash']
		self.__get_peers()


	def __get_peers(self):
		# request list of peers from tracker
		info_hash = self.torrent['info_hash']
		peer_id = b"Peer2Peers" + os.urandom(10)
		p = {
			"info_hash": self.info_hash,
			"peer_id": self.peer_id,
			"port": 6881, # 6881-6889 are common ports for torrenting
			"uploaded": "0",
			"downloaded": "0",
			"left": self.torrent['info']['length'],
			"compact": 1,
			"no_peer_id": 0,
			"event": "started", # stopped, completed
			# "ip": -- optional
			"numwant": 99999 # we want all of the peers
			# "key": -- optional
			# "trackerid": -- optional
		}
		r = requests.get(self.torrent['announce'], params = p) # debugging ONLY, verify = False)
		if r.status_code != 200:
			Print(f"Bad response from {self.torrent['announce']}")
		tracker_response = bdecode(r.text)
		self.peers = self.__parse_peers(tracker_response['peers'])


	def __load_torrent_file(self, torrent_file):
		with open(torrent_file, 'rb') as f:
			data = f.read()

		torrent = self.__parse_torrent_file(data)

	
	def __parse_torrent_file(self, data):
		chunks = bytearray(data)
		chunks.reverse()
		root = self.__torrent_dechunk(chunks)
		self.torrent = root


	def __torrent_dechunk(self, chunks):
		item = chunks.pop()
		if item == ord('d'): 
			item = chunks.pop()
			h = {}
			while item != ord('e'):
				chunks.append(item)
				key = self.__torrent_dechunk(chunks)
				# lookahead on info to hash
				if key == 'info':
					# calculate hash of the bencoded info value
					# necessary for other parts of the protocol
					old_chunks = list(chunks)
					old_chunks.reverse()
					end = len(chunks) - 1
					h[key] = self.__torrent_dechunk(chunks)
					start = len(chunks) - 1 
					m = hashlib.sha1()
					m.update(bytes(old_chunks[start:end]))
					info_hash = m.digest()
					h['info_hash'] = info_hash # binascii.hexlify(h)
				else:
					h[key] = self.__torrent_dechunk(chunks)

				item = chunks.pop()
			return h
		elif item == ord('l'):
			item = chunks.pop()
			l = []
			while item != ord('e'):
				chunks.append(item)
				l.append(self.__torrent_dechunk(chunks))
				item = chunks.pop()
			return list
		elif item == ord('i'):
			item = chunks.pop()
			num = ''
			while item != ord('e'):
				num  += chr(item)
				item = chunks.pop()
			return int(num)
		elif item < 0x3A and item >= 0x30: # is this a decimal?
			num = ''
			while item < 0x3A and item >= 0x30 :
				num += chr(item)
				item = chunks.pop()
			line = ''
			for i in range(int(num)):
				line += chr(chunks.pop())
			return line
		else:
			raise "Invalid input!"


	def __parse_peers(self, peers):
		# untested, attempt to discern between the two models
		if type(peers) == dict:
			"""
			peers: (dictionary model) The value is a list of dictionaries, each with the following keys:
				peer id: peer's self-selected ID, as described above for the tracker request (string)
				ip: peer's IP address either IPv6 (hexed) or IPv4 (dotted quad) or DNS name (string)
				port: peer's port number (integer)
			"""
			# theoretically, nothing needs to happen here.
			# recursive bdecoding should handle it
			return peers
		else:
			"""
			peers: (binary model) Instead of using the dictionary model described above, 
			the peers value may be a string consisting of multiples of 6 bytes. 
			First 4 bytes are the IP address and last 2 bytes are the port number. 
			All in network (big endian) notation.
			"""

			# not sure if this should be a list? probably...
			peers_list = []
			for i in range(0, int(len(peers)), 6):
				b = bytearray()
				b.extend(map(ord,peers[i:i+6]))
				ip, port = struct.unpack('!IH',b)
				ip = str(ipaddress.ip_address(ip))
				peers_list.append({'ip':ip,'port':port})
			return peers_list

		raise "Couldn't decode peers"

	
class Connection:
	def __init__(self,info_hash, peer_id, ip, port):
		self.info_hash = info_hash
		self.peer_id = peer_id
		self.ip = ip
		self.port = port
		self.am_choking = 1
		self.am_interested = 0
		self.peer_choking = 1
		self.peer_interested = 0
		self.pstr = b'BitTorrent protocol'
		self.s = None
		self.p_reserved = None
		self.p_info_hash = None
		self.p_peer_id = None

	def __create_socket(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.ip, self.port))
		#s.connect(("213.57.151.104", 6881))
		
		self.s = s

	def do_handshake(self):
		# handshake must be first message to peer
		try:
			self.__create_socket()
			# handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
			pstrlen = len(self.pstr).to_bytes(1, 'big')
			reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'
			m = pstrlen + self.pstr + reserved + self.info_hash + self.peer_id
			self.s.send(m)
			r_size = self.s.recv(1)
			if(len(r_size) == 0):
				print(f"Couldn't handshake with {self.ip}:{self.port}, connection reset")
				return
			r_size = ord(r_size)
			protocol = self.s.recv(r_size)
			if r_size != len(self.pstr) or protocol != self.pstr:
				print(self.pstr)
				print(protocol)
				raise "Unexpected protocol"
			self.p_reserved = self.s.recv(len(reserved))		
			self.p_info_hash = self.s.recv(len(self.info_hash))
			self.p_peer_id = binascii.hexlify(self.s.recv(len(self.peer_id))).decode('utf-8')
			if self.p_info_hash != self.info_hash:
				raise "Client and Peer info_hash mismatch"
		except Exception as e:
			print(e)
			return

		print(f"Handshake complete with {self.p_peer_id}: {self.ip}:{self.port}")
		self.s.close()
		#hexdump.hexdump(r)

"""
choked: Whether or not the remote peer has choked this client. When a peer chokes the client, it is a notification that no requests will be answered until the client is unchoked. The client should not attempt to send requests for blocks, and it should consider all pending (unanswered) requests to be discarded by the remote peer.
interested: Whether or not the remote peer is interested in something this client has to offer. This is a notification that the remote peer will begin requesting blocks when the client unchokes them.
Note that this also implies that the client will also need to keep track of whether or not it is interested in the remote peer, and if it has the remote peer choked or unchoked. So, the real list looks something like this:

am_choking: this client is choking the peer
am_interested: this client is interested in the peer
peer_choking: peer is choking this client
peer_interested: peer is interested in this client
Client connections start out as "choked" and "not interested". In other words:

am_choking = 1
am_interested = 0
peer_choking = 1
peer_interested = 0
"""


