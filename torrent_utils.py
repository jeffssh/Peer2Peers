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
import threading
import time
import struct
import math
import hashlib
from progress.bar import Bar

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
		raise Exception("Invalid input!")


class Torrent:
	def __init__(self,torrent_file):
		self.torrent_file = torrent_file
		self.torrent = None
		self.peers = None
		self.piece_hashes = []
		# fingerprint for others, not trying to be subtle
		self.peer_id = b"Peer2Peers" + os.urandom(10)
		self.__load_torrent_file(torrent_file)
		self.info_hash = self.torrent['info_hash']
		self.length = self.torrent['info']['length']
		self.piece_length = self.torrent['info']['piece length']
		self.__load_piece_hashes(self.torrent['info']['pieces'])
		self.__get_peers()

	def __str__(self):
		# TODO workng with single file torrent only for now
		"""
		{
			"announce": "https://torrent.ubuntu.com/announce", 
			"comment": "Xubuntu CD cdimage.ubuntu.com", 
			"created by": "mktorrent 1.1", 
			"creation date": 1596727330, 
			"info": {
					"length": 1699577856, 
					"name": "xubuntu-20.04.1-desktop-amd64.iso", 
					"piece length": 262144, 
					"pieces": "<--SNIP-->"
				}
		}
		"""
		s = f"announce: {self.torrent['announce']}\n"
		s += f"comment: {self.torrent['comment']}\n"
		s += f"created by: {self.torrent['created by']}\n"
		s += f"creation date: {self.torrent['creation date']}\n"
		s += f"name: {self.torrent['info']['name']}\n"
		s += f"length: {self.torrent['info']['length']}\n"
		s += f"number of pieces: {len(self.piece_hashes)}\n"
		s += f"piece length: {self.torrent['info']['piece length']}\n"
		s += f"info hash: {self.torrent['info_hash']}"
		return s

	def __get_peers(self):
		# request list of peers from tracker
		info_hash = self.torrent['info_hash']

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
			print(f"Bad response from {self.torrent['announce']}")
		tracker_response = bdecode(r.text)
		self.peers = self.__parse_peers(tracker_response['peers'])

	def __load_piece_hashes(self, piece_hashes_concat):
		for i in range(0, int(len(piece_hashes_concat)), 20):
			self.piece_hashes.append(piece_hashes_concat[i:i+20])

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
			raise Exception("Invalid input!")


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
				# TODO review this
				b.extend(map(ord,peers[i:i+6]))
				ip, port = struct.unpack('!IH',b)
				ip = str(ipaddress.ip_address(ip))
				peers_list.append({'ip':ip,'port':port})
			return peers_list

		raise Exception("Couldn't decode peers")

	
class Connection:
	def __init__(self, torrent, ip, port):
		self.torrent = torrent
		self.info_hash = torrent.info_hash
		self.peer_id = torrent.peer_id
		self.piece_hashes = torrent.piece_hashes
		self.ip = ip
		self.port = port
		self.am_choking = True
		self.peer_choking = True
		self.peer_interested = False
		self.bitfield = [False] * len(self.piece_hashes)
		self.pstr = b'BitTorrent protocol'
		self.s = None
		self.p_reserved = None
		self.p_info_hash = None
		self.p_peer_id = None
		self.p_bitfield = [False] * len(self.piece_hashes)
		self.outstanding_shards_max = 50
		self.outstanding_shards = 0
		self.shard_lock = threading.Lock()
		self.send_lock = threading.Lock()
		self.shard_size = 1<<14
		self.shards_per_piece = 0
		self.shards_per_last_piece = 0
		self.progress_bar = Bar('Downloading and verifying pieces', max=len(self.piece_hashes))
		self.shardfield = self.__create_shardfield()
		self.partial_pieces = [None] * len(self.piece_hashes)

	def __create_socket(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.ip, self.port))
		self.s = s

	def __recv_full(self, num_bytes):
		message = b""
		read = 0
		while read != num_bytes:
			try: 
				message += self.s.recv(num_bytes - read)
				read = len(message)
			except Exception as e:
				print("Connection to peer was closed")
				self.s.close()
				# fatal. For demo tool, os._exit() is fine
				os._exit(1)
		return message

	def __send_full(self, message):
		num_bytes = len(message)
		sent = 0
		self.send_lock.acquire()
		while sent != num_bytes:
			try: 
				sent += self.s.send(message[sent:])
			except Exception as e:
				print("couldn't send message to peer: ", e)
				self.s.close()
				self.send_lock.release()
				# fatal. For demo tool, os._exit() is fine
				os._exit(1)
		self.send_lock.release()
		return sent == len(message)


	def __recv_message(self):
		try:
			# <length prefix><message ID><payload>.
			length = self.__recv_full(4)
			#print("recved: ", length)
			length = struct.unpack(">I", length)[0]
			#print("length: ", length)
			if not length:
				#print("keepalive message")
				return
			#print("----------------------------")
			message = self.__recv_full(length)
			#print(f"message len: {len(message)}")
			message_id = message[0]
			# make sure to read until buff len = len
			message = message[1:]
			#print(len(message))
			if message_id == 0:
				print("choke")
				self.peer_choking = True
			elif message_id == 1:
				print("unchoke")
				self.peer_choking = False
			elif message_id == 2:
				print("interested")
				self.peer_interested = True
			elif message_id == 3:
				print("not interested")
				self.peer_interested = False
			elif message_id == 4:
				index = struct.unpack(">I", message[0:4])[0]
				self.p_bitfield[index] = True
				print(f"have - index: {index}")
				print(f"this peer has {self.p_bitfield.count(True)} out of {len(self.p_bitfield)} pieces")
			elif message_id == 5:
				print("bitfield")
				num_pieces = len(self.piece_hashes)
				if length == 4294967295:
					print("this peer has all pieces")
					self.p_bitfield = [True] * num_pieces
					self.interested = True
				elif length == num_pieces:
					print("this peer has all pieces")
					self.p_bitfield = [True] * num_pieces
					self.interested = True
				else:
					bitfield = []
					pieces = 0
					for b in message:
						curr_bitfield = [False] * 8
						for i in range(8):
							has_piece = b >> i & 1
							if has_piece:
								curr_bitfield[i] = True
								pieces += 1
						curr_bitfield.reverse()
						bitfield += curr_bitfield

					self.p_bitfield = bitfield
					self.interested = False
					print(f"this peer has {pieces} out of {len(self.p_bitfield)} pieces")

			elif message_id == 6:
				# <len=0013><id=6><index><begin><length>
				# 2^15
				index = struct.unpack(">I", message[0:4])[0]
				begin = struct.unpack(">I", message[4:8])[0]
				length = struct.unpack(">I", message[8:])[0]
				print(f"request - index: {index}, begin: {begin}, length:{length}")

			elif message_id == 7:
				#print("piece")
				# <len=0009+X><id=7><index><begin><block>
				index = struct.unpack(">I", message[0:4])[0]
				begin = struct.unpack(">I", message[4:8])[0]
				block = message[8:]
				#print(f"request - index: {index}, begin: {begin}, block size: {len(block)}")
				# as a shard comes in, store it, verify the piece if the whole piece is there,
				# and send out a request for a new shard
				self.__process_incoming_shard(index,begin,block)

			elif message_id == 8:
				print("cancel")
				#<len=0013><id=8><index><begin><length>
				index = struct.unpack(">I", message[0:4])[0]
				begin = struct.unpack(">I", message[4:8])[0]
				length = struct.unpack(">I", message[8:])[0]
				print(f"cancel - index: {index}, begin: {begin}, length:{length}")

			elif message_id == 9:
				print("port")
				# <len=0003><id=9><listen-port>
				# not implemented
				pass
			else:
				print(f"unrecognized message id: {message_id}")
			
			#print(f"message id: {message_id}, len {len(message)}, dump:")
			#hexdump.hexdump(message)
			#print("----------------------------")

		except Exception as e:
			self.s.close()
			print("Connection to peer was closed")
			# fatal. For demo tool, os._exit() is fine
			os._exit(1)



	def __peer_keepalive(self):
		while True:
			time.sleep(30)
			self.__send_full(b"\x00\x00\x00\x00")

	def __peer_listen(self):
		while True:
			self.__recv_message()

	def __send_message(self, message):
		length = struct.pack(">I", 1)
		self.__send_full(length + message)

	def __create_shardfield(self):
		print("================ shardfield")
		num_pieces = len(self.piece_hashes)
		num_normal_pieces = (num_pieces - 1)
		shards = []
		print(f"num_normal_shards: {self.torrent.piece_length / self.shard_size}, {math.floor(self.torrent.piece_length / self.shard_size)}")
		num_normal_shards = math.floor(self.torrent.piece_length / self.shard_size)
		last_shard_in_piece_length = self.torrent.piece_length % self.shard_size	
		print(f"last_shard_in_piece_length: {last_shard_in_piece_length}")
		self.shards_per_piece = num_normal_shards
		if last_shard_in_piece_length:
			self.shards_per_piece += 1

		for i in range(num_normal_pieces):
			curr_shards = []
			begin = 0
			for j in range(num_normal_shards):
				curr_shards.append({"index": i, "begin": begin, "length": self.shard_size, "requested": False})
				begin += self.shard_size
			if last_shard_in_piece_length:
				curr_shards.append({"index": i, "begin": begin, "length": last_shard_in_piece_length, "requested": False})
			
			shards += curr_shards 
		
		# do same calculations but for very last piece, which can be shorter than other
		# pieces
		last_piece_length = self.torrent.length % self.torrent.piece_length
		print(f"num_last_normal_shards: {math.floor(last_piece_length/self.shard_size)}, {math.floor(last_piece_length/self.shard_size)}")
		num_last_normal_shards = math.floor(last_piece_length/self.shard_size)
		last_shard_length = last_piece_length % self.shard_size
		print(f"last_shard_length: {last_shard_length}")
		self.shards_per_last_piece = num_last_normal_shards
		if last_shard_length:
			self.shards_per_last_piece += 1
		curr_shards = []
		begin = 0
		for i in range(num_last_normal_shards):
			curr_shards.append({"index": i, "begin": begin, "length": self.shard_size, "requested": False})
			begin += self.shard_size
		if last_shard_length:
			curr_shards.append({"index": i, "begin": begin, "length": last_shard_length, "requested": False})
	
		shards += curr_shards 
		print(f"made shardfield of size {len(shards)}, shards per piece: {self.shards_per_piece}, shards per last piece: {self.shards_per_last_piece}",)
		print("================ shardfield")
		return shards

	def __get_next_downloadable_shard(self):
		for i in range(len(self.p_bitfield)):
			if self.p_bitfield[i]:
				shards_per_piece = self.shards_per_piece
				if i == len(self.p_bitfield):
					shards_per_piece = self.shards_per_last_piece
				begin = shards_per_piece * i
				end = shards_per_piece * (i + 1)
				for s in self.shardfield[begin:end]:
					if not s["requested"]:
						return s
		return None
	
	def __request_new_shards_if_possible(self):
		# WORKING
		self.shard_lock.acquire()
		while self.outstanding_shards < self.outstanding_shards_max:
				# <len=0013><id=6><index><begin><length>
				#num_to_request = self.outstanding_pieces - self.outstanding_piece_max:
				shard = self.__get_next_downloadable_shard()
				if not shard:
					# no more shards that can be downloaded.
					# either we're finished, or this peer can't
					# give us the whole file now
					break
				else:
					message = b"\x06"
					message += struct.pack(">I", shard["index"])
					message += struct.pack(">I", shard["begin"])
					message += struct.pack(">I", shard["length"])
					#print(f"sending shard request - index: {shard['index']}, begin: {shard['begin']}, length:{shard['length']}")
					self.__send_message(message)
					shard["requested"] = True
					self.outstanding_shards += 1

		self.shard_lock.release()


	def __process_incoming_shard(self, index,begin,block):
		# todo
		self.shard_lock.acquire()
		self.outstanding_shards -= 1
		shards = self.partial_pieces[index]
		if not shards:
			self.partial_pieces[index] = {}
			shards = {}
		shards[begin] = block
		shards_per_piece = self.shards_per_piece
		if index == (len(self.piece_hashes) - 1):
			shards_per_piece = self.shards_per_last_piece
		
		if len(shards) == shards_per_piece:
			#print(f"have full piece {index}, reassembling")
			piece = b""
			for s in sorted(shards.keys()):
				piece += shards[s]
			h = hashlib.sha1(piece)
			piece_hash = h.digest()

			# these are strings from the bdecoding, convert
			real_piece_hash_str = self.piece_hashes[index]
			real_piece_hash_bytes = bytearray()
			real_piece_hash_bytes.extend(map(ord, real_piece_hash_str))
			real_piece_hash_bytes = bytes(real_piece_hash_bytes)

			#print(f"reassembled piece {index}, hash: {piece_hash}, expected: {real_piece_hash_bytes}")
			if piece_hash == real_piece_hash_bytes:
				# normally you'd write to disk here. Seeing as this tool is for
				# attribution of file ownership and not actually downloading files,
				# we just mark the piece as successfully downloaded
				self.bitfield[index] = True
				self.progress_bar.next()
			else:
				print(f"reassembled piece {index}, hash: {piece_hash}, expected: {real_piece_hash_bytes}")
				exit()

			# get rid of saved blocks to conserve memory and set up
			# for another piece download if attempted
			# (it won't be, retries for bad blocks won't be implemented) TODO
			shards = None

		self.partial_pieces[index] = shards
		self.shard_lock.release()
		self.__request_new_shards_if_possible()




	def download_file(self):
		print("starting file download")
		# send bitfield message 
		empty_bitfield = b"\x05"+ math.ceil(len(self.piece_hashes)/8) * b"\x00"
		#print(f"sending empty bitfield message of size {len(empty_bitfield)}")
		#self.__send_message(empty_bitfield)
		# send interested message
		self.__send_message(b"\x02")
		"""
		self.progress_bar.next()
		for _ in range(5):
			time.sleep(1)
			self.progress_bar.next()
		print("progress bar",self.progress_bar)
		"""

		while True:
			if not self.peer_choking:
				# can download
				self.__request_new_shards_if_possible()
				#if self.shards_requested <= self.outstanding_shard_max:
					# start requests for outstanding pieces. Reader thread will dispatch new
					# requests when it completes a piece successfully
					#if not self.__request_new_shards_if_possible()
						# was not possible to request a new shard
				#else:
					#time.sleep(10)
				return
					
			else:
				# can't download
				print("Peer choking, resending interested message and then retrying in 3 second")
				self.__send_message(b"\x02")
				time.sleep(3)
		

		


	def do_handshake(self):
		# handshake must be first message to peer
		try:
			# handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
			self.__create_socket()
			pstrlen = len(self.pstr).to_bytes(1, 'big')
			reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'
			m = pstrlen + self.pstr + reserved + self.info_hash + self.peer_id
			print("Attempting handshake with peer")
			self.__send_full(m)
			r_size = self.__recv_full(1)
			if(len(r_size) == 0):
				raise Exception((f"Couldn't handshake with {self.ip}:{self.port}, connection reset")
			r_size = ord(r_size)
			protocol = self.__recv_full(r_size)
			if r_size != len(self.pstr) or protocol != self.pstr:
				raise Exception(f"Unexpected protocol: '{protocol}' len: {self.pstr}")
			self.p_reserved = self.__recv_full(len(reserved))		
			self.p_info_hash = self.__recv_full(len(self.info_hash))
			self.p_peer_id = self.__recv_full(len(self.peer_id))
			if self.p_info_hash != self.info_hash:
				raise Exception("Client and Peer info_hash mismatch")
		except Exception as e:
			raise Exception("Handshake failed")
			return

		print(f"Handshake complete with {self.p_peer_id}: {self.ip}:{self.port}")
		# create reader thread
		threading.Thread(target=self.__peer_listen, args=()).start()
		threading.Thread(target=self.__peer_keepalive, args=()).start()
		#self.s.close()
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


