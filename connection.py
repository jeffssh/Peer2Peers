import hashlib, json, math, requests, socket, struct, time
from progress.bar import Bar

class Connection:
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
	def __init__(self, torrent, ip, port):
		self.ip = ip
		self.port = port
		self.torrent = torrent
		self.info_hash = torrent.info_hash
		self.peer_id = torrent.peer_id
		self.piece_hashes = torrent.piece_hashes
		
		# Peer connection state, we are always interested
		self.am_choking = True
		self.peer_choking = True
		self.peer_interested = False
		# socket
		self.s = None
		# protocol string
		self.pstr = b'BitTorrent protocol'
		# "bitfield" to track pieces we've downloaded
		self.bitfield = [False] * len(self.piece_hashes)
		# list to rebuild pieces as they are being requested.
		self.partial_pieces = [None] * len(self.piece_hashes)
		# shards are pieces of pieces
		self.shards_per_piece = 0
		self.shards_per_last_piece = 0
		# number of requested shards that have not been replied to
		self.outstanding_shards = 0
		# maximum number of shards to request per connection
		self.outstanding_shards_max = 20
		# shard size 
		self.shard_size = 1<<14
		# field of dicts representing shard attributes, including
		# whether or not one has been requested, piece indices, and
		# offsets within pieces
		self.shardfield = self.__create_shardfield()
		# a tracker for how many shard requests have failed.
		# once all shard requests have failed, the torrent
		# will be checked for completeness
		self.unfullfilled_shard_requests = 0
		# progress bar
		self.progress_bar = None

		# peer fields
		self.p_reserved = None
		self.p_info_hash = None
		self.p_peer_id = None
		self.p_bitfield = [False] * len(self.piece_hashes)

	
	# socket helpers
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
				print(e)
				self.s.close()
				raise Exception("Couldn't recv message from peer")
		return message


	def __send_full(self, message):
		num_bytes = len(message)
		sent = 0
		while sent != num_bytes:
			try: 
				sent += self.s.send(message[sent:])
			except Exception as e:
				print(e)
				self.s.close()
				raise Exception("Couldn't send message to peer")
		return sent == len(message)


	def __send_message(self, message):
		length = struct.pack(">I", 1)
		self.__send_full(length + message)

	
	def __peer_keepalive(self):
		while True:
			time.sleep(30)
			self.__send_full(b"\x00\x00\x00\x00")


	# shard helpers
	def __create_shardfield(self):
		# shardfield is a bitfield broken down into a
		# collection of dicts representing shards
		num_pieces = len(self.piece_hashes)
		num_normal_pieces = (num_pieces - 1)
		shards = []
		# calculate number of shards per piece
		num_normal_shards = math.floor(self.torrent.piece_length / self.shard_size)
		last_shard_in_piece_length = self.torrent.piece_length % self.shard_size	
		self.shards_per_piece = num_normal_shards
		# if there was a remainder
		if last_shard_in_piece_length:
			self.shards_per_piece += 1

		# create shard list for each piece, ensuring last shard is handled
		# correctly if it is shorter
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
		num_last_normal_shards = math.floor(last_piece_length/self.shard_size)
		last_shard_length = last_piece_length % self.shard_size
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
		return shards


	def __get_next_downloadable_shard(self):
		# look for a shard that hasn't been requested yet. If
		# all have been requested, return None.
		# Other functions are responsible for resetting the
		# shardfield state, this function will pick up earlier
		# shards that failed and were reset
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


	def __process_incoming_shard(self, index,begin,block):
		if not self.progress_bar:
			self.progress_bar = Bar('Downloading and verifying pieces', max=len(self.piece_hashes))
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
			# have full piece, reassembling
			piece = b""
			for s in sorted(shards.keys()):
				piece += shards[s]
			
			h = hashlib.sha1(piece)
			piece_hash = h.digest()
			if piece_hash == self.piece_hashes[index]:
				# normally you'd write to disk here. Seeing as this tool is for
				# attribution of file ownership and not actually downloading files,
				# we just mark the piece as successfully downloaded
				self.bitfield[index] = True
				self.progress_bar.next()
			else:
				# piece hash failed. reset shard requested values to redownload
				for i in range(shards_per_piece):
					s = self.shardfield[(self.shards_per_piece * index) + i]
					s["requested"] = False

			# get rid of saved blocks to conserve memory and set up
			# for another piece download if attempted
			shards = None

		self.partial_pieces[index] = shards
		self.__request_new_shard_if_possible()
		if self.unfullfilled_shard_requests == self.outstanding_shards_max:
			# Completed on all shard requests with no outstanding shards.
			# If we've downloaded all the pieces, the peer owns the file
			# if not, they can't serve the whole file to us at this moment.
			# for a proof of concept tool, os._kill is fine
			if self.bitfield.count(True) == len(self.piece_hashes):
				print("[+] This peer owns the whole file!")
				os._kill(0)
			else:
				print("[-] Peer couldn't serve whole file")
				os._kill(0)


	def __request_new_shard_if_possible(self):
		shard = self.__get_next_downloadable_shard()
		if not shard:
			# no more shards that can be downloaded.
			# either we're finished, or this peer can't
			# give us the whole file now
			self.unfullfilled_shard_requests += 1
		else:
			# <len=0013><id=6><index><begin><length>
			message = b"\x06"
			message += struct.pack(">I", shard["index"])
			message += struct.pack(">I", shard["begin"])
			message += struct.pack(">I", shard["length"])
			self.__send_message(message)
			shard["requested"] = True
			self.outstanding_shards += 1


	# recv loop - If this program was to be multithreaded,
	# this would be split up into a reader and writer loop
	# rather than just dispatching requests on a message recv
	def __recv_loop(self):
		while True:
			try:
				# recv torrent messages
				# <length prefix><message ID><payload>.
				length = self.__recv_full(4)
				length = struct.unpack(">I", length)[0]
				message = self.__recv_full(length)
				message_id = message[0]
				message = message[1:]

				if message_id == 0:
					# choke
					self.peer_choking = True
				elif message_id == 1:
					# unchoke
					self.peer_choking = False
					if self.outstanding_shards == 0:
						print(f"[*] Sending initial {self.outstanding_shards_max} shard requests")
					while self.outstanding_shards < self.outstanding_shards_max:
						self.__request_new_shard_if_possible()

				elif message_id == 2:
					# interested
					self.peer_interested = True
				elif message_id == 3:
					# not interested
					self.peer_interested = False
				elif message_id == 4:
					# have
					index = struct.unpack(">I", message[0:4])[0]
					self.p_bitfield[index] = True
				elif message_id == 5:
					# bitfield
					num_pieces = len(self.piece_hashes)
					if length == num_pieces:
						self.p_bitfield = [True] * num_pieces
						self.interested = True
					else:
						# parse bitfield and initialize list
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

				elif message_id == 6:
					# request - do nothing
					# <len=0013><id=6><index><begin><length>
					pass

				elif message_id == 7:
					# piece
					# <len=0009+X><id=7><index><begin><block>
					index = struct.unpack(">I", message[0:4])[0]
					begin = struct.unpack(">I", message[4:8])[0]
					block = message[8:]
					# as a shard comes in, store it, verify the piece if the whole piece is there,
					# and send out a request for a new shard
					self.__process_incoming_shard(index,begin,block)

				elif message_id == 8:
					# cancel - do nothing
					#<len=0013><id=8><index><begin><length>
					pass 

				elif message_id == 9:
					# port
					# <len=0003><id=9><listen-port>
					# not implemented
					pass
				else:
					print(f"unrecognized message id: {message_id}")
				
			except Exception as e:
				# general exception handling is bad, but fine for this proof of
				# concept
				print(e)
				self.s.close()

				raise Exception("Connection to peer was closed")
			
			if self.peer_choking:
				print("[*] Peer choking, waiting 2 second then resending interested message")
				time.sleep(2)
				self.__send_message(b"\x02")


	def download_file(self):
		# there are most likely post handshake messages waiting for us by now.
		# send the bitfield message anyway, just in case the client needs prompting
		# to declare its bitfield/haves. In practice, some finicky peers
		# disconnect during the handshake, this is also insurance against those
		# peers. Some peers also unchoke without an interested message,
		# but send one anyway to prompt the peer to unchoke
		
		# send bitfield message, letting peer know we have none of the pieces
		empty_bitfield = b"\x05"+ math.ceil(len(self.piece_hashes)/8) * b"\x00"
		self.__send_message(empty_bitfield)
		
		# send interested message
		self.__send_message(b"\x02")
		self.__recv_loop()
		return


	def do_handshake(self):
		# handshake must be first message to peer
        # handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
		pstrlen = len(self.pstr).to_bytes(1, 'big')
		reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'
		m = pstrlen + self.pstr + reserved + self.info_hash + self.peer_id

		print("[*] Attempting handshake with peer")
		self.__create_socket()
		self.__send_full(m)
		r_size = self.__recv_full(1)
		r_size = ord(r_size)
		protocol = self.__recv_full(r_size)
		if r_size != len(self.pstr) or protocol != self.pstr:
			raise Exception(f"Unexpected protocol: '{protocol}' len: {self.pstr}")
		self.p_reserved = self.__recv_full(len(reserved))		
		self.p_info_hash = self.__recv_full(len(self.info_hash))
		self.p_peer_id = self.__recv_full(len(self.peer_id))
		if self.p_info_hash != self.info_hash:
			raise Exception("Client and Peer info_hash mismatch")

		print(f"[+] Handshake complete with {self.p_peer_id}: {self.ip}:{self.port}")
		# could start a keepalive thread here if interested
		#threading.Thread(target=self.__peer_keepalive, args=()).start()


