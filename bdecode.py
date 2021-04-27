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