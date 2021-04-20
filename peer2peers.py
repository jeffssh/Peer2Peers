#!/usr/bin/env python3 
import requests
import os
import binascii
import json
import time
from torrent_utils import *
from PyInquirer import prompt, print_json
#from ip2geotools.databases.noncommercial import DbIpCity
#from geoip import geolite2

"""
def url_encode_all_chars(s):
	i = iter(s)
	info_hash = '%'.join(a+b for a,b in zip(i, i))
"""

def create_choices(peers):
	choices = []
	for p in peers:
		choices.append({'name':f"{p['ip']}:{p['port']}",'value':p})
	return choices

if __name__ == "__main__" :
	# for testing
	# https://wiki.theory.org/BitTorrentSpecification
	# https://torrent.ubuntu.com/tracker_index
	
	#torrent_file = "xubuntu-20.04.1-desktop-amd64.iso.torrent"
	#torrent_file = "volumes-136ffddd0959108becb2b3a86630bec049fcb0ff.torrent"
	# TODO change to input first arg
	t = Torrent("ubuntu-20.04.2.0-desktop-amd64.iso.torrent")
	# root keys = ['announce', 'comment', 'created by', 'creation date', 'info', 'info_hash']
	print("Torrent Loaded")
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

	### steps for torrenting

	# get tracker list from torrent file
	# files contain pieces
	# pieces contain blocks


	#print(torrent['url-list'])
	"""
	info_hash: urlencoded 20-byte SHA1 hash of the value of the info key from the Metainfo file. Note that the value will be a bencoded dictionary, given the definition of the info key above.
	peer_id: urlencoded 20-byte string used as a unique ID for the client, generated by the client at startup. This is allowed to be any value, and may be binary data. There are currently no guidelines for generating this peer ID. However, one may rightly presume that it must at least be unique for your local machine, thus should probably incorporate things like process ID and perhaps a timestamp recorded at startup. See peer_id below for common client encodings of this field.
	port: The port number that the client is listening on. Ports reserved for BitTorrent are typically 6881-6889. Clients may choose to give up if it cannot establish a port within this range.
	uploaded: The total amount uploaded (since the client sent the 'started' event to the tracker) in base ten ASCII. While not explicitly stated in the official specification, the concensus is that this should be the total number of bytes uploaded.
	downloaded: The total amount downloaded (since the client sent the 'started' event to the tracker) in base ten ASCII. While not explicitly stated in the official specification, the consensus is that this should be the total number of bytes downloaded.
	left: The number of bytes this client still has to download in base ten ASCII. Clarification: The number of bytes needed to download to be 100% complete and get all the included files in the torrent.
	compact: Setting this to 1 indicates that the client accepts a compact response. The peers list is replaced by a peers string with 6 bytes per peer. The first four bytes are the host (in network byte order), the last two bytes are the port (again in network byte order). It should be noted that some trackers only support compact responses (for saving bandwidth) and either refuse requests without "compact=1" or simply send a compact response unless the request contains "compact=0" (in which case they will refuse the request.)
	no_peer_id: Indicates that the tracker can omit peer id field in peers dictionary. This option is ignored if compact is enabled.
	event: If specified, must be one of started, completed, stopped, (or empty which is the same as not being specified). If not specified, then this request is one performed at regular intervals.
		started: The first request to the tracker must include the event key with this value.
		stopped: Must be sent to the tracker if the client is shutting down gracefully.
		completed: Must be sent to the tracker when the download completes. However, must not be sent if the download was already 100% complete when the client started. Presumably, this is to allow the tracker to increment the "completed downloads" metric based solely on this event.
	ip: Optional. The true IP address of the client machine, in dotted quad format or rfc3513 defined hexed IPv6 address. Notes: In general this parameter is not necessary as the address of the client can be determined from the IP address from which the HTTP request came. The parameter is only needed in the case where the IP address that the request came in on is not the IP address of the client. This happens if the client is communicating to the tracker through a proxy (or a transparent web proxy/cache.) It also is necessary when both the client and the tracker are on the same local side of a NAT gateway. The reason for this is that otherwise the tracker would give out the internal (RFC1918) address of the client, which is not routable. Therefore the client must explicitly state its (external, routable) IP address to be given out to external peers. Various trackers treat this parameter differently. Some only honor it only if the IP address that the request came in on is in RFC1918 space. Others honor it unconditionally, while others ignore it completely. In case of IPv6 address (e.g.: 2001:db8:1:2::100) it indicates only that client can communicate via IPv6.
	numwant: Optional. Number of peers that the client would like to receive from the tracker. This value is permitted to be zero. If omitted, typically defaults to 50 peers.
	key: Optional. An additional identification that is not shared with any other peers. It is intended to allow a client to prove their identity should their IP address change.
	trackerid: Optional. If a previous announce contained a tracker id, it should be set here.
	"""

	
	
	# connect to each peer and download file -- not necessary here
	
	choices = create_choices(t.peers)

	questions = [
		{
			'type': 'list',
			'name': 'peer',
			'message': 'Select a Peer to inspect',
			'choices': choices
		}
	]

	answers = prompt(questions)
	p = answers['peer']
	# using this endpoint because I don't want the hassle of
	# signing up for an account to use an SDK/library. Plus I would have
	# to securely store the API key.
	r = requests.get(f"https://geolocation-db.com/jsonp/{p['ip']}")
	"""
	sample ip_info
	{"country_code":"GB","country_name":"United Kingdom","city":null,"postal":null,"latitude":51.4964,"longitude":-0.1224,"IPv4":"185.21.216.139","state":null}
	"""
	ip_info = json.loads(r.text[0:-1].replace('callback(', "", 1))
	#print(ip_info)
	connection_info = f"Peer {p['ip']}:{p['port']} is in {ip_info['city']}, {ip_info['state']}, {ip_info['country_name']} at {ip_info['latitude']}, {ip_info['longitude']}"
	print(connection_info)
	print(t)
	c = Connection(t ,p['ip'],p['port'])
	c.do_handshake()
	time.sleep(10)
	print("calling download file")
	c.download_file()
	#exit()

	# we will connect to a single peer and download all pieces.


	# this is slower but is necessary to confirm the peer owns the whole file


	# for each file piece, write it to disk -- not necessary here
