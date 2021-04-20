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
	# created with the help of 
	# https://wiki.theory.org/BitTorrentSpecification
	
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
