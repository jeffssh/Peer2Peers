#!/usr/bin/env python3 
import json, random, requests
from torrent import Torrent
from connection import Connection
from PyInquirer import prompt, print_json


def create_choices(peers):
	choices = []
	for p in peers:
		choices.append({'name':f"{p['ip']}:{p['port']}",'value':p})
	return choices


if __name__ == "__main__" :
	# created with the help of 
	# https://wiki.theory.org/BitTorrentSpecification
	
	torrent_file = "ubuntu-20.04.2.0-desktop-amd64.iso.torrent"
	t = Torrent(torrent_file)	
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
	print(t)

	# using this endpoint because I don't want the hassle of
	# signing up for an account to use an SDK/library. Plus I would have
	# to securely store the API key. Found this while proxying their site
	r = requests.get(f"https://geolocation-db.com/jsonp/{p['ip']}")
	"""
	sample ip_info
	{"country_code":"GB","country_name":"United Kingdom","city":null,"postal":null,"latitude":51.4964,"longitude":-0.1224,"IPv4":"185.21.216.139","state":null}
	"""
	ip_info = json.loads(r.text[0:-1].replace('callback(', "", 1))
	connection_info = f"Peer {p['ip']}:{p['port']} is in {ip_info['city']}, {ip_info['state']}, {ip_info['country_name']} at {ip_info['latitude']}, {ip_info['longitude']}"
	print("Connecting to peer:", connection_info)
	c = Connection(t ,p['ip'],p['port'])
	c.do_handshake()
	c.download_file()