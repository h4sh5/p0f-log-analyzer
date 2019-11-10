#!/usr/bin/env python
'''
a simple python script to analyze p0f logs

p0f-log-analyzer.py  Copyright (C) 2019  Haoxi Tan

'''

import sys
import json


usage = "%s <path to log>" % sys.argv[0]

if (len(sys.argv) < 1):
	print (usage)
	exit(1)

'''
structure of data storage:

dict = { IP : dict{
	types (cli|srv) [],
	ports[],
	os_matches[],
	links[],
	mtus[],
	distances[],
	uptimes,
	raw_freqs,
	first_seen,
	last_seen
	}
}}

'''

global_data = {}

global_mode = sys.argv[1]


def update_list(l, item):
	if item not in l:
		l.append(item)


with open(sys.argv[1]) as f:
	for line in f:
		mod = line.split("|")[0].split("=")[1]
		subj = line.split("|")[3].split("=")[1]
		if subj == "cli":
			ip = line.split("|")[1].split("/")[0].split("=")[1]
			port = line.split("|")[1].split("/")[1]
		else:
			ip = line.split("|")[2].split("/")[0].split("=")[1]
			port = line.split("|")[2].split("/")[1]


		if not global_data.get(ip):
			global_data[ip] = {}

		if "syn" in mod: #TCP mode
			os = line.split("|")[4].split("=")[1]
			dist = line.split("|")[5].split("=")[1].rstrip()

			# fill in type info (cli/srv)
			if not global_data[ip].get("types"):
				global_data[ip]["types"] = [subj]
			else:
				if subj not in global_data[ip].get("types"):
					global_data[ip]["types"].append(subj)

			# fill in OS info
			if not global_data[ip].get("os_matches"):
				global_data[ip]["os_matches"] = []
				if os != "???":
					global_data[ip]["os_matches"].append(os)
			else:
				if os not in global_data[ip].get("os_matches") and os != "???":
					global_data[ip]["os_matches"].append(os)

		elif "mtu" in mod: #mod is mtu
			link = line.split("|")[4].split("=")[1]
			mtu = line.split("|")[5].split("=")[1].rstrip()
			if not global_data[ip].get("links"):
				global_data[ip]["links"] = [link]
			else:
				update_list(global_data[ip]["links"], link)

			if not global_data[ip].get("mtus"):
				global_data[ip]["mtus"] = [mtu]
			else:
				update_list(global_data[ip]["mtus"], mtu)


		elif "uptime" in mod:
			uptime = line.split("|")[4].split("=")[1]
			raw_freq = line.split("|")[5].split("=")[1].rstrip()
			if not global_data[ip].get("uptimes"):
				global_data[ip]["uptimes"] = [uptime]
			else:
				update_list(global_data[ip]["uptimes"], uptime)

			if not global_data[ip].get("raw_freqs"):
				global_data[ip]["raw_freqs"] = [raw_freq]
			else:
				update_list(global_data[ip]["raw_freqs"], raw_freq)

		if not global_data[ip].get("first_seen"):
			global_data[ip]["first_seen"] = line.split("]")[0].replace('[','')

		last_seen =  line.split("]")[0].replace('[','')
		if not global_data[ip].get("last_seen"):
			global_data[ip]["last_seen"] = last_seen
		elif global_data[ip].get("last_seen") != last_seen:
			# update last seen
			global_data[ip]["last_seen"] = last_seen

		# print (ip, global_data[ip])

# summary

print ("total IPs found:", len(global_data))
for k in global_data:
	print(json.dumps({k: global_data[k]}, indent=4, sort_keys=True))



