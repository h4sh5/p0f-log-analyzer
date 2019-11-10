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
	last_seen,
	apps,
	http_sigs,
	langs

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

			# fill in distance info
			if not global_data[ip].get("distances"):
				global_data[ip]["distances"] = []
				if dist != "???":
					global_data[ip]["distances"].append(dist)
			else:
				if dist not in global_data[ip].get("distances") and dist != "???":
					global_data[ip]["distances"].append(dist)

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

		elif "http" in mod:
			app = line.split("|")[4].split("=")[1]
			lang = line.split("|")[5].split("=")[1]
			
			if app != "???" and app != "none":
				if not global_data[ip].get("apps"):
					global_data[ip]["apps"] = [app]
				else:
					update_list(global_data[ip]["apps"], app)

			if lang != "none":
				if not global_data[ip].get("langs"):
					global_data[ip]["langs"] = [lang]
				else:
					update_list(global_data[ip]["langs"], lang)

			http_sig = line.split(":")[-1]
			if not global_data[ip].get("http_sigs"):
				global_data[ip]["http_sigs"] = [http_sig]
			else:
				update_list(global_data[ip]["http_sigs"], http_sig)




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


for k in global_data:
	print(json.dumps({k: global_data[k]}, indent=4, sort_keys=True))

sys.stderr.write("total IPs found: " + str(len(global_data)) + "\n")

