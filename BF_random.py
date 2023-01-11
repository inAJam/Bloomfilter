from scapy.all import *
import csv
import random
import time
import tracemalloc
from flowRadar_v2 import *

def find_srclist(cd_g_truth):
	"""
	To find the src IP with the maximum number of flows and other related parameters
	"""

	flow_list = set()
	src_IP = {}
	pkt_size = []
	for tup in cd_g_truth:
		flow_list.add(tuple(cd_g_truth[tup][0:5]))
		pkt_size.append(float(cd_g_truth[tup][5]))
		if cd_g_truth[tup][0] in src_IP:
			src_IP[cd_g_truth[tup][0]] +=1
		else:
			src_IP[cd_g_truth[tup][0]] = 0
	
	src = sorted(src_IP,key=src_IP.get)[-1:][0]
	print("Source IP: ",src,"->",src_IP[src])
	return src,flow_list,pkt_size

def attackers_BF(flowset,src,path):
	"""
	The BF used by the attacker to craft the malicius packets
	"""
	fl = flowset
	mal_flows_normal = {}
	pkt_count = 0
	for pkt in PcapReader(path):
		if IP in pkt and pkt[IP].version == 4 and pkt[IP].src in src and (pkt[IP].proto == 6 or pkt[IP].proto == 17):
			if pkt[IP].proto == 6 or pkt[IP].proto == 17:
				protocol = 'TCP'
				if pkt[IP].proto==17:
					protocol = 'UDP'
				flow_ID = [pkt[IP].src,pkt[IP].dst,str(pkt[protocol].sport),str(pkt[protocol].dport),str(pkt[IP].proto)]
			else:
				flow_ID = [pkt[IP].src,pkt[IP].dst,'0','0',str(pkt[IP].proto)]
			fl.add_ct(flow_ID)
			k = tuple(flow_ID)
			pkt_count+=1
			if k not in mal_flows_normal:
				mal_flows_normal[k] = 0
			mal_flows_normal[k]+=1
	
	print("pkt_count: ",pkt_count)
	return fl

def read_from_file(filename,EXP_flows,per_cent):
	flow_list = []
	l = math.ceil(EXP_flows*per_cent/100)
	with open(filename, 'r') as file:
		csvreader = csv.reader(file)
		for row in csvreader:
			if len(flow_list)>=l:
				break
			x = re.findall("'(.*?)'",row[0])
			flow_list.append(x)
	if len(flow_list)>0:
		random.shuffle(flow_list)
	return flow_list

def unique_flow_creator(flowset,EXP_flows,per_cent,pkt_count,flow_list):
	"""
	To craft unique malicious flows
	"""

	mal_flows_unique = {}
	pkt = 0
	for i in range(len(flowset)):
		mal_flows_unique[tuple(flowset[i])] = random.choice(pkt_count)
	
	print("flow length: ",len(mal_flows_unique))
	
	with open('unique_flow_tuple.csv', 'w',newline='') as csv_file:  
		writer = csv.writer(csv_file)
		for key, value in mal_flows_unique.items():
			writer.writerow([key, value])
	
	print("[+] Creation of unique mal flows successful...")
	return mal_flows_unique

def bucket(packet_size):
	packet_size.sort(reverse=True)
	return packet_size

def bloomfilter():
	EXP_FLOWS = 24725
	fpr = 0.01
	CT_hash = 4
	per_cent = float(input("Enter percentage of flows to be crafted: "))
	f = '400k_pkts.pcap'
	fl = Flowset(EXP_FLOWS,fpr,CT_hash)
	g_truth,flowset = insert_flows(f,{},0,fl,'ground.csv')

	src,flow_list,pkt_size = find_srclist(g_truth)
	bucket_pkt = bucket(pkt_size)
	mal_flowset = read_from_file('unique_flows.csv',EXP_FLOWS,per_cent)
	mal_flows = unique_flow_creator(mal_flowset,EXP_FLOWS,per_cent,bucket_pkt,flow_list)

	final = Flowset(EXP_FLOWS,fpr,CT_hash)
	final_mal_truth,en_mal_flowset = insert_flows(f,mal_flows,per_cent,final,'corrupted.csv')
	Decode(en_mal_flowset)


if __name__ == "__main__":
	bloomfilter()