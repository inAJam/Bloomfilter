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
			src_IP[cd_g_truth[tup][0]] = 1
	
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

def unique_flow_creator(flowset,EXP_flows,per_cent,pkt_count,flow_list):
	"""
	To craft unique malicious flows
	"""

	fl = flowset
	l=0
	k = 0
	pkt = 0
	mal_flows_unique = {}
	while l < math.ceil((EXP_flows*per_cent)/100):
		k+=1
		src_IP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
		dst_IP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
		src_port = random.randint(0,65535)
		dst_port = random.randint(0,65535)
		proto = random.choice([6, 17]) # TCP,UDP
		item = [str(src_IP),str(dst_IP),str(src_port),str(dst_port),str(proto)]
		flow = tuple(item)
		x = convert_to_hex(item)
		key = [a for a in x][0]
		if flow not in mal_flows_unique and flow not in flow_list and key in fl:
			mal_flows_unique[flow] = pkt_count[pkt]
			l+=1
			pkt = (pkt+1)%len(pkt_count)
		print("Iteration = %s | Items found = %s"%(k,l),end="\r")
	
	with open('unique_flows.csv', 'w',newline='') as csv_file:  
		writer = csv.writer(csv_file)
		for key, value in mal_flows_unique.items():
			writer.writerow([key, value])
	
	print("[+] Creation of unique mal flows successful...")
	return mal_flows_unique

def bucket(packet_size):
	packet_size.sort(reverse=True)
	x = int(len(packet_size)/3)
	i=0
	bucket = []
	while i <= len(packet_size):
		bucket.append(random.choice(packet_size[0:x]))
		bucket.append(random.choice(packet_size[x:2*x]))
		bucket.append(random.choice(packet_size[2*x:]))
		i+=3
	return bucket
			
def mal_flows_create(mal_flows,pkt_count):
	flow = {}
	i = 0
	for i in range(len(mal_flows)):
		flow[tuple(mal_flows[i])] = pkt_count[i]
		i = (i+1)%len(pkt_count)
	return flow

def bloomfilter():
	EXP_FLOWS = 24725
	fpr = 0.01
	CT_hash = 4
	per_cent = float(input("Enter percentage of flows to be crafted: "))
	f = '400k_pkts.pcap'
	fl = Flowset(EXP_FLOWS,fpr,CT_hash)
	mal_fl = Flowset(EXP_FLOWS,fpr,CT_hash)
	g_truth,flowset = insert_flows(f,{},0,fl,'ground.csv')

	src,flow_list,pkt_size = find_srclist(g_truth)
	bucket_pkt = bucket(pkt_size)
	mal_flowset = attackers_BF(mal_fl,src,f)
	mal_flows = unique_flow_creator(mal_flowset,EXP_FLOWS,per_cent,bucket_pkt,flow_list)

	final = Flowset(EXP_FLOWS,fpr,CT_hash)
	final_mal_truth,en_mal_flowset = insert_flows(f,mal_flows,per_cent,final,'corrupted.csv')
	Decode(en_mal_flowset)


if __name__ == "__main__":
	bloomfilter()
