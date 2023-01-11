from scapy.all import *

def bucket_details(bucket):
	print("max : ",bucket[0])
	print("min : ",bucket[-1])
	print("count :",len(bucket))
	mean = sum(bucket)/len(bucket)
	c = {}
	c[5] = 0
	c[10] = 0
	c[100] = 0
	c[1000] = 0
	c[10000] = 0
	c[1000000] = 0
	x = 0
	for i in range(len(bucket)):
		x+=(mean-bucket[i])**2
		if bucket[i] <6 :
			c[5]+=1
		elif bucket[i] < 11:
			c[10]+=1
		elif bucket[i] < 101:
			c[100]+=1
		elif bucket[i] < 1001:
			c[1000]+=1
		elif bucket[i] < 10001:
			c[10000]+=1
		else:
			c[1000000]+=1
		
	for i in c:
		print(i,"->",c[i])
	
	x = (x/len(bucket))**0.5
	print("Avg :",mean)
	print("deviation :",x)

def packet_check(path):
	pkt_count = 0
	flows = {}
	flow_ip_v4 = {}
	flow_ip_v6 = {}
	for packet in PcapReader(path):
		pkt_count +=1
		if IP in packet and TCP in packet:
			flow = tuple([packet[IP].src, packet[IP].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IP].proto)])
			if flow not in flows:
				flows[flow] = 0
			flows[flow] +=1
			src_ip = packet[IP].src
			if src_ip not in flow_ip_v4:
				flow_ip_v4[src_ip] = 0
			flow_ip_v4[src_ip]+=1
		

		elif IP in packet and UDP in packet:
			flow = tuple([packet[IP].src, packet[IP].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IP].proto)])
			if flow not in flows:
				flows[flow] = 0
			flows[flow] +=1
			src_ip = packet[IP].src
			if src_ip not in flow_ip_v4:
				flow_ip_v4[src_ip] = 0
			flow_ip_v4[src_ip]+=1
		
		
		elif IPv6 in packet and TCP in packet:
			flow = tuple([packet[IPv6].src, packet[IPv6].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IPv6].nh)])
			if flow not in flows:
				flows[flow] = 0
			flows[flow] +=1
			src_ip = packet[IPv6].src
			if src_ip not in flow_ip_v6:
				flow_ip_v6[src_ip] = 0
			flow_ip_v6[src_ip]+=1
		
		
		elif IPv6 in packet and UDP in packet:
			flow = tuple([packet[IPv6].src, packet[IPv6].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IPv6].nh)])
			if flow not in flows:
				flows[flow] = 0
			flows[flow] +=1
			src_ip = packet[IPv6].src
			if src_ip not in flow_ip_v6:
				flow_ip_v6[src_ip] = 0
			flow_ip_v6[src_ip]+=1
		
		
		elif IP in packet and UDP not in packet and TCP not in packet:
			flow = tuple([packet[IP].src, packet[IP].dst, str("0"), str("0"), str(packet[IP].proto)])
			if flow not in flows:
				flows[flow] = 0
			flows[flow] +=1
			src_ip = packet[IP].src
			if src_ip not in flow_ip_v4:
				flow_ip_v4[src_ip] = 0
			flow_ip_v4[src_ip]+=1
		
		
		elif IPv6 in packet and UDP not in packet and TCP not in packet:
			flow = tuple([packet[IPv6].src, packet[IPv6].dst, str("0"), str("0"), str(packet[IPv6].nh)])
			if flow not in flows:
				flows[flow] = 0
			flows[flow] +=1
			src_ip = packet[IPv6].src
			if src_ip not in flow_ip_v6:
				flow_ip_v6[src_ip] = 0
			flow_ip_v6[src_ip]+=1
		
		print("[+] Packets analyses = %s "%(pkt_count),end="\r")
		
	print("\nTotal number of unique flows: ",len(flows))
	print("for ipv4...")
	src = sorted(flow_ip_v4,key=flow_ip_v4.get)[-1:][0]
	print("Source IP: ",src,"->",flow_ip_v4[src])
	print("for ipv6...")
	#src = sorted(flow_ip_v6,key=flow_ip_v6.get)[-1:][0]
	#print("Source IP: ",src,"->",flow_ip_v6[src])
	
	pkt_sz = []
	for i in flows:
		pkt_sz.append(flows[i])
	pkt_sz.sort(reverse=True)
	x = int(len(pkt_sz)/3)
	print(pkt_sz[:20])
	bucket_1 = pkt_sz[:x]
	bucket_2 = pkt_sz[x:2*x]
	bucket_3 = pkt_sz[2*x:]
	print("length of buckets: \n1-> ",len(bucket_1),"\n2-> ",len(bucket_2),"\n3-> ",len(bucket_3))
	bucket_details(bucket_1)
	print("------------------------------")
	bucket_details(bucket_2)
	print("------------------------------")
	bucket_details(bucket_3)


packet_check('120k_chicago.pcap')