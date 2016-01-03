import os
import sys
import hashlib
import random
import httplib
import ssl
import subprocess
import signal
import time

#List of all the cipher suites for encryption
cipher_suites = ['RC4-SHA','AES128-GCM-SHA256','AES128-SHA', 'AES128-SHA256', 'AES256-GCM-SHA384', 'AES256-SHA', 'RSA-AES128-GCM-SHA256', 'AES256-SHA256','RSA-AES128-SHA']

#Read a directory structure and populate the URLs which can be accessed on the server
#@param root_dir_path : path at which the the ssl server was running
def walk_directory_paths_and_construct_url_path(root_dir_path):
	file_list = []
	skip_path_len = len(root_dir_path)
	if True == os.path.isdir(root_dir_path):
 		for root, subdirs, files in os.walk(root_dir_path):
 			for filename in files:
 				file_path = os.path.join(root, filename)
 				file_list.append(file_path[skip_path_len:])

 			for subdir in subdirs:
 				file_path = os.path.join(root, subdir)
 				file_list.append(file_path[skip_path_len:])

	print file_list
 	return file_list

#Pick a random number of urls 
#@param url_list : URL List containing all urls
#@param num_picks : Number of random requests to be picked
def pick_random_url(url_list, num_picks):
	number_urls = len(url_list)
	
	random_url_list = []

	while num_picks > 0:
		random_num = random.randrange(0, number_urls)
		random_url_list.append(url_list[random_num])
		num_picks = num_picks - 1

	return random_url_list

#Open a Secure HTTPS Connection and make requests
#@param serverip : Server IP Address
#@param serverport : Server Port Address
#@param clientip : Client ip to be used
#@param req_list : Request list to be made to the server
def make_requests_over_a_connection(serverip, serverport, clientip, req_list):
	try:
		conn = httplib.HTTPSConnection(serverip, serverport, source_address=(clientip, 0), context=ssl._create_unverified_context())
		conn.connect()
		req_remaining = len(req_list)
		req_num = 0

		while req_remaining > 0:
			print "Making Request"
			url = req_list[req_num]
			headers = {}
			headers['Accept'] = "*/*"
			headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36'
			headers['Host'] = serverip
			headers['Accept-Encoding'] = 'gzip, deflate, sdch'
			headers['Connection'] = 'Keep-Alive'
			conn.request("GET", url, headers=headers)
			r1 = conn.getresponse()
			req_remaining = req_remaining - 1
			req_num = req_num + 1

		#conn.close()
		return True
	except:
		e = sys.exc_info()[0]
		print e
		#conn.close()

	return False

#Start a capture in background
#@param interface : Interface name
#@param pcap_file_name : Name of the pcap file to be written
def start_capture_in_background(interface, pcap_file_name):
	try:
		print "Starting Capture"
		pcap_process = subprocess.Popen(['tcpdump', '-s', '65535', '-w', '/home/deeks/Desktop/new.pcap', '-i', interface, '-U'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		#Dont remove the sleep, this is because the tcpdump needs to start properly
		#Start generating the packets only after tcpdump has started
		time.sleep(5)
	except:
		e = sys.exc_info()[0]
		print e
	return pcap_process

#Stop the PCAP Capture started in the background
#@param pcap_process : Handle to the pcap process
def stop_capture(pcap_process):
	print "Stopping Capture"
	#Dont remove the sleep, this is because the tcpdump needs to buffer out the packets
	#This sleep makes sure that the buffered data is pushed out
	time.sleep(10)
	pcap_process.send_signal(signal.SIGINT)

#Merge required pcap files
#@param pcap_file_list : list of pcap files which needs to be merged
#@param merge_pcap_file_name : the name of the merged pcap file
def merge_pcaps(pcap_file_list, merge_pcap_file_name):
	input_file_list = ""
	index = 0
	while index < len(pcap_file_list):
		input_file_list = input_file_list + pcap_file_list[index] + " "
		index = index + 1

	p = subprocess.Popen(['mergecap', '-w', merge_pcap_file_name] + pcap_file_list,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output, errors = p.communicate()
	if len(output) > 0:
		print "Output: ", output
	if len(errors) > 0:
		print "Errors: ", errors
	print "Finished merging files"

#Replace source ip address in the pcap
#@param src_ip_address : Source IP address which needs to be replaced
#@param replace_ip_address : IP Address to be used for replacement
#@param input_file_name : Input pcap file
#@param output_file_name : Output pcap file to be generated
def rewrite_pcap_with_new_srcip_address(src_ip_address, replace_ip_address, input_file_name, output_file_name):
	src_ip_map = '--srcipmap=' + src_ip_address +'/32:' + replace_ip_address + '/32'
	in_file = '--infile=' + input_file_name
	out_file = '--outfile=' + output_file_name
##	cmd = 'tcprewrite' + src_ip_map + in_file + out_file
#	os.system(cmd)
	
	p = subprocess.Popen(['tcprewrite', src_ip_map, in_file, out_file],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output, errors = p.communicate()
	if len(output) > 0:
		print "Output: ", output
	if len(errors) > 0:
		print "Errors: ", errors
	print "Finished Replacing Source IP address"

#Replace destination ip address in the pcap
#@param dst_ip_address : Source IP address which needs to be replaced
#@param replace_ip_address : IP Address to be used for replacement
#@param input_file_name : Input pcap file
#@param output_file_name : Output pcap file to be generated
def rewrite_pcap_with_new_dstip_address(dst_ip_address, replace_ip_address, input_file_name, output_file_name):
	dst_ip_map = "--dstipmap=" + dst_ip_address +"/32:" + replace_ip_address + "/32"
	in_file = "--infile=" + input_file_name
	out_file = "--outfile=" + output_file_name
	p = subprocess.Popen(['tcprewrite', dst_ip_map, in_file, out_file],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output, errors = p.communicate()
	if len(output) > 0:
		print "Output: ", output
	if len(errors) > 0:
		print "Errors: ", errors
	print "Finished Replacing Destination IP address"


def spawn_n_servers(server_port, key_file, cert_file, index):
	bash_cmd = 'openssl s_server -key ' + key_file + ' -cert ' + cert_file + ' -WWW -cipher ' + cipher_suites[index] + ' -accept ' + server_port + ' &'
	print bash_cmd
	os.system(bash_cmd)
	

if __name__ == "__main__":
	tot_ser_cert_cnt = 1;
	cur_ser_cert_cnt = 0;
	server_port = 8442;
	while (cur_ser_cert_cnt < tot_ser_cert_cnt):
		
		cur_ser_cert_cnt +=1;
		server_key = '../certs/testkey_00' + str(cur_ser_cert_cnt) + '.pem'
		server_cert = '../certs/testcert_00' + str(cur_ser_cert_cnt) + '.pem'
		server_port += 1;
		server_cipher_index = 0;
	
		url_list = walk_directory_paths_and_construct_url_path('/home/deeks/Desktop/SSL_TASK/html_files')
		print url_list
		rand_no_of_urls = 3
		random_url_list = pick_random_url(url_list, rand_no_of_urls)
 		print random_url_list
		
		spawn_n_servers(str(server_port), server_key, server_cert, server_cipher_index);
		pcap_process = start_capture_in_background("lo", "/home/deeks/Desktop/abc.pcap")
		print "===============================\n"
		for url in random_url_list:	
			cmd = 'wget https://localhost:8443' + url + ' --no-check-certificate --bind-address 127.0.0.2'
			os.system(cmd)
			time.sleep(10)
			print cmd	
		stop_capture(pcap_process)
		#rewrite_pcap_with_new_srcip_address('127.0.0.2', '192.168.0.1', '/home/deeks/Desktop/new.pcap', '/home/deeks/Desktop/new.pcap')
		#rewrite_pcap_with_new_dstip_address('127.0.0.2', '192.168.0.1', '/home/deeks/Desktop/new.pcap', '/home/deeks/Desktop/new.pcap')
		#rewrite_pcap_with_new_dstip_address('127.0.0.1', '10.10.1.1', '/home/deeks/Desktop/new.pcap', '/home/deeks/Desktop/new.pcap')
		#rewrite_pcap_with_new_srcip_address('127.0.0.1', '10.10.1.1', '/home/deeks/Desktop/new.pcap', '/home/deeks/Desktop/new.pcap')

	
	#start_server("127.0.0.1", 443, "/home/deeks/Desktop/SSL_Task/OpenSSL/testkey.pem",  "/home/deeks/Desktop/SSL_Task/OpenSSL/testcert.pem");
	#pcap_process = start_capture_in_background("lo", "/home/deeks/Desktop/abc.pcap")
 	#make_requests_over_a_connection("127.0.0.1", 443, "127.0.0.1",random_url_list)
 	#time.sleep(50)
	#stop_capture(pcap_process)
 	#pcap_file_list = []
 	#pcap_file_list.append('1.pcap')
 	#pcap_file_list.append('2.pcap')
 	#pcap_file_list.append('3.pcap')

 	#merge_pcaps(pcap_file_list, "merged_pcap.pcap")
 	#rewrite_pcap_with_new_srcip_address('127.0.0.1','2.2.2.2', '2.pcap', '2_replace.pcap')
 	#print "Write Implementation"
