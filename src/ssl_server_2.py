import BaseHTTPServer, SimpleHTTPServer
import ssl
import sys

def start_ssl_server(ip_address, port, certfile_path):
	httpd = BaseHTTPServer.HTTPServer((ip_address, port), SimpleHTTPServer.SimpleHTTPRequestHandler)
	httpd.protocol_version = 'HTTP/1.1'
	httpd.socket = ssl.wrap_socket (httpd.socket, certfile=certfile_path, server_side=True)
	httpd.serve_forever()

if __name__ == "__main__":
   if len(sys.argv) != 4:
   		print "Usage: python ssl_server.py [ip_address] [port] [certfile_path]"
   else:
   		start_ssl_server(sys.argv[1], int(sys.argv[2]), sys.argv[3])
