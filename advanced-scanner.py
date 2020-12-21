
#!usr/bin/python

from socket import *
import optparse
from threading import *


def portScanner(tgtHost, tgtPorts):
	try:
		tgtIp = gethostbyname(tgtHost)
	except:
		print('Cannot resolve target host {}. '.format(tgtHost))
	try:
		tgtName = getHostbyaddr(tgtIp)
		print('[*] Scan Results for {}: '.format(tgtName[0]))

	except:
		print('[*] Scan reults for {}: '.format(tgtIp))
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target = connectionScan, args=(tgtHost, int(tgtPort)))
		t.start()

def connectionScan(tgtHost, tgtPort):
	try:
		sock = socket(AF_INET, SOCK_STREAM)
		sock.connect((tgtHost, tgtPort))
		print("[*]{} TCP open.".format(tgtPort))
	except:
		print('[-] {} tcp closed. '.format(tgtPort))
	finally:
		sock.close()


def main(): 
	parser = optparse.OptionParser('Usage of porgram: ' + '-H <target host> -p <target ports>')
	parser.add_option('-H', dest='tgtHost', type='string', help = 'specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', help = 'specify target ports seperated by comma')
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	tgtPorts = str(options.tgtPort).split(',')
	if (tgtHost == None) | (tgtPorts[0] == None):
		print(parser.usage)
		exit(0)
	portScanner(tgtHost, tgtPorts)
if __name__ == '__main__':
	main()
