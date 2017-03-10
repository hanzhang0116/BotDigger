from __future__ import division
import optparse
import Levenshtein
import getopt
import socket
import dpkt, dpkt.dns
import sys
import subprocess
import datetime
import re
import math
import socket
import pythonwhois
import time
import smtplib
import numpy
from os import walk
from dnslib import *
from collections import *
from wordsegment import segment
from optparse import OptionParser
from netaddr import IPNetwork, IPAddress

threshCnC=10 # the number of CnC domains mapped to the same IP
threshIP=2 # the number of IPs mapped to the same CnC domain

def outputCnCIP(outputCnCIPFile, singleDomainMultiIPsDict):
	global threshIP
	fp = open(outputCnCIPFile, 'w')
	for CnC in singleDomainMultiIPsDict:
		IPset=singleDomainMultiIPsDict[CnC]
		if len(IPset)>=threshIP:
			fp.write("%s:\t" % (CnC))
			for IP in IPset:
				fp.write("%s," % IP)
			fp.write("\n")
	fp.close()

def outputIPCnC(outputIPCnCFile, singleIPMultiDomainsDict):
	global threshCnC
	fp = open(outputIPCnCFile, 'w')
	for IP in singleIPMultiDomainsDict:
		CnCset=singleIPMultiDomainsDict[IP]
		if len(CnCset)>=threshCnC:
			fp.write("%s:\t" % (IP))
			for CnC in CnCset:
				fp.write("%s," % CnC)
			fp.write("\n")
	fp.close()

def reduceFP(inputFile, singleIPMultiDomainsDict, singleDomainMultiIPsDict, whitelistSet):
	fp = open(inputFile, 'r')
	for line in fp:
		info = line.strip("\n").split(' ')
		CnC=info[2].strip(",")
		IP=info[4]
		if checkWhitelist(CnC, whitelistSet) == True:
			#sys.stdout.write("%s is ok\n" % CnC)
			continue
		#sys.stdout.write("%s, %s\n" % (CnC, IP))
		if CnC not in singleDomainMultiIPsDict:
			IPset=set()
			IPset.add(IP)
			singleDomainMultiIPsDict[CnC] = IPset
		else:
			IPset=singleDomainMultiIPsDict[CnC]
			IPset.add(IP)
			singleDomainMultiIPsDict[CnC] = IPset

		if IP not in singleIPMultiDomainsDict:
			CnCset=set()
			CnCset.add(CnC)
			singleIPMultiDomainsDict[IP] = CnCset
		else:
			CnCset=singleIPMultiDomainsDict[IP]
			CnCset.add(CnC)
			singleIPMultiDomainsDict[IP] = CnCset
	fp.close()

def loadWhitelist(whitelistFile, whitelistSet):
	fp = open(whitelistFile, 'r')
	for line in fp:
		info = line.strip("\n")
		#sys.stdout.write("%s\n" % info)
		whitelistSet.add(info)

def checkWhitelist(domain, whitelistSet):
	for whiteDomain in whitelistSet:
		if whiteDomain in domain:
			return True
	return False

def main(argv) :

	whitelistFile = ""
	whitelistSet = set()
	IPtoDomainDict = dict()
	DomaintoIPDict = dict()
	singleIPMultiDomainsDict = dict()
	singleDomainMultiIPsDict = dict()
	inputFile = ""
	outputIPCnCFile = ""
	outputCnCIPFile = ""

	parser = optparse.OptionParser()
	parser.add_option("-w", "--whitelist", action="store", type="string", dest="whitelistFile", help="specify the file that contains whitelist domains")
	parser.add_option("-i", "--input", action="store", type="string", dest="inputFile", help="specify the input file")
	parser.add_option("-o", "--outputIPCnC", action="store", type="string", dest="outputIPCnCFile", help="specify the output file")
	parser.add_option("-c", "--outputCnCIP", action="store", type="string", dest="outputCnCIPFile", help="specify the output file")
	(options, args) = parser.parse_args()

	# load required files
	if options.inputFile:
		inputFile = options.inputFile
	else:
		parser.error("input file not given, use -i")

	if options.outputIPCnCFile:
		outputIPCnCFile = options.outputIPCnCFile
	else:
		parser.error("output file not given, use -o")

	if options.outputCnCIPFile:
		outputCnCIPFile = options.outputCnCIPFile
	else:
		parser.error("output file not given, use -c")

	if options.whitelistFile:
		whitelistFile = options.whitelistFile
		loadWhitelist(whitelistFile, whitelistSet)
	else:
		parser.error("whitelist file not given, use -w")
		
	reduceFP(inputFile, singleIPMultiDomainsDict, singleDomainMultiIPsDict, whitelistSet)
	outputIPCnC(outputIPCnCFile, singleIPMultiDomainsDict)
	outputCnCIP(outputCnCIPFile, singleDomainMultiIPsDict)

	return

if __name__ == "__main__" :
	main(sys.argv[1:])

