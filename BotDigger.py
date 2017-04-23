'''
BotDigger detects Domain Generation Algorithm based botnets based on DNS traffic
Copyright (C) <2015>  <Han Zhang>

BotDigger is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

BotDigger is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Contact information: 
	Email: zhanghan0116@gmail.com
'''

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
import pcap
import operator
import bz2
import gzip
import pylzma as xz
import zipfile
from os import walk
from dnslib import *
from collections import *
from wordsegment import segment
from optparse import OptionParser
from netaddr import IPNetwork, IPAddress


botDetected = 0
enableEmail = 0
enable2LDProbe = 0
enableVerbose = 0
localMaxSuspicious2LD = 2
timeInterval = 600	# time window
thresholdSuspiciousNXDOMAIN = 5
#thresholdDynamic = 3
timestampPeriodBegin = 0.0
thresholdDistance = 0.2
thresholdSimilarity = 0.1	# threshold for clustering algorithm
thresholdBotsOneCluster = 4
thresholdSignature = 16
temporalWindow = 5
receiver = ""
emailContents = ""
outputContentBot = ""
outputFilePrefix = ""
hostDict = dict()
botDict = dict()
tldDict = dict()
ccTldDict = dict()
nonCcTldDict = dict()
blWebsitesDict = dict()
dictionaryDict = dict()
configWordsDict = dict()
existingSLDDict = dict()
popularDomainDict = dict()
bigEnterpriseDict = dict()
excludedHostsDict = dict()
dynamicDomainDict = dict()
excludedDomainsDict = dict()
#allHostDict = dict()
#responseNXDomainDict = dict()
#responseSuspiciousNXDomainDict = dict()

# From http://www.networksorcery.com/enp/protocol/dns.htm    
type_table = {1:"A",        # IP v4 address, RFC 1035
			2:"NS",       # Authoritative name server, RFC 1035
			5:"CNAME",    # Canonical name for an alias, RFC 1035
			6:"SOA",      # Marks the start of a zone of authority, RFC 1035
			12:"PTR",      # Domain name pointer, RFC 1035
			13:"HINFO",    # Host information, RFC 1035
			15:"MX",       # Mail exchange, RFC 1035
			28:"AAAA",     # IP v6 address, RFC 3596
			}

# From http://www.garykessler.net/library/file_sigs.html
compressed_file_table = {
	"\x42\x5a\x68": "bz2",
	"\x1f\x8b\x08": "gz",
	"\xfd\x37\x7a\x58\x5a\x00": "xz",
	"\x50\x4b\x03\x04": "zip"
}

# Form http://stackoverflow.com/a/13044946/3934402
def file_type(filename):
	max_len = max(len(x) for x in compressed_file_table)
	with open(filename) as f:
		file_start = f.read(max_len)
	for magic, filetype in compressed_file_table.items():
		if file_start.startswith(magic):
			return filetype
	return None

def openFile(filename, modes):
	filetype = file_type(filename)
	if filetype is None:
		return open(filename, modes)
	elif filetype == "bz2":
		return bz2.BZ2File(filename)
	elif filetype == "gz":
		return gzip.open(filename)
	elif filetype == "xz":
		with open(filename, modes) as f:
			return xz.LZMAFile(f)
	elif filetype == "zip":
		return zipfile.ZipFile(filename)
	else:
		# should never get here
		raise LookupError("filetype is invalid")

class Host():
	def __init__(self):
		try:
			self.IP = ""
			self.startTime = 0
			self.startTimePeriod = 0
			self.endTime = 0
			self.labeled = 0
			self.noError = 0
			self.formatError = 0
			self.serverFail = 0
			self.NXDOMAIN = 0
			self.suspiciousNXDOMAIN = 0
			self.suspiciousNXDOMAIN2LD = 0
			self.notImplement = 0
			self.refused = 0
			self.noErrorDict = dict()
			self.formatErrorDict = dict()
			self.serverFailDict = dict()
			self.NXDOMAINDict = dict()
			self.suspiciousNXDOMAINDict = dict()
			self.suspiciousNXDOMAIN2LDDict = dict()
			self.suspiciousNXDOMAINPeriodDict = dict()
			self.notImplementDict = dict()
			self.refusedDict = dict()
			self.suspiciousNXDOMAINList = list()
			self.suspiciousNXDOMAINPeriodList = list()
			self.suspiciousNXDOMAINPeriodCountList = list()
		except:
			print "Failure Initializing Host"
			return None
	def __eq__(self, other): 
		if not isinstance(other, Host):
			raise NotImplementedError 
		return self.IP==other.IP

def initialize_tables() :
	global type_table

# functions to load files
def loadNetworkPrefix(networkPrefixFile, networkPrefixDict):
	with open(networkPrefixFile, 'r') as fp:
		for line in fp:
			info = line.strip('\n')
			networkPrefixDict[info] = None

def loadExcludedHosts(excludedHostsFile, excludedHostsDict):
	with open(excludedHostsFile, 'r') as fp:
		for line in fp:
			info = line.strip('\n').lower().split('\t')
			excludedHostsDict[info[0]] = None

def loadDictionary(dictionaryFile, dictionaryDict):
	with open(dictionaryFile, 'r') as fp:
		for line in fp:
			info = line.strip('\n').lower()
			if len(info) >= 3:
				dictionaryDict[info] = None

def loadBLWebsites(blWebsitesDict, blWebsitesFile):
	with open(blWebsitesFile, 'r') as fp:
		for line in fp:
			info = line.split()
			if info[0] not in blWebsitesDict:
				blWebsitesDict[info[0]] = None

def loadConfigWords(configWordsDict, configWordsFile):
	with open(configWordsFile, 'r') as fp:
		for line in fp:
			info = line.split()
			if info[0] not in configWordsDict:
				configWordsDict[info[0]] = None

def loadSLDExistence(sldExistenceFile, existingSLDDict):
	with open(sldExistenceFile, 'r') as fp:
		for line in fp:
			info = line.strip('\n').lower().split(' ')
			if len(info) >= 2:
				existingSLDDict[info[0]] = int(info[1])

def loadDynamicDomain(dynamicDomainDict, dynamicDomainFile):
	with open(dynamicDomainFile, 'r') as fp:
		for line in fp:
			info = line.strip("\n")
			if info not in dynamicDomainDict:
				dynamicDomainDict[info] = None

def loadDNSServer(dnsServerDict, dnsServerFile):
	with open(dnsServerFile, 'r') as fp:
		for line in fp:
			info = line.strip("\n")
			if info not in dnsServerDict:
				dnsServerDict[info] = None

def loadKnownTLD(tldDict, ccTldDict, nonCcTldDict, tldListFile):
	with open(tldListFile, 'r') as fp:
		for line in fp:
			info = line.split('\t')
			if info[0] not in tldDict:
				tldDict[info[0]] = None
			if "country" in info[1]:
				ccTldDict[info[0]] = None
			else:
				nonCcTldDict[info[0]] = None

def loadExludedDomains(excludedDomainsDict, excludedDomainsFile, tldDict, ccTldDict):
	with open(excludedDomainsFile, 'r') as fp:
		for line in fp:
			info = line.strip("\n")
			(domain2LD, domain3LD, domain2LDs, domain3LDs) = extractLevelDomain(info, ccTldDict, tldDict)
			if domain2LD not in excludedDomainsDict:
				excludedDomainsDict[domain2LD] = None

def loadBigEnterprises(bigEnterpriseDict, bigEnterpriseFile, tldDict, ccTldDict):
	with open(bigEnterpriseFile, 'r') as fp:
		for line in fp:
			info = line.strip("\n").split("\t")
			(domain2LD, domain3LD, domain2LDs, domain3LDs) = extractLevelDomain(info[2], ccTldDict, tldDict)
			if domain2LD not in bigEnterpriseDict:
				bigEnterpriseDict[domain2LD] = None

def loadPopularDomain(popularDomainDict, popularDomainFile, tldDict, ccTldDict):
	with open(popularDomainFile, 'r') as fp:
		lineCount = 0
		for line in fp:
			info = line.strip("\n").split(",")
			(domain2LD, domain3LD, domain2LDs, domain3LDs) = extractLevelDomain(info[1], ccTldDict, tldDict)
			lineCount = lineCount + 1
			if lineCount > 1000:	#consider the first 1,000 domains from Alexa
				break
			if domain2LD not in popularDomainDict:
				popularDomainDict[domain2LD] = None

#end of load fuctions

# filters to remove unsuspicious domains
def distanceDomain(domain, DomainDict, ccTldDict, tldDict):
	similarDomain = ""
	minDistance = sys.maxint
	level = domain.split(".")
	if len(level) <=1:
		return ("not a domain", sys.maxint)
	(domain2LD, domain3LD, domain2LDs, domain3LDs) = extractLevelDomain(domain, ccTldDict, tldDict)
	for popularDomain in DomainDict:
		distance = Levenshtein.distance(domain2LD.decode('utf-8'), popularDomain.decode('utf-8'))
		if distance < minDistance:
			minDistance = distance
			similarDomain = popularDomain
	#debug
	#sys.stdout.write("subdomain: %s, similarDomain: %s, minDistance: %d\n" % (subdomain, similarDomain, minDistance))
	if len(similarDomain) > 0:
		return (similarDomain, minDistance/float(len(similarDomain)))
	else:
		return (domain2LD, 0)

# check whether a domain contains invalid TLD
def searchTLDList(domain, tldDict):
	single = domain.split(".")
	singleDot = "." + single[len(single)-1]
	if singleDot in tldDict:
		#print domain, "has a known tld"
		return 1
	else:
		#print domain, "has an unknown tld"
		return 0

# check whether a domain contains overloaded DNS query
def searchBLWebsites(domain, blWebsitesDict):
	for website in blWebsitesDict:
		if website in domain:
			#print domain, "is used for overloaded DNS query"
			return 0
	return 1

# check whether a domain contains configuration words
def searchConfigWords(domain, configWordsDict):
	for configWord in configWordsDict:
		if configWord in domain:
			#print domain, "is related to configuration word:", configWord
			return 0
	return 1

# check whether a domain contains ".arpa"
def arpaNXDOMAIN(domain):
	if "in-addr.arpa" in domain:
		return 0
	elif "ip6.arpa" in domain:
		return 0
	else:
		return 1

# check whether a domain contains PC name, e.g., HAN-PC
# currently not used
def searchLocalPC(domain):
	return 1

# check whether a domain contains IP address, e.g., 1.2.3.4.example.com, 1-2-3-4.example.com
def searchIPDomain(domain):
	count1 = 0
	count2 = 0
	ipPattern = re.compile("[0-9]{1,3}")
	info1 = domain.split(".")
	for level1 in info1:
		if ipPattern.match(level1):
			count1 = count1 + 1
		else:
			count1 = 0
		if count1 == 4:
			#print domain, "contains an IP"
			return 0
		count2 = 0
		info2 = level1.split("-")
		for level2 in info2:
			if ipPattern.match(level2):
				count2 = count2 + 1
			else:
				count2 = 0
			if count2 == 4:
				#print domain, "contains an IP"
				return 0
	return 1

# check whether a domain contains repeated TLDs, e.g., www.example.com.foo.com
# need to improve
def searchRepeatTLD(domain, tldDict):
	count = 0
	start = 0
	firstSingle = 0
	count = 0
	repeatTld = ""
	level = domain.split(".")
	offset = 0
	if len(level) == 1:
		return 1

	for loop in range(0, len(level)):
		subdomain = "." + level[len(level)-1-loop]
		if subdomain in tldDict:
			if (loop != offset+1) and (loop != 0):
				return 0
			offset = loop
	return 1

	for single in level:
		count = count + 1
		if firstSingle == 0:
			firstSingle = 1
			continue
		dotSingle = "." + single
		dotSingleDot = "." + single + "."
		if dotSingle in tldDict:
			if dotSingle == level[len(level)-1]:
				return 0
			if dotSingleDot in domain[(domain.index(dotSingle)+1):]:
				return 0
	return 1	

# label whether a domain is suspicious
def labelSuspiciousDomain(domain, tldDict, ccTldDict):

	# ignore domain that contains overloaded DNS queries
	suspiciousDomain = 1
	if searchBLWebsites(domain, blWebsitesDict) == 0:
		suspiciousDomain = 0

	# ignore domain that contains invalid TLD
	if searchTLDList(domain, tldDict) == 0:
		suspiciousDomain = 0

	# ignore domain that contains repeated TLD
	if searchRepeatTLD(domain, tldDict) == 0:
		suspiciousDomain = 0

	# ignore domain that contains "in-addr.arpa/ip6.arpa"
	if arpaNXDOMAIN(domain) == 0:
		suspiciousDomain = 0
			
	# ignore domain that contains configuration words
	if searchConfigWords(domain, configWordsDict) == 0:
		suspiciousDomain = 0

	# ignore "local" (e.g., HAN-PC.colostate.edu.edu)
	if searchLocalPC(domain) == 0:
		suspiciousDomain = 0
	
	# ignore domain that contains an IP
	if searchIPDomain(domain) == 0:
		suspiciousDomain = 0

	# ignore domain that contains typo for popular domain
	(typoDomain, distance) = distanceDomain(domain, popularDomainDict, ccTldDict, tldDict)
	if distance <= thresholdDistance:
		suspiciousDomain = 0

	# ignore domain that contains typo for big enterprise domain
	(typoDomain, distance) = distanceDomain(domain, bigEnterpriseDict, ccTldDict, tldDict)
	if distance <= thresholdDistance:
		suspiciousDomain = 0

	# ignore domain that contains excluded domain or such typo (e.g., colostate)
	(typoDomain, distance) = distanceDomain(domain, excludedDomainsDict, ccTldDict, tldDict)
	if distance <= thresholdDistance:
		suspiciousDomain = 0
	return suspiciousDomain

# end of functions to label/remove suspicious domains

# functions of extract linguistic attributes from domains
def strEntropy(levelDomain):
	freq = 0.0
	entropy = 0.0
	normalizedEntropy = 0.0
	if len(levelDomain) == 0:
		return (0, 0)
	for character in set(levelDomain):
		freq = levelDomain.count(character)/float(len(levelDomain))
		if freq > 0:
			entropy = entropy - freq * math.log(freq, 2)
	if math.log(len(levelDomain), 2) > 0:
		normalizedEntropy = entropy/math.log(len(levelDomain), 2)
	#debug
	#sys.stdout.write("str: %s, entropy: %f, normalizedEntropy: %f\n" % (levelDomain, entropy, normalizedEntropy))
	return (entropy, normalizedEntropy)

def domainLevels(domain, ccTldDict, tldDict):
	domainLevel = 0
	info = domain.split(".")
	for dynamicDomain in dynamicDomainDict:
		if dynamicDomain in domain:
			infoDynamic = dynamicDomain.split(".")
			domainLevel = len(info) - len(infoDynamic)
			return domainLevel
	cc = "." + info[len(info)-1]
	if cc in ccTldDict:
		if len(info) >=2:
			tld = "." + info[len(info)-2]
			if tld in tldDict:
				# e.g., www.hello.example.com.cn
					domainLevel = len(info)-2
			else:
				# e.g., www.hello.example.cn
				domainLevel = len(info)-1
	else:
		# e.g., www.hello.example.com
		domainLevel = len(info)-1
	return domainLevel

def wordBreak(word, dictionaryDict):
	info = segment(word)
	length = 0
	for word in info:
		if word in dictionaryDict:
			length = length + len(word)
	return length

def extractLevelDomain(domain, ccTldDict, tldDict):
	domain2LD = ""
	domain3LD = ""
	domain2LDs = ""
	domain3LDs = ""
	info = domain.split(".")
	for dynamicDomain in dynamicDomainDict:
		dynamicDomainDot = "." + dynamicDomain
		if dynamicDomainDot in domain:
			infoDynamic = dynamicDomain.split(".")
			if len(info) >= len(infoDynamic) + 1:
				domain2LD = info[len(info)-len(infoDynamic) - 1]
				domain2LDs = domain2LD + dynamicDomainDot
			if len(info) >= len(infoDynamic) + 2:
				domain3LD = info[len(info)-len(infoDynamic) - 2]
				domain3LDs = domain3LD + "." + domain2LDs
			return (domain2LD, domain3LD, domain2LDs, domain3LDs)
	cc = "." + info[len(info)-1]
	if cc in ccTldDict:
		if len(info) >=2:
			tld = "." + info[len(info)-2]
			if tld in tldDict:
				# e.g., www.hello.example.com.cn
				if len(info) >= 3:
					domain2LD = info[len(info)-3]
					domain2LDs = domain2LD + "." + info[len(info)-2] + "." + info[len(info)-1]
				if len(info) >= 4:
					domain3LD = info[len(info)-4]
					domain3LDs = domain3LD + "." + domain2LDs
			else:
				# e.g., www.hello.example.cn
				domain2LD = info[len(info)-2]
				domain2LDs = domain2LD + "." + info[len(info)-1]
				if len(info) >= 3:
					domain3LD = info[len(info)-3]
					domain3LDs = domain3LD + "." + domain2LDs
	else:
		# e.g., www.hello.example.com
		if len(info) >=2:
			domain2LD = info[len(info)-2]
			domain2LDs = domain2LD + "." + info[len(info)-1]
		if len(info) >=3:
			domain3LD = info[len(info)-3]
			domain3LDs = domain3LD + "." + domain2LDs
	return (domain2LD, domain3LD, domain2LDs, domain3LDs)

# extract linguistic attributes from domain
def extractAttributes(domain, ccTldDict, tldDict, fpOutput):
	global enableVerbose 
	attibutesList = list()
	#if enableVerbose == 1:
	#	fpOutput.write("domain: %s\n" % domain)
	(domain2LD, domain3LD, domain2LDs, domain3LDs) = extractLevelDomain(domain, ccTldDict, tldDict)
	length2LD = len(domain2LD)
	length3LD = len(domain3LD)
	#if enableVerbose == 1:
	#	fpOutput.write("domain2LD: %s, domain3LD: %s\n" % (domain2LD, domain3LD))

	# 1,2: length of dictionanry words in 2LD and 3LD
	# 3,4: percent of dictionanry words in 2LD and 3LD
	meaningfulWordsLength2LD = wordBreak(domain2LD, dictionaryDict)
	meaningfulWordsLength3LD = wordBreak(domain3LD, dictionaryDict)
	if length2LD == 0:
		meaningfulWordsPercent2LD = 0
	else:
		meaningfulWordsPercent2LD = meaningfulWordsLength2LD/float(length2LD)
	if length3LD == 0:
		meaningfulWordsPercent3LD = 0
	else:
		meaningfulWordsPercent3LD = meaningfulWordsLength3LD/float(length3LD)
	attibutesList.append(meaningfulWordsLength2LD)
	attibutesList.append(meaningfulWordsLength3LD)
	attibutesList.append(meaningfulWordsPercent2LD)
	attibutesList.append(meaningfulWordsPercent3LD)
	#if enableVerbose == 1:
	#	fpOutput.write(" meaningfulWordsLength2LD: %d\n meaningfulWordsPercent2LD: %f\n meaningfulWordsLength3LD: %d\n meaningfulWordsPercent3LD: %f\n" % (meaningfulWordsLength2LD, meaningfulWordsPercent2LD, meaningfulWordsLength3LD, meaningfulWordsPercent3LD))

	# 5,6: the length of the longest meaningful substring in 2LD and 3LD
	# 7,8: percent of the length of the longest meaningful substring in 2LD and 3LD
	lengthLMS2LD = 0
	lengthLMS3LD = 0
	for word in dictionaryDict:
		if word in domain2LD:
			if len(word) > lengthLMS2LD:
				lengthLMS2LD = len(word)
	for word in dictionaryDict:
		if word in domain3LD:
			if len(word) > lengthLMS3LD:
				lengthLMS3LD = len(word)
	if length2LD == 0:
		percentLMS2LD = 0
	else:
		percentLMS2LD = lengthLMS2LD/float(length2LD)
	if length3LD == 0:
		percentLMS3LD = 0
	else:
		percentLMS3LD = lengthLMS3LD/float(length3LD)
	attibutesList.append(lengthLMS2LD)
	attibutesList.append(lengthLMS3LD)
	attibutesList.append(percentLMS2LD)
	attibutesList.append(percentLMS3LD)
	#if enableVerbose == 1:
	#	fpOutput.write(" lengthLMS2LD: %d\n percentLMS2LD: %f\n lengthLMS3LD: %d\n percentLMS3LD: %f\n" % (lengthLMS2LD, percentLMS2LD, lengthLMS3LD, percentLMS3LD))

	# 9,10,11,12: entropy, normalizedEntropy in 2LD and 3LD
	(entropy2LD, normalizedEntropy2LD) = strEntropy(domain2LD)
	(entropy3LD, normalizedEntropy3LD) = strEntropy(domain3LD)
	attibutesList.append(entropy2LD)
	attibutesList.append(normalizedEntropy2LD)
	attibutesList.append(entropy3LD)
	attibutesList.append(normalizedEntropy3LD)
	#if enableVerbose == 1:
	#	fpOutput.write(" entropy2LD: %f\n normalizedEntropy2LD: %f\n entropy3LD: %f\n normalizedEntropy3LD: %f\n" % (entropy2LD, normalizedEntropy2LD, entropy3LD, normalizedEntropy3LD))

	# 13: number of levels
	domainLevel = domainLevels(domain, ccTldDict, tldDict)
	attibutesList.append(domainLevel)
	#if enableVerbose == 1:
	#	fpOutput.write(" domainLevel: %d\n" % domainLevel)

	# 14, 15: length of 2LD and 3LD
	attibutesList.append(len(domain2LD))
	attibutesList.append(len(domain3LD))
	#if enableVerbose == 1:
	#	fpOutput.write(" length2LD: %d\n length3LD: %d\n" % (length2LD, length3LD))

	# 16, 17: number of distinct digital characters in 2LD and 3LD
	numberStr2LD = re.findall('\d', domain2LD)
	distinctNumbers2LD = len(set(numberStr2LD))
	numberStr3LD = re.findall('\d', domain3LD)
	distinctNumbers3LD = len(set(numberStr3LD))
	attibutesList.append(distinctNumbers2LD)
	attibutesList.append(distinctNumbers3LD)
	#if enableVerbose == 1:
	#	fpOutput.write(" distinctNumbers2LD: %d\n distinctNumbers3LD: %d\n" % (distinctNumbers2LD, distinctNumbers3LD))

	# 18, 19: percent of distinct digital characters in 2LD and 3LD
	if length2LD == 0:
		distinctNumbers2LDPercent = 0
	else:
		distinctNumbers2LDPercent = distinctNumbers2LD/float(length2LD)
	if length3LD == 0:
		distinctNumbers3LDPercent = 0
	else:
		distinctNumbers3LDPercent = distinctNumbers3LD/float(length3LD)
	attibutesList.append(distinctNumbers2LDPercent)
	attibutesList.append(distinctNumbers3LDPercent)
	#if enableVerbose == 1:
	#	fpOutput.write(" uniqueNumbers2LD: %d\n uniqueNumbers2LDPercent: %f\n uniqueNumbers3LD: %d\n uniqueNumbers3LDPercent: %f\n" % (distinctNumbers2LD, distinctNumbers2LDPercent, distinctNumbers3LD, distinctNumbers3LDPercent))

	# 20, 21: number of distinct characters in 2LD and 3LD
	distinctChar2LD = len(set(re.sub("[0-9]", "", domain2LD)))
	distinctChar3LD = len(set(re.sub("[0-9]", "", domain3LD)))
	attibutesList.append(distinctChar2LD)
	attibutesList.append(distinctChar3LD)
	#if enableVerbose == 1:
	#	fpOutput.write(" distinctChar2LD: %d\n distinctChar3LD: %d\n" % (distinctChar2LD, distinctChar3LD))

	# 22, 23: percent of distinct characters in 2LD and 3LD
	if length2LD == 0:
		distinctChar2LDPercent = 0
	else:
		distinctChar2LDPercent = distinctChar2LD/float(length2LD)
	if length3LD == 0:
		distinctChar3LDPercent = 0
	else:
		distinctChar3LDPercent = distinctChar3LD/float(length3LD)
	attibutesList.append(distinctChar2LDPercent)
	attibutesList.append(distinctChar3LDPercent)
	#if enableVerbose == 1:
	#	fpOutput.write(" distinctChar2LD: %d\n distinctChar2LDPercent: %f\n distinctChar3LD: %d\n distinctChar3LDPercent:%f\n" % (distinctChar2LD, distinctChar2LDPercent, distinctChar3LD, distinctChar3LDPercent))
	return attibutesList

# end of functions of extract linguistic attributes from domains

# update host information
def updateResponseDomain(hostDict, domain, qtype, rcode, ip, timestamp, domainIP, fpOutput):
	global tldDict
	global ccTldDict
	suspiciousDomain = 1
	domain = domain.lower()
	if qtype != 1:
		return
	if (rcode == 0):	
		hostDict[ip].noErrorDict[domain] = (timestamp, domainIP)

	if (rcode == 3):
		# filter non-malicious domains
		suspiciousDomain = labelSuspiciousDomain(domain, tldDict, ccTldDict)
		# update suspicious domain dict
		if suspiciousDomain == 1:
			#record the NXDomains queried by a host
			hostDict[ip].suspiciousNXDOMAIN = hostDict[ip].suspiciousNXDOMAIN + 1
			hostDict[ip].suspiciousNXDOMAINDict[domain] = timestamp
			hostDict[ip].suspiciousNXDOMAINList.append((domain, timestamp))
			if domain not in hostDict[ip].NXDOMAINDict:
				hostDict[ip].NXDOMAINDict[domain] = 1
			else:
				hostDict[ip].NXDOMAINDict[domain] = hostDict[ip].NXDOMAINDict[domain] + 1
			hostDict[ip].suspiciousNXDOMAINPeriodDict[domain] = 1
			hostDict[ip].endTime = timestamp
			(domain2LD, domain3LD, domain2LDs, domain3LDs) = extractLevelDomain(domain, ccTldDict, tldDict)
			if domain2LDs in hostDict[ip].suspiciousNXDOMAIN2LDDict:
				hostDict[ip].suspiciousNXDOMAIN2LDDict[domain2LDs] = timestamp
			else:
				hostDict[ip].suspiciousNXDOMAIN2LDDict[domain2LDs] = timestamp
				hostDict[ip].suspiciousNXDOMAIN2LD += 1

# functions for bot detection
def botDetection(host, fpOutput):
	global outputContentBot
	domainAttributesList = list()
	domainsList = list()

	# locate the time during when bot contacts C&C servers.
	# temporal feature 1: number of suspicious NXDomains increases quickly
	# temporal feature 2: number of suspicious NXDomains stops increasing
	(increaseStart, increaseEnd, increaseStartTimestamp) = increaseCUSUM(host, localMaxSuspicious2LD, thresholdBotsOneCluster, fpOutput)
	if (increaseStart != -1 ) and (increaseEnd != -1):
		(decreaseStart, decreaseEnd, decreaseEndTimestamp) = decreaseCUSUM(host, localMaxSuspicious2LD, thresholdBotsOneCluster, increaseStart, fpOutput)
		if decreaseStart >= increaseStart:
			if enableVerbose == 1:
				fpOutput.write("increase starts at offset %d, time: %f, decrease ends at offset %d, time: %f\n" % (increaseStart, increaseStartTimestamp, decreaseEnd, decreaseEndTimestamp))
		else:
			return
	else:
		if enableVerbose == 1:
			fpOutput.write("No temporal evidence found\n")
		return

	# focus on the suspicious NXDomains queried during the above time window
	for domain in host.suspiciousNXDOMAINDict:
		if (host.suspiciousNXDOMAINDict[domain] > increaseStartTimestamp-60) and (host.suspiciousNXDOMAINDict[domain] < decreaseEndTimestamp + 60):
			domainsList.append(domain)
	
	outputContentBot += "Suspicious NXDomains queried by %s:\n" % host.IP
	if enableVerbose == 1:
		fpOutput.write("Suspicious NXDomains queried by %s:\n" % host.IP)
	for domain in domainsList:
		outputContentBot += "%s\n" % domain
		if enableVerbose == 1:
			fpOutput.write("%s\n" % domain)
	domains = removeLegitimateDomains(domainsList, ccTldDict, tldDict, dynamicDomainDict, dictionaryDict)
	outputContentBot += "Suspicious NXDomains queried by %s after removing the ones containing registered 2LD\n" % host.IP
	if enableVerbose == 1:
		fpOutput.write("Suspicious NXDomains queried by %s after removing the ones containing registered 2LD\n" % host.IP)
	for domain in domains:
		outputContentBot += "%s\n" % domain
		if enableVerbose == 1:
			fpOutput.write("%s\n" % domain)
	
	if len(domains) < thresholdBotsOneCluster:
		if enableVerbose == 1:
			fpOutput.write("number of domains: %d is less than thresholdBotsOneCluster: %d\n" % (len(domains), thresholdBotsOneCluster))
		return

	similarityMatrix = [[0 for x in range(0, len(domains))] for x in range(0, len(domains))]

	for index in range (0, len(domains)):
		domainAttributes = extractAttributes(domains[index], ccTldDict, tldDict, fpOutput)
		domainAttributesList.insert(index, domainAttributes)
	for index1 in range (0, len(domains)):
		for index2 in range (index1+1, len(domains)):
			similarityMatrix[index1][index2] = similarityCalculation(domainAttributesList[index1], domainAttributesList[index2] )
			similarityMatrix[index2][index1] = similarityMatrix[index1][index2]

	# output the similarity matrix
	'''
	if enableVerbose == 1:
		for index1 in range (0, len(domains)):
			fpOutput.write("%d %s %f\n" %( index1, domains[index1], host.suspiciousNXDOMAINDict[domains[index1]]))
		for index1 in range (0, len(domains)):
			for index2 in range (0, len(domains)):
				fpOutput.write( "%3.3f " % similarityMatrix[index1][index2])
			fpOutput.write("\n")
	'''
	singleLinkageClustering(similarityMatrix, domains, host, fpOutput)

def singleLinkageClustering(similarityMatrix, domains, host, fpOutput):
	global enableVerbose
	global outputContentBot
	ip = host.IP
	index1 = 0
	index2 = 0
	pair1 = 0
	pair2 = 0
	loop = 0
	count = 0
	domainsOneCluster = 0
	mostDomainsOneCluster = 0
	mostDomainsClusterID = 0
	label = 1
	leastSimilarity = 2
	clusters = [0 for x in range(0, len(domains))]
	for loop in range(0, len(domains)):
		clusters[loop] = loop
	whileLoop = 0
	while (1):
		leastSimilarity = 1
		pair1 = 0
		pair2 = 0
		for index1 in range(0, len(domains)-1):
			for index2 in range(index1+1, len(domains)):
				if similarityMatrix[index1][index2] < leastSimilarity and clusters[index1] != clusters[index2]:
					leastSimilarity = similarityMatrix[index1][index2]
					pair1 = index1
					pair2 = index2
		if enableVerbose == 1:
			fpOutput.write("\nLeast Similarity is: %f between cluster %d and cluster %d\n" % (leastSimilarity, pair1, pair2))
		if leastSimilarity >= thresholdSimilarity: 
			if mostDomainsOneCluster >= thresholdBotsOneCluster:
				# check the existance of sld, how long it has been registered, and the contacts information
				outputContentBot += "Host %s is detected as suspicious based on the linguistic feature 1: %d suspicious NXDomains are clustered together since their similarity is less than %f\n" % (ip, mostDomainsOneCluster, thresholdSimilarity)
				outputContentBot += "The largest cluster has %d domains\n" % mostDomainsOneCluster
				fpOutput.write("Host %s is detected as suspicious based on the linguistic feature 1: %d suspicious NXDomains are clustered together since their similarity is less than %f\n" % (ip, mostDomainsOneCluster, thresholdSimilarity))
				fpOutput.write("The largest cluster has %d domains\n" % (mostDomainsOneCluster))
				detectCnC(clusters, domains, host, fpOutput)
				if ip in botDict:
					botDict[ip] = botDict[ip] + 1
				else:
					botDict[ip] = 1
			break
		if enableVerbose == 1:
			fpOutput.write("\nRound %d: Merge cluster %d and cluster %d\n" % (whileLoop + 1, clusters[pair1], clusters[pair2]))
		pair1Cluster = clusters[pair1]
		pair2Cluster = clusters[pair2]
		for loop in range(0, len(domains)):
			if (clusters[loop] == pair2Cluster):
				clusters[loop] = pair1Cluster
		if enableVerbose == 1:
			for loop in range(0, len(domains)):
				fpOutput.write("%d %s\n" % (clusters[loop], domains[loop]))
		count = 1
		for index1 in range(0, len(domains)):
			label = 0
			domainsOneCluster = 0
			for index2 in range(0, len(domains)):
				if clusters[index2] == index1:
					if label == 0:
						if enableVerbose == 1:
							fpOutput.write("\nCluster %d \n" % count)
						label = 1
						count = count + 1
					domainsOneCluster = domainsOneCluster + 1
					if enableVerbose == 1:
						fpOutput.write("domain: %d, %s\n" % (domainsOneCluster, domains[index2]) )
			if enableVerbose == 1:
				if domainsOneCluster > 0:
					fpOutput.write("\nThis cluster has %d domains\n" % domainsOneCluster)
			if domainsOneCluster > mostDomainsOneCluster:
				mostDomainsOneCluster = domainsOneCluster
		whileLoop = whileLoop + 1
	return 0

# calculate similarity between two domains
def similarityCalculation(domain1AttributesList, domain2AttributesList):
	similarityScore = 0
	# calculate overall similarity
	attributeSimilarity = 0
	for i in range(0, len(domain1AttributesList)):
		if (float(domain1AttributesList[i]) == 0) and (float(domain2AttributesList[i]) == 0):
			attributeSimilarity = 0
		else:
			attributeSimilarity = abs(float(domain1AttributesList[i]) - float(domain2AttributesList[i]))/max(float(domain1AttributesList[i]), float(domain2AttributesList[i]))
		similarityScore = similarityScore + attributeSimilarity ** 2
	similarityScore = math.sqrt(similarityScore/len(domain1AttributesList))
	return similarityScore

# extract signatures from bot clusters of NXDomains
def extractSignature(NXDomainList, fpOutput):
	global enableVerbose
	attributesMatrix = []
	signatureLower = []
	signatureUpper = []
	signatureMin = []
	signatureMax = []
	for i in range(0,len(NXDomainList)):
		attributesMatrix.append(NXDomainList[i][1])
	meanArray = numpy.mean(attributesMatrix, axis=0)
	stdArray = numpy.std(attributesMatrix, axis=0)
	for i in range(0,len(attributesMatrix[0])):
		signatureLower.append(meanArray[i] - 3*stdArray[i])
		signatureUpper.append(meanArray[i] + 3*stdArray[i])
		signatureMin.append(min(item[i] for item in attributesMatrix))
		signatureMax.append(max(item[i] for item in attributesMatrix))
	if enableVerbose == 1:
		fpOutput.write("signatures\n")
		fpOutput.write("%s\n" % str(signatureLower))
		fpOutput.write("%s\n" % str(signatureUpper))
	return (signatureLower, signatureUpper, signatureMin, signatureMax)

# check whether a single domain matches the signature
def compareSignature(attributes, signatureLower, signatureUpper, signatureMin, signatureMax, fpOutput):
	count = 0
	for i in range(0, len(attributes)):
		#debug
		#sys.stdout.write("%d %d %f %f\n" % (len(record[2]), len(signatureMin), record[2][i], signatureMin[i]))
		if (attributes[i]>=signatureMin[i]) and (attributes[i]<=signatureMax[i]):
		#if (record[2][i]>=signatureLower[i]) and (record[2][i]<=signatureUpper[i]):
			count = count + 1
	return count

# extract signatures and then apply them on all the successfully resolved domains to detect C&C domain
def detectCnC(clusters, domains, host, fpOutput):
	global botDetected
	global enableEmail
	global receiver
	global emailContents
	global enableVerbose
	global outputContentBot
	lastTimestamp = 0
	firstTimestamp = 0
	botsAttributesTotalList = list()
	domainList = list()
	botsAttributesList = list()
	botsNXDomainList = list()
	for j in set(clusters):
		for i in range(0, len(domains)):
			if clusters[i] == j:
				domainList.append(domains[i])
				outputContentBot += "cluster: %d, domain: %s\n" % (j, domains[i])
				fpOutput.write("cluster: %d, domain: %s\n" % (j, domains[i]))
		if len(domainList) >= thresholdBotsOneCluster: 
			for domain in domainList:
				botsNXDomainList.append(domain)
				attributes = extractAttributes(domain, ccTldDict, tldDict, fpOutput)
				botsAttributesList.append([domain, attributes])
				botsAttributesTotalList.append([domain, attributes])
				if host.suspiciousNXDOMAINDict[domain] > lastTimestamp:
					lastTimestamp = host.suspiciousNXDOMAINDict[domain]
				if firstTimestamp == 0:
					firstTimestamp = host.suspiciousNXDOMAINDict[domain]
				if host.suspiciousNXDOMAINDict[domain] < firstTimestamp:
					firstTimestamp = host.suspiciousNXDOMAINDict[domain]
			(signatureLower, signatureUpper, signatureMin, signatureMax) = extractSignature(botsAttributesList, fpOutput)
		del botsAttributesList[:]
		del domainList[:]

	domainIP = ""
	CnCDetected = 0
	CnCDomain = ""
	CnCDomainList = list()
	signatureMatchCountMax = 0
	if enableVerbose == 1:
		fpOutput.write("host %s has %d noError domain\n" % (host.IP, len(host.noErrorDict)))
	for domain in host.noErrorDict.keys():
		signatureMatchCountMax = 0
		# apply the signatures on all the successfully resolved domains 60 seconds before and after the bot clusters
		if ((host.noErrorDict[domain][0] > firstTimestamp - 60) and (host.noErrorDict[domain][0] < lastTimestamp+60) and host.noErrorDict[domain][1]):
			#debug
			#fpOutput.write("domain: %s, timestamp: %f, firstTimestamp: %f, lastTimestamp: %f\n" % (domain, host.noErrorDict[domain][0], firstTimestamp-60, lastTimestamp+60))
			suspiciousDomain = labelSuspiciousDomain(domain, tldDict, ccTldDict)
			if suspiciousDomain == 0:
				continue
			CnCDomain = domain
			domainIP = host.noErrorDict[domain][1]
			(signatureLower, signatureUpper, signatureMin, signatureMax) = extractSignature(botsAttributesTotalList, fpOutput)
			attributes = extractAttributes(CnCDomain, ccTldDict, tldDict, fpOutput)
			signatureMatchCount = compareSignature(attributes, signatureLower, signatureUpper, signatureMin, signatureMax, fpOutput)
			#debug
			#fpOutput.write("CnC candidate domain: %s matchs %d signatures\n" % (CnCDomain, signatureMatchCount))
			if signatureMatchCount >= thresholdSignature:
				botDetected = 1
				if CnCDetected == 0:
					CnCDetected = 1
					outputContentBot += "Host %s is detected as bot based on linguistic feature 2: C&C domain is detected\n" % host.IP
					fpOutput.write("Host %s is detected as bot based on linguistic feature 2: C&C domain is detected\n" % host.IP)
				outputContentBot += "CnC domain: %s, IP: %s matches %d signature attributes\n" % (domain, domainIP, signatureMatchCount)
				fpOutput.write("CnC domain: %s, IP: %s matches %d signature attributes\n" % (domain, domainIP, signatureMatchCount))
				CnCDomainList.append(domain)
	if CnCDetected == 1:
		outputContentBot += "\n"
		outputFileBot = outputFilePrefix + "-Bot-%s" % host.IP
		with open(outputFileBot, 'a') as fpOutputBot:
			fpOutputBot.write("%s\n" % outputContentBot)
		emailContents = "Host: %s is labeled as bot during %s and %s\n\nQueried NXDomains:\n" % (host.IP, datetime.datetime.fromtimestamp(firstTimestamp-60).strftime('%Y-%m-%d %H:%M:%S'), datetime.datetime.fromtimestamp(lastTimestamp+60).strftime('%Y-%m-%d %H:%M:%S'))
		for domain in botsNXDomainList:
			emailContents = emailContents + "%s\n" % domain
		emailContents = emailContents + "\nLabeled C&C domains:\n"
		for domain in CnCDomainList:
			emailContents = emailContents + "%s\n" % domain
		if (botDetected == 1) and (enableEmail == 1):
			#sys.stdout.write("Email to send: %s\n" % emailContents)
			sendEmail(emailContents, receiver)
		botDetected = 0

def outlierNXDomain2LD(hostDict, fpOutput):
	global enableVerbose
	# if the number of hosts is very few, we consider all of them as outliers
	if len(hostDict) < 10:
		return 0
	count = 0
	SuspiciousNXDomain2LDArray = list()
	SuspiciousNXDomain2LDSum = 0
	outlierMatrix = list()
	if enableVerbose == 1:
		fpOutput.write("outlierNXDomain2LD\nhost number: %d\n" % len(hostDict))
	for host in hostDict:
		if enableVerbose == 1:
			if hostDict[host].suspiciousNXDOMAIN2LD > 0:
				fpOutput.write("%s %d\n" % (host, hostDict[host].suspiciousNXDOMAIN2LD))
		SuspiciousNXDomain2LDArray.append(hostDict[host].suspiciousNXDOMAIN2LD)
		SuspiciousNXDomain2LDSum = SuspiciousNXDomain2LDSum + hostDict[host].suspiciousNXDOMAIN2LD
	average = numpy.mean(SuspiciousNXDomain2LDArray)
	stddev = numpy.std(SuspiciousNXDomain2LDArray)
	if enableVerbose == 1:
		fpOutput.write("mean: %f, std: %f, threshold: %f\n" % (average, stddev, average+3*stddev))
	return average+3*stddev

# remove the domains whose 2LD is registered, we consider such domains are legitimate
# this function is NOT used if sldExistenceFile is not specified
def removeLegitimateDomains(domainsList, ccTldDict, tldDict, dynamicDomainDict, dictionaryDict):
	subdomain = ""
	domainCount = 0
	domainsListReturn = domainsList
	subdomainDict = dict()
	domainToDelList = list()
	for index in range(0, len(domainsList)):
		info = domainsList[index].split(".")
		(domain2LD, domain3LD, domain2LDs, domain3LDs) = extractLevelDomain(domainsList[index], ccTldDict, tldDict)
		subdomain = domain2LDs

		if subdomain not in dynamicDomainDict:
			wwwSubdomain = "www." + subdomain
			if (subdomain in existingSLDDict) or (wwwSubdomain in existingSLDDict):
				if (subdomain in existingSLDDict) and (existingSLDDict[subdomain] == 1):
					#sys.stdout.write("%s is in existingSLDDict and exists\n" % subdomain)
					domainToDelList.append(domainsList[index])
					#sys.stdout.write("remmove: %s\n" % domainsList[index])
				elif (wwwSubdomain in existingSLDDict) and (existingSLDDict[wwwSubdomain] == 1):
					#sys.stdout.write("%s is in existingSLDDict and exists\n" % subdomain)
					domainToDelList.append(domainsList[index])
					#sys.stdout.write("remmove: %s\n" % domainsList[index])
				#else:
					#sys.stdout.write("%s is in existingSLDDict but doesn't exist\n" % subdomain)

			else:
				#sys.stdout.write("%s is not in existingSLDDict\n" % subdomain)
				if enable2LDProbe == 1:
					existence1 = domainExistenceCheck(subdomain)
					existence2 = domainExistenceCheck(wwwSubdomain)
					if (existence1 == 1) or (existence2 == 1):
						domainToDelList.append(domainsList[index])
						#sys.stdout.write("remmove: %s\n" % domainsList[index])
					existingSLDDict[subdomain] = existence1
					existingSLDDict[wwwSubdomain] = existence2
	for domainToDel in domainToDelList:
		domainsListReturn.remove(domainToDel)
	return domainsListReturn

# check whether an IP is in local networks
def inPrefix(IP, networkPrefixDict):
	for prefix in networkPrefixDict:
		if IPAddress(IP) in IPNetwork(prefix):
			return 1
	return 0

# check whether a domain exists
def domainExistenceCheck(domain):
	try:
		host = socket.gethostbyname(domain)
		#sys.stdout.write("IP: %s\n" % host)
		return 1
	except socket.gaierror, err:
		#print "cannot resolve hostname: ", domain, err
		#sys.stdout.write("IP not found\n")
		return 0

# this function is currently NOT used
def removeDynamicDomains(domainsList, ccTldDict, tldDict, dynamicDomainDict):
	domainCount = 0
	subdomain = ""
	domainsListReturn = domainsList
	subdomainList = dict()
	domainToDelList = list()
	for index in range(0, len(domainsList)):
		info = domainsList[index].split(".")
		(domain2LD, domain3LD, domain2LDs, domain3LDs) = extractLevelDomain(domainsList[index], ccTldDict, tldDict)
		subdomain = domain2LDs
		if subdomain in subdomainList:
			subdomainList[subdomain] = subdomainList[subdomain] + 1
		else:
			subdomainList[subdomain] = 1
				#sys.stdout.write("subdomain: %s\n" % subdomain)
	for subdomain in subdomainList:
		if subdomain in dynamicDomainDict:
			#sys.stdout.write("dynamic domain: %s\n" % subdomain)
			continue
		if subdomainList[subdomain] >= thresholdDynamic:
			for domain in domainsListReturn:
				if subdomain in domain:
					domainToDelList.append(domain)
	for domainToDel in domainToDelList:
		domainsListReturn.remove(domainToDel)
				
	return domainsListReturn

# end of functions for bot detection


def hexify(x):
	"The strings from DNS resolver contain non-ASCII characters - I don't know why.  This function investigates that"
	toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
	return toHex(x)

def singleDNSFileDetection(dnsServerDict, networkPrefixDict, inputFile, fpOutput):
	global timestampPeriodBegin
	timestampPeriodBegin = 0
	domainIP = ""
	with open(inputFile, 'r') as fpInput:
		print inputFile
		offlineHost = Host()
		for dnsServer in dnsServerDict:
			sys.stdout.write("DNS Server: %s\n" % dnsServer)
		for line in fpInput:
			line = line.strip("\n")
			info = line.split(" ")
			if len(info) < 10:
				continue
			response = int(info[6])
			if response != 1:
				continue
			timestamp = float(info[0])
			srcIP = info[1]
			srcPort = info[2]
			dstIP = info[3]
			dstPort = info[4]
			rcode = int(info[7])
			qtype = int(info[8])
			domain = info[9]
			if(len(info) == 11):
				domainIP = info[10]
			if (srcIP in dnsServerDict) :
				#if (prefix not in dstIP):
				if inPrefix(dstIP, networkPrefixDict) == 0:
					continue
				ip = dstIP
			if (dstIP in dnsServerDict) :
				#if (prefix not in srcIP):
				if inPrefix(srcIP, networkPrefixDict) == 0:
					continue
				ip = srcIP
			if (srcIP not in dnsServerDict) and (dstIP not in dnsServerDict):
				continue
			if timestampPeriodBegin == 0:
				timestampPeriodBegin = timestamp
			if(timestamp - timeInterval > timestampPeriodBegin):
				timeoutDetection(hostDict, fpOutput)
				cleanHostDict(hostDict, ccTldDict, tldDict, dynamicDomainDict)
				timestampPeriodBegin = timestampPeriodBegin + timeInterval
			if ip not in hostDict:
				newHost = Host()
				newHost.IP = ip
				newHost.startTime = timestamp
				newHost.endTime = timestamp
				hostDict[ip] = newHost
			updateResponseDomain(hostDict, domain, qtype, rcode, ip, timestamp, domainIP, fpOutput)

def singlePcapDetection(pc, fpOutput, dnsServerDict, networkPrefixDict):
	global timestampPeriodBegin
	timestampPeriodBegin = 0
	domainIP = ""
	count = 0
	for ts, pkt in pc:
		count += 1
		#test for 1,000,000 packets
		#if count > 1000000:
		#	break
		try:
			eth = dpkt.ethernet.Ethernet(pkt)
			if eth.type == dpkt.ethernet.ETH_TYPE_IP :
				ip = eth.data
				src = ip.src
				dst = ip.dst
				time_date = datetime.datetime.fromtimestamp(ts)
				if ip.p == dpkt.ip.IP_PROTO_UDP :
					udp = ip.data
					sport = udp.sport
					dport = udp.dport
					data = udp.data
				elif ip.p == dpkt.ip.IP_PROTO_TCP :
					tcp = ip.data
					sport = tcp.sport
					dport = tcp.dport
					data = tcp.data
				else:
					continue
			else:
				continue
		except:
			continue

		if (dport == 53 or sport == 53):
			time_date = datetime.datetime.fromtimestamp(ts)
			# some packets have bad DNS data
			try:
				dns = dpkt.dns.DNS(data)
			except:
				continue
			# DNS responces
			if(dns.qr == dpkt.dns.DNS_R) :
				for qname in dns.qd :
					for rr in dns.ns:
						domainIP = extractDomainIP(rr)
					for rr in dns.an:
						domainIP = extractDomainIP(rr)
					for rr in dns.ar:
						domainIP = extractDomainIP(rr)
					src_ip = socket.inet_ntoa(src)
					dst_ip = socket.inet_ntoa(dst)
					if (src_ip in dnsServerDict) :
						#if (prefix not in dst_ip):
						if inPrefix(dst_ip, networkPrefixDict) == 0:
							continue
						ip = dst_ip
					if (dst_ip in dnsServerDict) :
						#if (prefix not in src_ip):
						if inPrefix(src_ip, networkPrefixDict) == 0:
							continue
						ip = src_ip
					if (src_ip not in dnsServerDict) and (dst_ip not in dnsServerDict):
						continue
					if timestampPeriodBegin == 0:
						timestampPeriodBegin = ts
					if(ts - timeInterval > timestampPeriodBegin):
						timeoutDetection(hostDict, fpOutput)
						cleanHostDict(hostDict, ccTldDict, tldDict, dynamicDomainDict)
						timestampPeriodBegin = timestampPeriodBegin + timeInterval
					if ip not in hostDict:
						newHost = Host()
						newHost.IP = ip
						newHost.startTime = ts
						newHost.endTime = ts
						hostDict[ip] = newHost
					updateResponseDomain(hostDict, qname.name, qname.type, dns.rcode, ip, ts, domainIP, fpOutput)

def decodeDname(question, dname):  # handle compression
	i = 0
	domain = ""
	while True:
		length = ord(dname[i])
		print "length: ", length
		if length > 63:  # compression?
			c_index = (length & 0x3f)*256 + ord(dname[i+1])
			print "c_index: ", c_index
			compressed, ii = decodeDname(question, question[c_index:])
			return (domain + compressed).lower(), i+2  
		if length == 0: break
		domain += dname[i+1:i+1+length] + "."
		i += length + 1
		#print "DOMAIN: ", domain
	return domain.lower(), i+1

def extractDomainIP(rr):
	r_type = rr.type
	r_data = rr.rdata
	ip = ""
	if r_type == dpkt.dns.DNS_A  :
		try:
			ip = socket.inet_ntoa(r_data)
			return ip
		except:
			return ip
	return ip

def cleanHostDict(hostDict, ccTldDict, tldDict, dynamicDomainDict):
	for ip in hostDict:
		hostDict[ip].noErrorDict.clear()
		hostDict[ip].formatErrorDict.clear()
		hostDict[ip].serverFailDict.clear()
		hostDict[ip].NXDOMAINDict.clear()
		hostDict[ip].suspiciousNXDOMAINDict.clear()
		hostDict[ip].suspiciousNXDOMAIN2LDDict.clear()
		hostDict[ip].notImplementDict.clear()
		hostDict[ip].refusedDict.clear()
		hostDict[ip].suspiciousNXDOMAIN = 0
		hostDict[ip].suspiciousNXDOMAIN2LD = 0
		hostDict[ip].suspiciousNXDOMAINPeriodDict.clear()
		del hostDict[ip].suspiciousNXDOMAINList[:]
	hostDict.clear()

def timeoutDetection(hostDict, fpOutput):
	global enableVerbose
	NXDomain2LDThreshold = outlierNXDomain2LD(hostDict, fpOutput)
	for ip in hostDict:
		if (len(hostDict[ip].suspiciousNXDOMAIN2LDDict.keys()) >= NXDomain2LDThreshold) and (hostDict[ip].labeled == 0):
			if ip in excludedHostsDict:
				#sys.stdout.write("host: %s is in the excluded hosts list\n" % ip)
				continue
			if enableVerbose == 1:
				fpOutput.write("Host %s is detected as suspicious based on quantity feature: This host is an outlier in terms of the number of suspicious NXDOMAIN 2LD: %d suspicious NXDOMAIN 2LD\n" % (ip, len(hostDict[ip].suspiciousNXDOMAIN2LDDict.keys())) )
			# debug output
			#if enableVerbose == 1:
			#	fpOutput.write("start time: %s, end time: %s\n" % (hostDict[ip].startTimePeriod, hostDict[ip].endTime))
			botDetection(hostDict[ip], fpOutput)

def increaseCUSUM(host, localMax, threshold, fpOutput):
	first = -1
	indexIncrease = 0
	indexDecrease = 0
	count = 0
	sumLast = 0
	sumCurrent = 0
	counterList = list()
	sorted2LDList = sorted(host.suspiciousNXDOMAIN2LDDict.items(), key=operator.itemgetter(1))
	if len(sorted2LDList) < 1:
		return (-1, -1, -1)
	timestampFirst = sorted2LDList[0][1]
	for item in sorted2LDList:
		# record the number of suspicious 2LD every 60 seconds
		if item[1] < timestampFirst + 60:
			count += 1
		else:
			counterList.append(count)
			count = 1
			timestampFirst = item[1]
	counterList.append(count)
	for i in range(0, len(counterList)):
		sumLast = 0
		sumCurrent = 0
		# check whether the number of suspicious 2LD increases in 5 minutes
		for j in range(0, 5):
			if i+j >= len(counterList):
				break
			sumCurrent = sumLast + math.fabs(counterList[i+j] - localMax)
			if (counterList[i+j] > localMax) and (first == -1):
				first = i+j
			if sumCurrent > threshold:
				if enableVerbose:
					fpOutput.write("increase change detected: offset %d-%d\n" % (first, i+j))
				return (first, i+j, sorted2LDList[0][1]+60*first)
			sumLast = sumCurrent
	return (-1, -1, -1)

def decreaseCUSUM(host, localMax, threshold, increaseEnd, fpOutput):
	indexIncrease = 0
	indexDecrease = 0
	decreaseStart = 0
	decreaseEnd = 0
	count = 0
	sumCurrent = 0
	timestampLastDomain = 0
	counterList = list()
	sorted2LDList = sorted(host.suspiciousNXDOMAIN2LDDict.items(), key=operator.itemgetter(1))
	if len(sorted2LDList) < 1:
		return (-1, -1, -1)
	timestampFirst = sorted2LDList[0][1]
	for item in sorted2LDList:
		timestampLastDomain = item[1]
		if item[1] < timestampFirst + 60:
			count += 1
		else:
			counterList.append(count)
			count = 1
			timestampFirst = item[1]
	counterList.append(count)
	if timestampPeriodBegin + timeInterval > timestampLastDomain:
		counterList.append(0)
	for i in range(increaseEnd+1, len(counterList)):
		sumCurrent = 0
		for j in range(0, temporalWindow):
			if i+j >= len(counterList):
				break
			sumCurrent = sumCurrent + math.fabs(counterList[i+j] - counterList[i+j-1])
			if sumCurrent > threshold:
				if enableVerbose == 1:
					fpOutput.write("decrease change detected: offset %d-%d\n" % (i, i+j))
				return (i, i+j, sorted2LDList[0][1]+60*(i+j))
	return (-1, -1, -1)

def sendEmail(emailContents, receiver):
	SERVER = "localhost"
	FROM = "admin@botdiggertest.com"
	TO = list()
	TO.append(receiver)
	#TO = ["botdiggeradmin@test.com"] # must be a list
	SUBJECT = "BotDigger Notice"
	TEXT = emailContents
	message = """\From: %s\nTo: %s\nSubject: %s\n\n%s""" % (FROM, ", ".join(TO), SUBJECT, TEXT)
	try:
		server = smtplib.SMTP(SERVER)
		server.sendmail(FROM, TO, message)
		server.quit()
		print "Successfully sent email"
	except:
		print "Error: unable to send email"

def main(argv) :

	global outputFilePrefix
	global botDetected
	global receiver
	global emailContents
	global enableEmail
	global enable2LDProbe
	global enableVerbose
	global timeInterval
	global thresholdSimilarity
	global thresholdBotsOneCluster
	totalResponsePkts = 0
	totalResponseDomains = 0
	totalQueryPkts = 0
	totalQueryDomains = 0
	prefixFile = ""
	interface = ""
	tldListFile = ""
	bigEnterpriseFile = ""
	dictionaryFile = ""
	offlineDomainFile = ""
	offlineDomainDirectory = ""
	bigEnterpriseFile = ""
	configWordsFile = ""
	popularDomainFile = ""
	dynamicDomainFile = ""
	blWebsitesFile = ""
	resultsFile = ""
	dnsServerFile = ""
	excludedDomainsFile = ""
	sldExistenceFile = ""
	inputpcapfile = ""
	inputpcapDir = ""
	dnsServerDict = dict()
	networkPrefixDict = dict()
	ip = ""

	parser = optparse.OptionParser()
	parser.add_option("-i", "--interface", action="store", type="string", dest="interface", help="specify the network interface")
	parser.add_option("-f", "--inputpcap", action="store", type="string", dest="inputpcapfile", help="specify the input pcap file")
	parser.add_option("-F", "--inputpcapDir", action="store", type="string", dest="inputpcapDir", help="specify the input pcap directory")
	parser.add_option("-t", "--tld", action="store", type="string", dest="tldListFile", help="specify the file that contains TLDs")
	parser.add_option("-b", "--blwebsites", action="store", type="string", dest="blWebsitesFile", help="specify the file that contains websites providing blacklist service")
	parser.add_option("-c", "--configwords", action="store", type="string", dest="configWordsFile", help="specify the file that contains the words to ignore")
	parser.add_option("-s", "--dnsserver", action="store", type="string", dest="dnsServerFile", help="specify the file that contains IPs of local RDNS")
	parser.add_option("-p", "--populardomain", action="store", type="string", dest="popularDomainFile", help="specify the file that contains popular domains")
	parser.add_option("-P", "--prefixFile", action="store", type="string", dest="prefixFile", help="specify the file including local network prefixes (e.g., NetworkPrefixes)")
	parser.add_option("-d", "--dictionary", action="store", type="string", dest="dictionaryFile", help="specify the file that contains dictionary")
	parser.add_option("-o", "--offlinefile", action="store", type="string", dest="offlineDomainFile", help="specify the file that contains DNS information")
	parser.add_option("-O", "--offlinedirectory", action="store", type="string", dest="offlineDomainDirectory", help="specify the directory that contains DNS files")
	parser.add_option("-n", "--dynamicdomains", action="store", type="string", dest="dynamicDomainFile", help="specify the file that contains dynamic domains")
	parser.add_option("-e", "--enterprises", action="store", type="string", dest="bigEnterpriseFile", help="specify the file that contains big enterprises")
	parser.add_option("-x", "--excludedhosts", action="store", type="string", dest="excludedHostsFile", help="specify the file that contains hosts to exclude")
	parser.add_option("-D", "--excludeddomains", action="store", type="string", dest="excludedDomainsFile", help="specify the file that contains domains to exclude")
	parser.add_option("-r", "--resultsfile", action="store", type="string", dest="resultsFile", help="specify the output file or directory")
	parser.add_option("-R", "--receiver", action="store", type="string", dest="receiver", help="specify the email receiver")
	parser.add_option("-E", "--existingSLD", action="store", type="string", dest="sldExistenceFile", help="specify the file that contains existing SLDs")
	parser.add_option("-T", "--thresholdSimilarity", action="store", type="float", dest="thresholdSimilarity", help="specify the similarity threshold, default value is 0.1")
	parser.add_option("-B", "--thresholdBotsOneCluster", action="store", type="int", dest="thresholdBotsOneCluster", help="specify the bot cluster threshold, default value is 4")
	parser.add_option("-w", "--timeWindow", action="store", type="int", dest="timeInterval", help="specify the time window for bot detection, default value is 600 seconds")
	parser.add_option("-l", "--enable2LDProbe", action="store_true", dest="enable2LDProbe", default=False, help="enbale 2LD probe, this generates lots of DNS queries, recommand to disable this when running BotDigger in real time")
	parser.add_option("-v", "--enableVerbose", action="store_true", dest="enableVerbose", default=False, help="verbose mode, analysis information is given for debugging")
	(options, args) = parser.parse_args()
	
	initialize_tables()

	#default is 0.1
	if options.thresholdSimilarity:			
		thresholdSimilarity = options.thresholdSimilarity

	#default is 4
	if options.thresholdBotsOneCluster:
		thresholdBotsOneCluster = options.thresholdBotsOneCluster

	#default is 10 minutes
	if options.timeInterval:
		timeInterval = options.timeInterval

	if options.prefixFile:
		prefixFile = options.prefixFile
		loadNetworkPrefix(prefixFile, networkPrefixDict)
	else:
		parser.error("network prefix not given, use -P")

	if options.dnsServerFile:
		dnsServerFile = options.dnsServerFile
		loadDNSServer(dnsServerDict, dnsServerFile)
	else:
		parser.error("DNS server file not given, use -s")

	if options.tldListFile:
		tldListFile = options.tldListFile
		loadKnownTLD(tldDict, ccTldDict, nonCcTldDict, tldListFile)
	else:
		parser.error("TLD file not given, use -t")

	if options.blWebsitesFile:
		blWebsitesFile = options.blWebsitesFile
		loadBLWebsites(blWebsitesDict, blWebsitesFile)
	else:
		parser.error("blWebsitesFile not given, use -b")

	if options.configWordsFile:
		configWordsFile = options.configWordsFile
		loadConfigWords(configWordsDict, configWordsFile)
	else:
		parser.error("configWordsFile not given, use -c")

	if options.dynamicDomainFile:
		dynamicDomainFile = options.dynamicDomainFile
		loadDynamicDomain(dynamicDomainDict, dynamicDomainFile)
	else:
		parser.error("dynamicDomainFile not given, use -n")

	if options.popularDomainFile:
		popularDomainFile = options.popularDomainFile
		loadPopularDomain(popularDomainDict, popularDomainFile, tldDict, ccTldDict)
	else:
		parser.error("popularDomainFile not given, use -p")

	if options.bigEnterpriseFile:
		bigEnterpriseFile = options.bigEnterpriseFile
		loadBigEnterprises(bigEnterpriseDict, bigEnterpriseFile, tldDict, ccTldDict)
	else:
		parser.error("bigEnterpriseFile not given, use -e")

	if options.dictionaryFile:
		dictionaryFile = options.dictionaryFile
		loadDictionary(dictionaryFile, dictionaryDict)
	else:
		parser.error("dictionaryFile not given, use -d")

	if options.excludedHostsFile:
		excludedHostsFile = options.excludedHostsFile
		loadExcludedHosts(excludedHostsFile, excludedHostsDict)
	else:
		parser.error("excludedHostsFile not given, use -x")

	if options.excludedDomainsFile:
		excludedDomainsFile = options.excludedDomainsFile
		loadExludedDomains(excludedDomainsDict, excludedDomainsFile, tldDict, ccTldDict)
	else:
		parser.error("excludedDomainsFile not given, use -D")

	if options.sldExistenceFile:
		sldExistenceFile = options.sldExistenceFile
		loadSLDExistence(sldExistenceFile, existingSLDDict)

	if options.resultsFile:
		resultsFile = options.resultsFile
	else:
		parser.error("output file/directory not given, use -r")

	if options.receiver:
		receiver = options.receiver
		enableEmail = 1

	if options.enable2LDProbe:
		enable2LDProbe = 1

	if options.enableVerbose:
		enableVerbose = 1

	if options.interface:
		interface = options.interface
		outputFile = resultsFile
		with open(outputFile, 'w') as fpOutput:
			sys.stdout.write("Monitoring the DNS traffic on interface: %s\n" % interface)
			pc = pcap.pcap(interface)
			singlePcapDetection(pc, fpOutput, dnsServerDict, networkPrefixDict)
			timeoutDetection(hostDict, fpOutput)
			cleanHostDict(hostDict, ccTldDict, tldDict, dynamicDomainDict)

	#offline detection using pcap files
	if options.inputpcapfile:
		inputpcapfile = options.inputpcapfile
		outputFile = resultsFile
		outputFilePrefix = resultsFile
		with open(outputFile, 'w') as fpOutput:
			with openFile(inputpcapfile, 'rb') as f:
				pc = dpkt.pcap.Reader(f)
				singlePcapDetection(pc, fpOutput, dnsServerDict, networkPrefixDict)
				print inputpcapfile
				timeoutDetection(hostDict, fpOutput)
				cleanHostDict(hostDict, ccTldDict, tldDict, dynamicDomainDict)

	#offline detection using pcap files in a directory
	if options.inputpcapDir:
		inputpcapDir = options.inputpcapDir
		for (dirpath, dirnames, filenames) in walk(inputpcapDir):
			filenames.sort()
			for filename in filenames:
				inputpcapfile = os.path.join(dirpath, filename)
				outputFile = resultsFile + filename + "-BotResults"
				print inputpcapfile
				print outputFile
				with open(outputFile, 'w') as fpOutput:
					with openFile(inputpcapfile, 'rb') as f:
						pc = dpkt.pcap.Reader(f)
						singlePcapDetection(pc, fpOutput, dnsServerDict, networkPrefixDict)
						timeoutDetection(hostDict, fpOutput)
						cleanHostDict(hostDict, ccTldDict, tldDict, dynamicDomainDict)

	#offline detection using DNS log files
	if options.offlineDomainDirectory:
		offlineDomainDirectory = options.offlineDomainDirectory
		#sys.stdout.write("%s\n", offlineDomainDirectory)
		for (dirpath, dirnames, filenames) in walk(offlineDomainDirectory):
			filenames.sort()
			for filename in filenames:
				inputFile = os.path.join(dirpath, filename)
				outputFilePrefix = resultsFile + filename
				outputFile = resultsFile + filename + "-BotResults"
				with open(outputFile, 'w') as fpOutput:
					singleDNSFileDetection(dnsServerDict, networkPrefixDict, inputFile, fpOutput)
					timeoutDetection(hostDict, fpOutput)
					cleanHostDict(hostDict, ccTldDict, tldDict, dynamicDomainDict)

	if options.offlineDomainFile:
		offlineDomainFile = options.offlineDomainFile
		outputFile = resultsFile
		outputFilePrefix = resultsFile
		with open(outputFile, 'w') as fpOutput:
			singleDNSFileDetection(dnsServerDict, networkPrefixDict, offlineDomainFile, fpOutput)
			timeoutDetection(hostDict, fpOutput)
			cleanHostDict(hostDict, ccTldDict, tldDict, dynamicDomainDict)	

	return

if __name__ == "__main__" :
	main(sys.argv[1:])

