
	BotDigger.py is a program to detect DGA-based bots using DNS traffic. It can be deployed in a single enterprise-like network. The inputs of BotDigger include pcap file or DNS log file following certain format (timestamp, source IP, source port, destination IP, destination port, DNS query/answer, DNS rcode, DNS qtype, queried domain).

Section I - Configuration:
	Three files have to be configured before running BotDigger, including DNSServerList, ExculedDomains, and ExculedHosts. These three files are used to specify local DNS servers, excluded domains, and excluded hosts, respectively. Notice that users need to follow the formats of these files when they change them.
	Besides commonly used python packages, BotDigger requires several packages installed, including wordsegment, python-Levenshtein, pythonwhois, dpkt, netaddr, and pypcap. You can install these packages seperately or simply run "sudo ./PackagesInstallation.sh" to install them all.

Section II - Included Files:
	BigCompanies: Fortune 500 companies' domains. The included domains will be used as whitelist.
	DNSServerList: local RDNS servers. Only the DNS packets sent from these local RDNS servers will be parsed and analyzed.
	DynamicDomains: websites that provide dynamic DNS (e.g, dyndns.org). The domains in these list will not be delivered to "unsuspicious domain filters", thus they are considered as "suspicious". 
	ExculedDomains: excluded domains. The included domains will be ignored and not analyzed. For example, if BotDigger is running in Colorado State University whose domain is colostate.edu, then put colostate.edu in file ExculedDomains.
	ExculedHosts: excluded hosts (e.g., mail servers, spamcanners).
	InvalidWords: invalid words of domains is InvalidWords, for example, ".local", ".wpad", "http:", etc.
	OverloadDNSWebsites: overloaded DNS query websites, for example, ".dnswl.org", ".spamhaus.org", etc.
	TLDList: all valid TLDs. Downloaded from http://www.iana.org/domains/root/db
	top-1m.csv: top 1 million popular websites from Alexa.com. The list can the downloaded from http://s3.amazonaws.com/alexa-static/top-1m.csv.zip. The top 1,000 domains in the file will be used as whitelist.
	wordsEn.txt: English dictionary words, which will be used for word segment. The file can be downloaded from http://www-01.sil.org/linguistics/wordlists/english/
	DomainsExistence-test: whether a domain exists

Section III - Usage:
Options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface=INTERFACE
                        specify the network interface (e.g., eth0)
  -f INPUTPCAPFILE, --inputpcap=INPUTPCAPFILE
                        specify the input pcap file
  -t TLDLISTFILE, --tld=TLDLISTFILE
                        specify the file that contains TLDs (e.g., file TLDList)
  -b BLWEBSITESFILE, --blwebsites=BLWEBSITESFILE
                        specify the file that contains websites providing
                        blacklist service (e.g., file OverloadDNSWebsites)
  -c CONFIGWORDSFILE, --configwords=CONFIGWORDSFILE
                        specify the file that contains the words to ignore (e.g., file InvalidWords)
  -s DNSSERVERFILE, --dnsserver=DNSSERVERFILE
                        specify the file that contains IPs of local RDNS (e.g., file DNSServerList)
  -p POPULARDOMAINFILE, --populardomain=POPULARDOMAINFILE
                        specify the file that contains popular domains (e.g., file top-1m.csv)
  -P PREFIX, --prefix=PREFIX
                        specify the local network prefix (e.g., "192.168.")
  -d DICTIONARYFILE, --dictionary=DICTIONARYFILE
                        specify the file that contains English dictionary (e.g., file wordsEn.txt)
  -o OFFLINEDOMAINFILE, --offlinefile=OFFLINEDOMAINFILE
                        specify the file that contains DNS information
						file format: each line in the file is a DNS query/response record, composed of 10 fields: timestamp, src_ip, src_port, dst_ip, dst_port, queryID, query(0)/response(1), return code, query type, queried domain. The fields are seperated by space. 
  -O OFFLINEDOMAINDIRECTORY, --offlinedirectory=OFFLINEDOMAINDIRECTORY
                        specify the directory that contains DNS files
						Each file should follow the format of ten fiends decribed above.
  -n DYNAMICDOMAINFILE, --dynamicdomains=DYNAMICDOMAINFILE
                        specify the file that contains dynamic domains (e.g., file DynamicDomains)
  -e BIGENTERPRISEFILE, --enterprises=BIGENTERPRISEFILE
                        specify the file that contains big enterprises (e.g., file BigCompanies)
  -x EXCLUDEDHOSTSFILE, --excludedhosts=EXCLUDEDHOSTSFILE
                        specify the file that contains hosts to exclude (e.g., file ExculedHosts)
  -D EXCLUDEDDOMAINSFILE, --excludeddomains=EXCLUDEDDOMAINSFILE
                        specify the file that contains domains to exclude (e.g., file ExculedDomains)
  -r RESULTSFILE, --resultsfile=RESULTSFILE
                        specify the output file or directory
						the file includes detected bot, clueters of queried suspicious NXDomains, and labeled C&C domains
  -R RECEIVER, --receiver=RECEIVER
                        specify the email receiver
						when the input data is offline files (pcap, DNS log), the email is sent when every input file is completely analyzed
						the email includes 1) the IP labeled as bot, 2) queried suspicious NXDomains, and 3) labaled C&C domains
  -T THRESHOLDSIMILARITY, --thresholdSimilarity=THRESHOLDSIMILARITY
                        specify the similarity threshold, the default value is 0.1.
  -B THRESHOLDBOTSONECLUSTER, --thresholdBotsOneCluster=THRESHOLDBOTSONECLUSTER
                        specify the bot cluster threshold, the default value is 4.
  -w TIMEINTERVAL, --timeWindow=TIMEINTERVAL
  						specify the time window (seconds) for bot detection, default value is 600 seconds
  -E SLDEXISTENCEFILE, --existingSLD=SLDEXISTENCEFILE
                        specify the file that contains existing SLDs
  -l, --enable2LDProbe  enbale 2LD probe, this generates lots of DNS queries, recommand to disable this when running BotDigger in real time

Example:
python DGABotDetection.py -B 4 -T 0.10 -w 300 -P "192.168." -R test@example.com -s DNSServerList -t TLDList -b OverloadDNSWebsites -c InvalidWords -p top-1m.csv -d wordsEn.txt -e BigCompanies -x ExculedHosts -D ExculedDomains -n DynamicDomains -f test.pcap -r temp-output
	- bot cluster threshold is 4
	- similarity threshold to cut the hierarchical clustering dendrogram is 0.1
	- time window is 300 seconds
	- send bot detection notice to test@example.com
	- File containing local RDNS servers is DNSServerList
	- File containing all TLDs is TLDList
	- File containing overloaded DNS query websites is OverloadDNSWebsites
	- File containing invalid words of domains is InvalidWords
	- File containing popular websites from Alexa is top-1m.csv
	- File containing dictionary words is wordsEn.txt
	- File containing big enterprise websites is BigCompanies
	- File containing excluded hosts (e.g., local mail servers) is ExculedHosts
	- File containing excluded domains is ExculedDomains
	- File containing websites that provide dynamic DNS is DynamicDomains
	- Input pcap file is test.pcap
	- Output log file is temp-output
