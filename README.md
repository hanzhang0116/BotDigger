# BotDigger: Detecting DGA Bots in a Single Network Using DNS Traffic

**BotDigger.py** is a program to detect DGA-based bots using DNS traffic. It can be
deployed in a single enterprise-like network. The inputs of BotDigger include
.pcap or DNS log files following certain format (timestamp, source IP,
source port, destination IP, destination port, DNS query/answer, DNS rcode, DNS
qtype, queried domain).

The design and implementation details can be found in our published paper [BotDigger][botdigger].

[botdigger]: http://www.cs.colostate.edu/~hanzhang/papers/BotDigger-TMA16.pdf

## Configuring BotDigger

There are several things that need to be configured before running
BotDigger:

1. Install [software dependencies](#software-dependencies)
2. (*optional*) Run BotDigger on the [sample trace file](#running-on-an-example-trace-file)
3. Configure [network information](#configure-network-information)
4. (*optional*) Configure BotDigger [parameters](#configure-botdigger-parameters)
5. Ready to run BotDigger

### Software Dependencies

BotDigger uses and has been tested with Python 2.7.x.

Several additional Python packages are required--you can install them
(local to the user) using the included `PackagesInstallation.sh` script,
or with your favorite package manager:

* dnslib
* dpkt
* netaddr
* pylzma
* pypcap
* python-Levenshtein
* pythonwhois
* wordsegment

### Configure Network Information

We need to give BotDigger some information about the network so that it
will know which data to analyze and which to ignore:

* `DNSServerList`: local DNS servers that local hosts make queries to
* `ExculedDomains`: domains to ignore as possible CnC domains
* `ExculedHosts`: local hosts to ignore in analysis as possible bots
* `NetworkPrefixes`: a list of local prefixes (CIDR format) to analyze
  for bots or bot activity

For example, if we had a network on various subnets (10.10.0.0/16 and
192.168.1.0/24), with multiple DNS servers (both local and global), and
several services running, the configuration files might look like the
following:

DNSServerList (users might use Google's or Level-3's DNS servers):
~~~~
4.2.2.1
8.8.8.8
192.168.1.1
10.10.0.1
~~~~

ExculedDomains (the following are known not to be CnC domains):
~~~~
wwww.localdomain
~~~~

ExculedHosts (the following are known not to be bot hosts):
~~~~
10.10.0.1
192.168.1.1
~~~~

NetworkPrefixes (only analyze queries coming from the following
prefixes):
~~~~
192.168.1.0/24
10.10.0.0/16
~~~~

### Configure BotDigger Parameters

There are several BotDigger parameters that will affect the accuracy and
precision of bot detection:

* bot cluster threshold (`-B`, default is 4)
* similarity threshold to cut the hierarchical clustering dendrogram
  (`-T`, default is 0.1)
* time window (`-w`, default is 600 seconds)

The parameters have been tuned for a large, diverse network (such as
  Colorado State University, with ~30K hosts).

For example, a time window (`-w`) of 600 seconds means that bots must
make enough DNS queries in that time period to be detected.
A greater time window might detect more bots, but might also increase
the number of false positives.

Similarly, you can tune BotDigger to be more aggressive in detection by
using a smaller bot cluster threshold (`-B`, minimum value is 2) and
increasing the similarity threshold (`-T`, maximum value is 1.0).

## Included Files

* BigCompanies: Fortune 500 companies' domains. The included domains
  will be used as whitelist.
* DNSServerList: local RDNS servers. Only the DNS packets sent from
  these local RDNS servers will be parsed and analyzed.
* DynamicDomains: websites that provide dynamic DNS (e.g, dyndns.org).
  The domains in these list will not be delivered to "unsuspicious
  domain filters", thus they are considered as "suspicious".
* ExculedDomains: excluded domains. The included domains will be ignored
  and not analyzed. For example, if BotDigger is running in Colorado
  State University whose domain is colostate.edu, then put colostate.edu
  in file ExculedDomains.
* ExculedHosts: excluded hosts (e.g., mail servers, spamcanners).
* InvalidWords: invalid words of domains is InvalidWords, for example,
  ".local", ".wpad", "http:", etc.
* OverloadDNSWebsites: overloaded DNS query websites, for example,
  ".dnswl.org", ".spamhaus.org", etc.
* TLDList: all valid TLDs. Downloaded from
  http://www.iana.org/domains/root/db
* top-1m.csv: top 1 million popular websites from Alexa.com. The list
  can the downloaded from
  http://s3.amazonaws.com/alexa-static/top-1m.csv.zip. The top 1,000
  domains in the file will be used as whitelist.
* wordsEn.txt: English dictionary words, which will be used for word
  segment. The file can be downloaded from
  http://www-01.sil.org/linguistics/wordlists/english/
* DomainsExistence-test: whether a domain exists

## Running BotDigger

BotDigger runs independently on individual packet capture (.pcap) files
and is inherently parallelizeable.

TODO

### Usage

~~~~
Options:
  -h, --help, show this help message and exit
  -i INTERFACE, --interface=INTERFACE,
            specify the network interface (e.g., eth0)
  -f INPUTPCAPFILE, --inputpcap=INPUTPCAPFILE,
            specify the input pcap file
  -F INPUTPCAPDIR, --inputpcapDir=INPUTPCAPDIR,
            specify the input pcap directory
  -t TLDLISTFILE, --tld=TLDLISTFILE,
            specify the file that contains TLDs (e.g., file TLDList)
  -b BLWEBSITESFILE, --blwebsites=BLWEBSITESFILE,
            specify the file that contains websites providing blacklist service
            (e.g., file OverloadDNSWebsites)
  -c CONFIGWORDSFILE, --configwords=CONFIGWORDSFILE,
            specify the file that contains the words to ignore (e.g., file InvalidWords)
  -s DNSSERVERFILE, --dnsserver=DNSSERVERFILE,
            specify the file that contains IPs of local RDNS (e.g., file DNSServerList)
  -p POPULARDOMAINFILE, --populardomain=POPULARDOMAINFILE,
            specify the file that contains popular domains (e.g., file top-1m.csv)
  -P PREFIX, --prefix=PREFIX,
            specify the file that contains local network prefixes (e.g., NetworkPrefixes)
  -d DICTIONARYFILE, --dictionary=DICTIONARYFILE,
            specify the file that contains English dictionary (e.g., file wordsEn.txt)
  -o OFFLINEDOMAINFILE, --offlinefile=OFFLINEDOMAINFILE,
            specify the file that contains DNS information.
  -O OFFLINEDOMAINDIRECTORY, --offlinedirectory=OFFLINEDOMAINDIRECTORY,
            specify the directory that contains DNS files
  -n DYNAMICDOMAINFILE, --dynamicdomains=DYNAMICDOMAINFILE,
            specify the file that contains dynamic domains (e.g., file DynamicDomains)
  -e BIGENTERPRISEFILE, --enterprises=BIGENTERPRISEFILE,
            specify the file that contains big enterprises (e.g., file BigCompanies)
  -x EXCLUDEDHOSTSFILE, --excludedhosts=EXCLUDEDHOSTSFILE,
            specify the file that contains hosts to exclude (e.g., file ExculedHosts)
  -D EXCLUDEDDOMAINSFILE, --excludeddomains=EXCLUDEDDOMAINSFILE,
            specify the file that contains domains to exclude (e.g., file ExculedDomains)
  -r RESULTSFILE, --resultsfile=RESULTSFILE,
            specify the output file or directory
  -R RECEIVER, --receiver=RECEIVER,
            specify the email receiver when the input data is offline files
            (pcap, DNS log), the email is sent when every input file is completely
            analyzed. The email includes 1) the IP labeled as bot, 2) queried suspicious
            NXDomains, and 3) labeled C&C domains
  -T THRESHOLDSIMILARITY, --thresholdSimilarity=THRESHOLDSIMILARITY,
            specify the similarity threshold, the default value is 0.1.
  -B THRESHOLDBOTSONECLUSTER, --thresholdBotsOneCluster=THRESHOLDBOTSONECLUSTER,
            specify the bot cluster threshold, the default value is 4.
  -w TIMEINTERVAL, --timeWindow=TIMEINTERVAL,
            specify the time window (seconds) for bot detection, default value
            is 600 seconds
  -E SLDEXISTENCEFILE, --existingSLD=SLDEXISTENCEFILE,
            specify the file that contains existing SLDs
  -l, --enable2LDProbe
            enable 2LD probe, this generates lots of DNS queries, recommend to
            disable this when running BotDigger in real time
~~~~


`OFFLINEDOMAINFILE` file format: each line in the file is a DNS
query/response record, composed of 11 fields: timestamp, src_ip,
src_port, dst_ip, dst_port, queryID, query(0)/response(1), return code,
query type, queried domain, returned IP for resolved domain (blank for
NXDomains). The fields are seperated by a space.

Each file in the `OFFLINEDOMAINDIRECTORY` should follow the format of
ten fields decribed above.

`RESULTSFILE` will include the detected bot, clusters of queried
suspicious NXDomains, and labeled C&C domains.

### Running on an Example Trace File

Let's run BotDigger on a trace file with a known local bot.
In the repository is a provided sample trace file (`bot_sample.pcap`).
Run BotDigger with the following parameters:

~~~~
python BotDigger.py \
  -B 4 -T 0.10 -w 300 \
  -P NetworkPrefixes -s DNSServerList -t TLDList -b OverloadDNSWebsites \
  -c InvalidWords -p top-1m.csv -d wordsEn.txt -e BigCompanies \
  -x ExculedHosts -D ExculedDomains -n DynamicDomains \
  -f bot_sample.pcap \
  -r bot_sample-results.txt
~~~~

The necessary network information is pre-configured for running on this
sample file and will work as expected if you haven't modified any of the
files.

The expected output should be a file named
  `bot_sample-results.txt-Bot-192.168.32.5`.
This means that BotDigger has tagged local host `192.168.32.5` as a
suspected bot because of the DNS queries the host has made.

The output file is broken down into several sections:
* Suspicious `NXDomains` queried
* Clusters and corresponding domains in each cluster
* A list of suspected command and control (CnC) domains and IP addresses

#### BotDigger Example Parameters

- Bot cluster threshold is 4
- Similarity threshold to cut the hierarchical clustering dendrogram is 0.1
- Time window is 300 seconds
- File containing local network prefixes is NetworkPrefixes
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
- Input pcap file is `bot_sample.pcap`
- Output log file is `bot_sample-results.txt`

## Algorithm Description

TODO

## LICENSE

[GPLv3](./LICENSE)
