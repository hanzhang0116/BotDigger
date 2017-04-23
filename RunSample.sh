#!/bin/sh

python BotDigger.py \
  -B 4 -T 0.10 -w 300 \
  -P NetworkPrefixes -s DNSServerList -t TLDList -b OverloadDNSWebsites \
  -c InvalidWords -p top-1m.csv -d wordsEn.txt -e BigCompanies \
  -x ExculedHosts -D ExculedDomains -n DynamicDomains \
  -f bot_sample.pcap \
  -r bot_sample-results.txt
