#!/bin/sh

# TODO use virtualenv

# install the required packages
pip install --user \
  wordsegment \
  python-levenshtein \
  pythonwhois \
  dpkt \
  pypcap \
  netaddr \
  dnslib \
  pylzma
