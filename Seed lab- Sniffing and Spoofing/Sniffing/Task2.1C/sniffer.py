#!/usr/bin/python=
# -*- coding: utf-8 -*-

from scapy.all import *

def print_pkt(pkt):
 pkt.show()

pkt = sniff(filter='port 23',prn = print_pkt)
