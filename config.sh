#!/usr/bin/env bash


iptables -F
iptables -A INPUT -s 192.248.8.68 -j DROP
iptables -A FORWARD -p tcp -s 172.217.194.103 -j REJECT
iptables -A INPUT -p tcp --dport 443 -j REJECT
iptables -A INPUT -p tcp -d 44.230.27.229 --dport 443 -j REJECT