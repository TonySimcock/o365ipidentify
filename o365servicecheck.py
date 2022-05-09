#!/usr/bin/env python

import ipaddress
import argparse
import sys

o365servicelistURL = 'https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7'

def get_o365servicelist(url):
    import json,urllib.request
    data = urllib.request.urlopen(url).read()
    return json.loads(data)

def validateIP(ip):
    try:
        ip = ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def checkIPversion(ip):
    ipver = ipaddress.ip_network(ip).version
    return ipver
    
def checkifinNetwork(ip,ipver,nw):
    if ipver == 4:
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(nw)
    if ipver == 6:
        return ipaddress.IPv6Address(ip) in ipaddress.IPv6Network(nw)
    
def checkIPv4(ip,o365nw):
    if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(o365nw):
        return(True)
    else:
        return(False)
        
def checkIPv6(ip,o365nw):
    if ipaddress.IPv6Address(ip) in ipaddress.IPv6Network(o365nw):
        return(True)
    else:
        return(False)

def runreport(ip,ipver,servicelist):
    ret_data = {}
    for service in servicelist:
        #print(service['serviceArea'])
        if 'ips' in service:
            for o365nw in service['ips']:
                o365ipver = checkIPversion(o365nw)
                if o365ipver == ipver:
                    if checkifinNetwork(ip,ipver,o365nw):
                        if service['serviceArea'] not in ret_data:
                            ret_data[service['serviceArea']] = {}
                        matched_data = {}
                        matched_data['o365_network'] = o365nw
                        matched_data['matched_ip'] = ip
                        matched_data['ports'] = {}
                        if 'tcpPorts' in service:
                            matched_data['ports']['tcp'] = service['tcpPorts']
                        if 'udpPorts' in service:
                            matched_data['ports']['udp'] = service['udpPorts']
                        #print(matched_data)
                        #return(matched_data)
                        for key, value in matched_data.items():
                            ret_data[service['serviceArea']][key] = value
                        print(ret_data)

servicelist = get_o365servicelist(o365servicelistURL)

parser = argparse.ArgumentParser(description='Choose file input or stdin')
parser.add_argument('--file', help='provide a list of IPs - 1 per line')
args = parser.parse_args()

if args.file:
    with open(args.file) as data:
        for ip in data:
            ip = ip.strip()
            if validateIP(ip):
                ipver = checkIPversion(ip)
                runreport(ip,ipver,servicelist)
else:
    for ip in sys.stdin.readlines():
        ip = ip.strip()
        if validateIP(ip):
            ipver = checkIPversion(ip)
            runreport(ip,ipver,servicelist)