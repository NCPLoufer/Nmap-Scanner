#!/usr/bin/python3

import nmap
import sys

ns = nmap.PortScanner()

ip = input('Enter the ip address you want to scan: ')
type(ip)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan 
                4)Regular Scan
                5)OS Detection
                6)Ping Scan \n""")
print('You selected option: ', resp)

try:    
    if resp == '1': 
        print('SYN ACK Scan in progress...')
        print('Nmap Version: ', ns.nmap_version())
        ns.scan(ip, '1-1024', '-v -sT')
        print(ns.scaninfo())
        print('IP Status: ', ns[ip].state())
        print(ns[ip].all_protocols())
        print('Open Ports: ', ns[ip]['tcp'].keys())
    elif resp == '2':
        print('UDP Scan in progress...')
        print('Nmap Version: ', ns.nmap_version())
        ns.scan(ip, '1-1024', '-v -sU')   
        print(ns.scaninfo())
        print('IP Status: ', ns[ip].state())
        print(ns[ip].all_protocols())
        print('Open Ports: ', ns[ip]['udp'].keys()) 
    elif resp == '3':
        print('Comprehensive Scan in progress...')
        print('Nmap Version: ', ns.nmap_version())
        ns.scan(ip, '1-1024', '-v -sS -sV -sC -A -O') 
        print(ns.scaninfo())
        print('IP Status: ', ns[ip].state())
        print(ns[ip].all_protocols())
        print('Open Ports: ', ns[ip]['tcp'].keys())  
    elif resp == '4': 
        print('Regular Scan in progress...')
        print('Nmap Version: ', ns.nmap_version())
        ns.scan(ip)
        print(ns.scaninfo())
        print('IP Status: ', ns[ip].state())
        print(ns[ip].all_protocols())
        print('Open Ports: ', ns[ip]['tcp'].keys()) 
    elif resp == '5': 
        print('OS Detection in progress...')
        print('Nmap Version: ', ns.nmap_version())
        print(ns.scan('127.0.0.1', arguments='-O')['scan']['127.0.0.1']['osmatch'][1]) 
    elif resp == '6': 
        print('Ping Scan in progress...')
        ns.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
        hosts_list = [(x, ns[x]['status']['state']) for x in ns.all_hosts()]
        for host, status in hosts_list:
            print('{0}:{1}'.format(host, status))     
    elif resp >= '7': 
        print('Please enter a valid option!')

except KeyError:
    print('No open ports found!')
    sys.exit()

except KeyboardInterrupt:
    print('You pressed a wrong button')
    sys.exit()

#Note: This tool requires root privileges!