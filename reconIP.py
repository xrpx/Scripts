#!/usr/bin/env python3

# Author:		xrpx
# Description:		Passive scan IP address/ range using shodan.io
# Last modified: 	May 30, 2019

# Dependencies
# pip3 install shodan, netaddr

import shodan, sys, csv, os, time
from netaddr import IPAddress, IPNetwork

# Initiate session with API key
########## CONFIGURATION ZONE ###########
api_key='SHODAN KEY HERE'
#########################################
api = shodan.Shodan(api_key)

# Generate filename before entering loop
timestamp = str(time.time())
filename = 'shodan_results_' + timestamp + '.csv'


def write_csv(combined_res,filename):
    # Export data as csv
    if os.path.exists(filename):
        append_write = 'a' # append if already exists
    else:
        append_write = 'w' # make a new file if not

    with open(filename, append_write, newline='') as f:
        writer = csv.writer(f)
        writer.writerows(combined_res)

    f.close()


def lookups(ip, filename):
    try:
    
        for ipn in ip:
        
            ip_str = [str(ipn)]

# Continue execution upon 'IP not found' exception
            try:
                ipinfo = api.host(ip_str)
                hostnames = ipinfo.get('hostnames')
                hostnames = str(hostnames).replace(', ', '/')
                hostnames = [hostnames]

                ports = ipinfo.get('ports')
                ports = str(ports).replace(', ', '/')
                ports = [ports]

                combined_res = zip(ip_str, hostnames, ports)
                
                write_csv(combined_res, filename)
            except shodan.APIError:
                pass

    except Exception as e:
            print('Error: {}'.format(e))
# Elaborate code for debug
#           print('Error! Code: {c}, Message, {m}'.format(c = type(e).__name__, m = str(e)))
        

##### MAIN #####

with open(sys.argv[1]) as nets:
    for subnet in nets:
        ip = IPNetwork(subnet)
        lookups(ip, filename)

