# Security python script

def scan_logfile(filename):
    with open(filename,'r') as file:
        return scan(file)

def scan_compressed_file(filename):
    with bz2.BZ2File(filename,"r") as file:
        return scan(file)

def scan(file):
    ips = {}

    for line in file:
        match = re.search("Failed password for (\w+) from ([\d\.]+)",line)
        if match:      
            ip = match.group(2)
            
            if not is_local_ip(ip):                 
                if ip in ips:
                    ips[ip] += 1
                else:
                    ips[ip] = 1

    return ips.keys()

def is_local_ip(ip):
    if re.match("10\.",ip):
        return True

    if re.match("192\.168\.",ip):
        return True
    
    match = re.match("172\.(\d+)\.",ip)
    
    if match:
        group = int(match.group(1))
        
        if group >= 16 and group <=31:
            return True
    
    return False;
        

if __name__ == "__main__":
    import sys
    import re
    import bz2
    from os import listdir
    
    all_ips = list()
    
    all_ips.extend(scan_logfile('/var/log/auth.log'))

    files = [ f for f in listdir('/var/log') if re.search("^auth.log.\d+.bz2$",f) ]
    
    for file in files:
        all_ips.extend(scan_compressed_file('/var/log/'+file))
    
    all_ips = list(set(all_ips))
    
    start = 65534 - len(all_ips)

    print '#!/bin/sh'
    print 'ipfw -q flush'
    
    for ip in all_ips:
        print str.format("ipfw -q add {0} deny all from {1} to any",start,ip)
        start += 1
        
    #print "ipfw -q add 65535 allow ip from any to any"
    
    