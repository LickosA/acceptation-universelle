#!/usr/bin/env python
# coding: utf-8

# In[59]:


#Modules
import dns.resolver
import sys, getopt
import subprocess
import socket
import smtplib
import json
import os
import numpy as np
from nmap import *


# 

dict = {}

def getMX(domain):
    mx = []
    answers = dns.resolver.resolve(domain, 'MX')
    for rdata in answers:
        mx.append(str(rdata.exchange))
    return mx


# 


def smtpSession(mx):
    server = smtplib.SMTP(str(mx), 25)
    response = server.ehlo()
    return [mx,response]


# 


def checkSMTUTF8(a):
    if 'SMTPUTF8' in str(a):
        status = 'yes'
    else:
       status = 'no'
    return status


# 


def getEmailServerName(mailServer):
    nmScan = nmap.PortScanner()
    x = nmScan.scan(mailServer, '25')
    server = x['scan']
    if not server :
        emailServer = 'Not Found'
    else :
        emailServer = server[list(server.keys())[0]]['tcp'][25]['product']
    return emailServer


# 


def funct2(i):
    server = getEmailServerName(i)
    s = checkSMTUTF8(smtpSession(i))
    return {i : {'eia' : s, 'server' : server }}


# 


def test(d):
    r  = []
    mx = getMX(d)
    for i in mx :
        r.append(funct2(i))
    return json.dumps({'domain': d,
         'results': r}, indent=4)


# 

def main():
    if(sys.argv[1]=='-i'):
        with open(sys.argv[2]) as topo_file:
            for line in topo_file:
                #print(str(line))
                print(test(str(line.rstrip())))
    else:
        if(len(sys.argv[1])==0):
            print(test(str(sys.argv[1:])))
            dict['final'] = test(str(sys.argv[1:]))
            print(dict)
        else:
            args = sys.argv[1].split(',')
            args = np.array([str(i) for i in args]) 
            #print(args)
            for i in range(0, len(args)):          
                dict[i]= test(str(args[i]))
            print(dict)

    exDict = {'final' : dict}
    with open('file.json', 'w') as file:
        file.write(json.dumps(exDict)) # use `json.loads` to do the rev
# 

if __name__ == "__main__":
    main()




