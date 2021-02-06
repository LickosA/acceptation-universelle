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
import argparse

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
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('-f', help="utilisez -f pour passer un fichier en argument")
    parser.add_argument('-d', help="utilisez -d pour passer directement un nom de domaine en argument")
    parser.add_argument('-l', help="utilisez -l pour passer directement une liste de nom de domaine en argument")
    args = parser.parse_args()
    print('args is: ', args)
    if(args.d != None and args.f == None and args.l == None):
        print(test(str(args.d)))
        dict['final'] = test(str(args.d))
        #print('domaine')
    if(args.f != None and args.d == None and args.l == None):
        with open(args.f) as topo_file:
            for line in topo_file:
                print(test(str(line.rstrip())))
        #print('Fichier')
    if(args.l != None and args.f == None and args.d == None):
        liste = args.l.split(',')
        liste = np.array([str(i) for i in liste]) 
        for i in range(0, len(liste)):
            print(test(str(liste[i])))          
            dict[i]= test(str(liste[i]))
        #print('Liste')
    

    exDict = {'final' : dict}
    with open('file.json', 'w') as file:
        file.write(json.dumps(dict)) # use `json.loads` to do the rev
    
# 

if __name__ == "__main__":
    main()




