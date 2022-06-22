import sys
import time
import os
import datetime

def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(10. / 100)
slowprint("")
time.sleep(0)
os.system('clear')

from scapy.arch.windows import get_windows_if_list
from scapy.all import *
import requests, os
from huepy import *
import sys
import signal
import ipaddress
from time import sleep
import geocoder
import requests
import time
import socket
import ipaddress
import folium
from time import sleep
import subprocess
import string
import random
import os
import sys
from geoip import geolite2
from telnetlib import ENCRYPT, IP
from scapy.all import *
import argparse
import requests
import re
import sys
import os
import time
import zipfile
import random
import urllib
from itertools import product
from bs4 import BeautifulSoup
import logging
import scapy.all as scapy
import keyboard
import re
import pandas as pd
import multiprocessing
import subprocess
import socket
from geoip import geolite2
import folium
from simple_geoip import GeoIP
from phonenumbers import geocoder
import phonenumbers
from phonenumbers import carrier
from phonenumbers import timezone
from cryptography.fernet import Fernet
from telnetlib import IP
from scapy.all import *
import socket
from geoip import geolite2
import os, requests, json, sys
from time import sleep
from huepy import *
import cryptography
import pyfiglet
import socket
from datetime import datetime
import datetime
import phonenumbers as pn
from phonenumbers import carrier
from phonenumbers import geocoder
from phonenumbers import carrier
from phonenumbers import timezone


def slowprint(s):
    for c in s + '\n' :
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(10. / 100)
slowprint("")
time.sleep(0)
os.system('clear')

print("""
                        Iraqi Ghost
              ,---------------------------,
              |  /---------------------\  |
              | |                       | |
              | |      Bloddy           | |
              | |           Hell        | |
              | |                       | |
              | |                       | |
              |  \_____________________/  |
              |___________________________|
            ,---\_____     []     _______/------,
          /         /______________\           /|
        /___________________________________ /  | ___
        |                                   |   |    )
        |  _ _ _                 [-------]  |   |   (
        |  o o o                 [-------]  |  /    _)_
        |__________________________________ |/     /  /
    /-------------------------------------/|      ( )/
  /-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/ /
/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/ /
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

                
                Linux Version

               a8888b.
             d888888b.
             8P"YP"Y88
             8|o||o|88
             8'    .88
             8`._.' Y8.
            d/      `8b.
           dP   .    Y8b.
          d8:'  "  `::88b
         d8"         'Y88b
        :8P    '      :888
         8a.   :     _a88P
       ._/"Yaa_:   .| 88P|
       \    YP"    `| 8P  `.
       /     \.___.d|    .'
       `--..__)8888P`._.'


""")

def slowprint(s):
    for c in s + '\n' :
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(10. / 100)
slowprint("[!] On the Way ...")
time.sleep(1.5)
os.system('clear')


print("""

                Created for EDUCATIONAL purpose onLY

######                                       #     #                      
#     # #       ####   ####  #####  #   #    #     # ###### #      #      
#     # #      #    # #    # #    #  # #     #     # #      #      #      
######  #      #    # #    # #    #   #      ####### #####  #      #      
#     # #      #    # #    # #    #   #      #     # #      #      #      
#     # #      #    # #    # #    #   #      #     # #      #      #      
######  ######  ####   ####  #####    #      #     # ###### ###### ###### 
                                                                                    
                    The Owner is an Iraqi Ghost

                        version -> 1.1
                        Date -> 2022/6/20
                            \n""")




tool = input("[+]Enter by Number ==>\n\n\n\n[1]Network SPY\n[2]OSINT\n[3]Encryption\n[4]Malware\n[99]Contact me\n\n\n\n[+] ==> ")


if tool == "1":
    def slowprint(s):
        for c in s + '\n':
            sys.stdout.write(c)
            sys.stdout.flush()
            time.sleep(10. / 100)
    slowprint("")
    time.sleep(0)
    os.system('clear')
    print("""


#     # ####### ####### #     # ####### ######  #    #           #####  ######  #     # 
##    # #          #    #  #  # #     # #     # #   #           #     # #     #  #   #  
# #   # #          #    #  #  # #     # #     # #  #            #       #     #   # #   
#  #  # #####      #    #  #  # #     # ######  ###              #####  ######     #    
#   # # #          #    #  #  # #     # #   #   #  #                  # #          #    
#    ## #          #    #  #  # #     # #    #  #   #           #     # #          #    
#     # #######    #     ## ##  ####### #     # #    #           #####  #          #    


                       By: Iraqi Ghost                                                                     
    """)
    spy = input("Enter by Numbers ==>\n\n[1]Network Sniffer\n[2]Local Host\n[3]Port Scanner\n==> ")
    if spy == "1":
        def network_monitoring_for_visualization_version(pkt):
            time = datetime.datetime.now()
            # classifying packets into TCP
            if pkt.haslayer(TCP):
                # classyfying packets into TCP Incoming packets
                if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
                    print(str("[") + str(time) + str("]") + "  " + "TCP-IN ==> {}".format(len(pkt[TCP])) + " Bytes" + "    " + "SRC-MAC ==> " + str(pkt.src) + "    " + "DST-MAC ==> " + str(pkt.dst) + "    " + "SRC-PORT ==>" + str(pkt.sport) + "    " + "DST-PORT ==> " + str(pkt.dport) + "    " + "SRC-IP ==> " + str(pkt[IP].src) + "    " + "DST-IP ==> " + str(pkt[IP].dst))
                    print("")
                if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
                    print(str("[") + str(time) + str("]") + "  " + "TCP-OUT ==> {}".format(len(pkt[TCP])) + " Bytes" + "    " + "SRC-MAC ==> " + str(pkt.src) + "    " + "DST-MAC ==> " + str(pkt.dst) + "    " + "SRC-PORT ==> " + str(pkt.sport) + "    " + "DST-PORT ==> " + str(pkt.dport) + "    " + "SRC-IP ==> " + str(pkt[IP].src) + "    " + "DST-IP ==> " + str(pkt[IP].dst))
                    print("")
            # classifying packets into UDP
            if pkt.haslayer(UDP):
                if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
                    # classyfying packets into UDP Outgoing packets
                    print(str("[") + str(time) + str("]") + "  " + "UDP-OUT ==> {}".format(len(pkt[UDP])) + " Bytes " + "    " + "SRC-MAC ==> " + str(pkt.src) + "    " + "DST-MAC ==> " + str(pkt.dst) + "    " + "SRC-PORT ==> " + str(pkt.sport) + "    " + "DST-PORT ==> " + str(pkt.dport) + "    " + "SRC-IP ==> " + str(pkt[IP].src) + "    " + "DST-IP ==> " + str(pkt[IP].dst))
                    print("")
                if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
                    # classyfying packets into UDP Incoming packets
                    print(str("[") + str(time) + str("]") + "  " + "UDP-IN ==> {}".format(len(pkt[UDP])) + " Bytes " + "    " + "SRC-MAC ==> " + str(pkt.src) + "    " + "DST-MAC ==> " + str(pkt.dst) + "    " + "SRC-PORT ==> " + str(pkt.sport) + "    " + "DST-PORT ==> " + str(pkt.dport) + "    " + "SRC-IP ==> " + str(pkt[IP].src) + "    " + "DST-IP ==> " + str(pkt[IP].dst))
                    print("")
            # classifying packets into ICMP
            if pkt.haslayer(ICMP):
                # classyfying packets into UDP Incoming packets
                if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
                    print(str("[") + str(time) + str("]") + "  " + "ICMP-OUT ==> {}".format(len(pkt[ICMP])) + " Bytes" + "    " + "IP-Version ==> " + str(pkt[IP].version) + "    " * 1 + " SRC-MAC ==> " + str(pkt.src) + "    " + "DST-MAC ==> " + str(pkt.dst) + "    " + "SRC-IP ==> " + str(pkt[IP].src) + "    " + "DST-IP ==> " + str(pkt[IP].dst))
                    print("")

                if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
                    print(str("[") + str(time) + str("]") + "  " + "ICMP-IN ==> {}".format(len(pkt[ICMP])) + " Bytes" + "    " + "IP-Version ==> " + str(pkt[IP].version) + "    " * 1 + "	 SRC-MAC ==> " + str(pkt.src) + "    " + "DST-MAC ==> " + str(pkt.dst) + "    " + "SRC-IP ==> " + str(pkt[IP].src) + "    " + "DST-IP ==> " + str(pkt[IP].dst))
                    print("")



        if __name__ == '__main__':
            sniff(prn=network_monitoring_for_visualization_version)


        
    if spy == "2":
        def host_IP():
            try:
                hname = socket.gethostname()
                hip = socket.gethostbyname(hname)
                print("Hostname:  ",hname)
                print("IP Address: ",hip)
            except:
                print("Unable to get Hostname and IP")
            # Driver code
        host_IP() #Function call

    if spy == "3":
        ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
        print(ascii_banner)

        target = input(str("Enter the Target IP ==> "))

        #Banner
        print("_" * 50)
        print("Scanning Target ==> " + target)
        print("Scanning started at ==> " + str(datetime.now()))
        print("_" * 50)

        try:

            #scan every port
            for port in range(1,65535):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(0.5)

                # return open ports
                results = s.connect_ex((target,port))
                if results == 0:
                    print("[*] Port {} is open".format(port))
                s.close()
        except KeyboardInterrupt:
            print("\n Exiting :(")
            sys.exit()
        
        except socket.error:
            print(" Host not responding ;(")
            sys.exit()



if tool == "2":
    def slowprint(s):
        for c in s + '\n':
            sys.stdout.write(c)
            sys.stdout.flush()
            time.sleep(10. / 100)
    slowprint("")
    time.sleep(0)
    os.system('clear')
    print("""
                                                         
#######  #####  ### #     # ####### 
#     # #     #  #  ##    #    #    
#     # #        #  # #   #    #    
#     #  #####   #  #  #  #    #    
#     #       #  #  #   # #    #    
#     # #     #  #  #    ##    #    
#######  #####  ### #     #    #    
        
        By -> Iraqi Ghost
                    
    """)

    gath = input("Enter By Numbers ==> \n\n[1]IP address lookup\n[2]Phonenumber lookup\n==> ")
    if gath == "1":
            def banner():
                print(lightred("""
### ######                                               
 #  #     #    #       ####   ####  #    # #    # #####  
 #  #     #    #      #    # #    # #   #  #    # #    # 
 #  ######     #      #    # #    # ####   #    # #    # 
 #  #          #      #    # #    # #  #   #    # #####  
 #  #          #      #    # #    # #   #  #    # #      
### #          ######  ####   ####  #    #  ####  #   
            By -> Iraqi Ghost  
                        \n"""))
    API = "http://ip-api.com/json/"

    if gath != "1":
        pass

    else:

        os.system('cls') if os.name == 'nt' else os.system('clear')
        banner()

        IP = input("[" + ("+" + ("]" + ("Enter the IP: ")))).strip()

        os.system('cls') if os.name == 'nt' else os.system('clear')
        banner()

        try:
            
            data = requests.get(API+IP).json()
            sys.stdout.flush()

            print("    IP Address      " + (" :      " + (IP)))
            sleep(0.6)
            print("    city            " + (" :      " + (data['city'])))
            sleep(0.6)
            print("    Region            " + (" :      " + (data['region'])))
            sleep(0.6)
            print("    Country              " + (" :      " + (data['country'] + "\n")))
            sleep(0.6)
            print("    Lat           " + (" :      " + (data['lat'])))
            sleep(0.6)
            print("    Lon          " + (" :      " + (data['lon'])))
            sleep(0.6)
            print("    TimeZone      " + (" :      " + (data['timezone'])))
            sleep(0.6)
            print("    Country Code    " + (" :      " + (data['countryCode'])))
            sleep(0.6)
            print("    Zip Code     " + (" :      " + (data['zip'] + "\n")))
            sleep(0.6)
            print("    ISP               " + (" :      " + (data['isp'])))
            sleep(0.6)
            print("    ASN               " + (" :      " + (data['as'] + "\n")))
            sleep(0.6)
            print("    Google Maps       " + (" :      " + ("https://maps.google.com/?q="+ str(data['lat']) + "," + str(data['lon']) + "\n")))

        except:
            pass



    if gath == "2":
        def slowprint(s):
            for c in s + '\n':
                sys.stdout.write(c)
                sys.stdout.flush()
                time.sleep(10. / 100)
        slowprint("")
        time.sleep(0)
        os.system('clear')
        print("""
        

######  #     # ####### #     # #######    #     # #     # #     # ######  ####### ######  
#     # #     # #     # ##    # #          ##    # #     # ##   ## #     # #       #     # 
#     # #     # #     # # #   # #          # #   # #     # # # # # #     # #       #     # 
######  ####### #     # #  #  # #####      #  #  # #     # #  #  # ######  #####   ######  
#       #     # #     # #   # # #          #   # # #     # #     # #     # #       #   #   
#       #     # #     # #    ## #          #    ## #     # #     # #     # #       #    #  
#       #     # ####### #     # #######    #     #  #####  #     # ######  ####### #     # 

                                By -> Iraqi Ghost
                                                                                                                                                            
        """)
        phone = pn.parse(input("Enter the Target Phone Number with (+) -> "))

        # Country
        country_name = geocoder.description_for_number(phone, 'en')
        print("Country -> " + country_name)

        # timezone
        timezone = timezone.time_zones_for_number(phone)
        print("TimeZone -> ", timezone)

        # carrier name
        carrier_name = carrier.name_for_number(phone, 'en')
        print("Carrier name -> ", carrier_name)

        format = pn.format_number(phone, pn.PhoneNumberFormat.NATIONAL)
        print("Format of the number -> ", format)

        Validity = pn.is_valid_number(phone)
        print("Vaildity -> ", Validity)


if tool == "3":
    encrypt = input("\n\nEnter by Numbers ==> \n\n[1]Text Encryption\n[2]Encrypted Password Generator\n\n ==> ")
    if encrypt == "1":
        def enncrypt(text):
            
            key = Fernet.generate_key()
            
            print("Your Key is:",key.decode('ascii'))
        
            b = bytes(text, 'utf-8')
            
            f = Fernet(key)
            
            print()
            
            token=f.encrypt(b)

            print("Your encrypted text is:",token.decode('ascii'))
        
        def deccrypt(key,text):
            k=bytes(key, 'utf-8')
            b = bytes(text, 'utf-8')
            f=Fernet(k)
            
            dec=f.decrypt(b)

            print("Your decrypted text is:",dec.decode('ascii'))
            
            
        print("Enter text you want to encrypt or decrypt:")
        text = (input())
        print()
        print("For Encryption Press 1 || For Decryption Press 2 ==> ")
        press=int(input())


        if(press==1):
            enncrypt(text)
        else:
            print("Enter Key:")
            keyy=input()
            print()
            deccrypt(keyy,text)


    if encrypt == "2":
        def encrypt(text):
            
            key = Fernet.generate_key()
            
            print("Your Key is:",key.decode('ascii'))
        
            b = bytes(text, 'utf-8')
            
            f = Fernet(key)
            
            print()
            
            token=f.encrypt(b)

            print("Your encrypted text is: -> ",token.decode('ascii'))
        
        def decrypt(key,text):
            k=bytes(key, 'utf-8')
            b = bytes(text, 'utf-8')
            f=Fernet(k)
            
            dec=f.decrypt(b)

            print("Your decrypted text is:",dec.decode('ascii'))
            
            
        print("Enter text you want to encrypt or decrypt:")
        text = (input())
        print()
        print("For Encryption Press 1 || For Decryption Press 2 ==> ")
        press=int(input())


        if(press==1):
            encrypt(text)
        else:
            print("Enter Key:")
            keyy=input()
            print()
            decrypt(keyy,text)


if tool == "4":
    print("*** The Malwares is coded for Educational purpose ***")
    print("[+]https://www.mediafire.com/file/uzl305rj6o8c9p9/malwareTest/file (python) \n[+]https://www.mediafire.com/file/ua3o4hxk287c8de/tree/file (C++)\n\n\nBecareful when you download it. Im not responsible for any illegal activites !! ")

if tool == "99":
    def slowprint(s):
        for c in s + '\n':
            sys.stdout.write(c)
            sys.stdout.flush()
            time.sleep(10. / 100)
    slowprint("")
    time.sleep(0)
    os.system('clear')
    print("""
    Contact the Ghost at
    E-mail: bowman001@proton.me
            
    """)

while True:
    if keyboard.read_key() == "enter":
        print("Quitting....")
        break
