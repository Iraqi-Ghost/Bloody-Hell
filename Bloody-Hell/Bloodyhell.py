from ast import Return
import sys
import time
import os

def slowprint(s):
    for c in s + '\n' :
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

                            
        ██████  ██       ██████   ██████  ██████  ██    ██     ██   ██ ███████ ██      ██      
        ██   ██ ██      ██    ██ ██    ██ ██   ██  ██  ██      ██   ██ ██      ██      ██      
        ██████  ██      ██    ██ ██    ██ ██   ██   ████       ███████ █████   ██      ██      
        ██   ██ ██      ██    ██ ██    ██ ██   ██    ██        ██   ██ ██      ██      ██      
        ██████  ███████  ██████   ██████  ██████     ██        ██   ██ ███████ ███████ ███████ 
                                                                                       
                    
                                                                                    
                                The Owner is an Iraqi Ghost

                                    version ==> 1.0
                            \n""")




tool = input("[+]Enter by Number ==>\n\n\n\n[1]Network SPY\n[2]OSINT\n[3]Encryption\n[4]Malware\n[99]Contact me\n\n\n\n[+] ==> ")


if tool == "1":
    spy = input("Enter by Numbers ==>\n\n[1]Network Sniffer\n[2]Local Host\n[3]Port Scanner\n==> ")
    if spy == "1":
        # -*- coding: utf-8 -*-

        # pip install scapy

        """
        [{'name': 'Intel(R) 82574L Gigabit Network Connection',
        'win_index': '4',
        'description': 'Ethernet0',
        'guid': '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}',
        'mac': '00:0C:29:5C:EE:6D',
        'netid': 'Ethernet0'}]
        """

        # disable verbose mode
        conf.verb = 0


        def parse_packet(packet):
            """sniff callback function.
            """
            if packet and packet.haslayer('UDP'):
                udp = packet.getlayer('UDP')
                udp.show()


        def udp_sniffer():
            """start a sniffer.
            """
            interfaces = get_windows_if_list()
            print(interfaces)

            print('\n[*] start UDP sniffer')
            sniff(
                filter="udp port 53",
                iface=r'Intel(R) 82574L Gigabit Network Connection', prn=parse_packet
            )



        if __name__ == '__main__':
            udp_sniffer()


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
            print("\ Host not responding ;(")
            sys.exit()



if tool == "2":
    gath = input("Enter By Numbers ==> \n\n[1]IP address lookup\n[2]Phonenumber OSINT\n==> ")
    if gath == "1":
            def banner():
                print(lightred("""

                    
        ██████  ██       ██████   ██████  ██████  ██    ██     ██   ██ ███████ ██      ██      
        ██   ██ ██      ██    ██ ██    ██ ██   ██  ██  ██      ██   ██ ██      ██      ██      
        ██████  ██      ██    ██ ██    ██ ██   ██   ████       ███████ █████   ██      ██      
        ██   ██ ██      ██    ██ ██    ██ ██   ██    ██        ██   ██ ██      ██      ██      
        ██████  ███████  ██████   ██████  ██████     ██        ██   ██ ███████ ███████ ███████ 
                                                                                       
                                                                                       

    
                        \n"""))
    API = "http://ip-api.com/json/"

    if gath != "1":
        pass

    else:

        os.system('cls') if os.name == 'nt' else os.system('clear')
        banner()

        IP = input("[" + ("+" + ("]" + (" Enter the IP: ")))).strip()

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
        phone_n = phonenumbers.parse(input("Enter the phonenumber ==> "))
        print(geocoder.description_for_number(phone_n,'en' + ("The Country is ==> ")))

        print(carrier.name_for_number(phone_n, 'en' + ("The Carrier name is ==> ")))

        print(timezone.time_zones_for_number(phone_n) + ("The TimeZone is ==> "))



if tool == "3":
    def slowprint(s):
        for c in s + '\n' :
            sys.stdout.write(c)
            sys.stdout.flush()
            time.sleep(10. / 100)
    slowprint("[!] Moving ...")
    time.sleep(1)
    os.system('clear')

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
        ## characters to generate password from
        characters = list(string.ascii_letters + string.digits + "!@$")

        def generate_random_password():
            ## length of password from the user
            length = int(input("[+]Enter password length: "))

            ## shuffling the characters
            random.shuffle(characters)
            
            ## picking random characters from the list
            password = []
            for i in range(length):
                password.append(random.choice(characters))

            ## shuffling the resultant password
            random.shuffle(password)

            ## converting the list to string
            ## printing the list
            print("".join(password))
            
            generate_random_password()



if tool == "4":
    print("*** The Malwares is coded for Educational purpose ***")
    print("[+]https://www.mediafire.com/file/uzl305rj6o8c9p9/malwareTest/file (python) \n[+]https://www.mediafire.com/file/ua3o4hxk287c8de/tree/file (C++)\n\n\nBecareful when you download it. Im not responsible for any illegal activites !! ")

if tool == "99":
    print("""Contact the Ghost at
            E-mail: bowman001@proton.me
    """)

while True:
    if keyboard.read_key() == "enter":
        print("Quitting....")
        break