import ctypes as ct
import tkinter as tk
import os
import sys
import scapy
import time
import re
import requests

os.makedirs('temp', exist_ok = True)
wind = tk.Tk()
last_packet = None
found = False
downtxt = ""
def bk(packet):
    global found
    return found
savedpath = ""
def download_file(url, save_path):
    try:
        if os.path.exists(save_path):
            os.remove(save_path)
        global savedpath
        savedpath = save_path
        response = requests.get(url, stream = True)
        response.raise_for_status()
        with open(save_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        return
    except:
        print("Download Failed!!!")
        sys.exit()
def myhandler(packet):
    global found
    global last_packet
    if (packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw)):
        try:
            data = packet[scapy.Raw].load.decode('utf-8', errors = 'ignore')
        except:
            return
        if data.startswith("POST"):
            lines = data.splitlines()
            if (len(lines)) > 0:
                request_line = lines[0]
                parts = request_line.split(" ")
                if (len(parts) >= 2):
                    url = parts[1]
                    if "fileinfo" in url:
                        found = True
                        last_packet = packet

def decodepacket(mode, fnme = ""):
    global downtxt
    if (mode == 1):
        rdpacket = scapy.rdpcap("temp/" + fname)[0]
    else:
        rdpacket = last_packet
    if rdpacket.haslayer(scapy.Raw):
        try:
            rawtext = rdpacket[scapy.Raw].load.decode('utf-8', errors='ignore')
            rawlist = rawtext.splitlines()
            for i in rawlist:
                match = re.search(r'"downloadUrl":"(.*?)"', i)
                if match:
                    downtxt = match.group(1)
                    return
            print("Failed!?")
            sys.exit()
        except:
            sys.exit()



def catch1():
    w3 = tk.Tk()
    labd = tk.Label(w3, text = "请下载需要做的题目(等待中)")
    labd.pack()
    w3.mainloop()
    packets = scapy.sniff(filter = "host 127.0.0.1 and port 5291", prn = myhandler, stop_filter = bk)
    filename = f"temp/catch_{int(time.time())}.pcap"   
    scapy.wrpcap(filename, [last_packet])

def strt():
    wind.destroy()
    w2 = tk.Tk()
    def on_finish1():
        w2.destroy()
        catch1()
    labd = tk.Label(w2, text = "请将天学网客户端代理设置为127.0.0.1,端口5291(在登陆界面)")
    btn1 = tk.Button(w2, command = on_finish1, text = "完成")
    labd.pack()
    btn1.pack()
    w2.mainloop()

def init():
    # print("init")
    labd = tk.Label(wind, text = "是否开始抓包")
    btn1 = tk.Button(wind, command = strt, text = "开始")
    btn2 = tk.Button(wind, command = sys.exit, text = "退出")
    labd.pack()
    btn1.pack()
    btn2.pack()
    wind.mainloop()

if __name__ == '__main__':
    init()
