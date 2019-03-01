#!/usr/bin/env python
from tinydb import TinyDB, Query
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import socket

radius="192.168.1.11"
seckey="cisco"

msoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msoc.connect((radius, 1812 ))
myip = msoc.getsockname()[0]

srv = Client(server=radius, secret=seckey,
             dict=Dictionary("dictionary"))
db = TinyDB('1vm2radius.db')
dbq = Query()
srec = db.search(dbq.iclass!="")
for recs in srec:
    req2 = srv.CreateAcctPacket(User_Name=recs['vname'])
    req2["Calling-Station-Id"] = str(recs['vmac'])
    req2["Framed-IP-Address"] = str(recs['vipadd'])
    req2["Service-Type"] = 2
    req2["NAS-Port-Type"] = 0
    req2["NAS-IP-Address"] = myip
    req2["Acct-Status-Type"] = "Stop"
    req2["Class"] = str(recs['iclass'])
    req2["Acct-Session-Id"] = str(recs['asess'])
    req2["Cisco-AVPair"] = "audit-session-id="+str(recs['isess'])
    req2['Acct-Terminate-Cause'] = 2
    req2['Acct-Delay-Time']=2
    acct=srv.SendPacket(req2)
db.purge()
db.close()
