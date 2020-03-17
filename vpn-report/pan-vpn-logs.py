#!/usr/bin/python
#
# Download Thread pcap from a paloalto FW
#
# Sorry for the code , my second pyhon program (first one after hello world ;-)
#
#
import urllib
import requests
import re
import time
import sys
import argparse
#import ConfigParser
import configparser
import os
from xml.dom.minidom import  parseString
import xml.dom.minidom
import csv
import pan.xapi
import xmltodict
import pprint
import json
import datetime

config="panos.cfg"


debug =True

nodebug=False

# Funciones

def dodebug(line):
   """ simple debug funtion """
   if debug == True:
        print("DEBUG " + line)


def dolog(lines):
    """ Write lines to the log file """
    output= open (LOGFILE ,'a')
    output.writelines(lines)
    output.close


## start code
#
# Check the arguments
parser = argparse.ArgumentParser(description='Generate  VPN reports from a PaloAlto Firewall.')
parser.add_argument('--config','-C',help='Config file,(defaults to ' + config + ')')
parser.add_argument('--debug','-D',help='set the debug flag',action='store_true')
parser.add_argument('--nodebug','-ND',help='unset the debug flag',dest='nodebug',action='store_true')

args = parser.parse_args()
if (args.config):
        config = args.config

# Load of the configuration file
if os.path.exists(config):
    Config = configparser.ConfigParser()
    Config.read(config)
    # dodebug  ("Config file " + config + " read" )
else:
    print("Error can't read config file " + config)
    print("Try using --config configfile to especify the config file")
    sys.exit("Error")

# Load the config 

debug= Config.getboolean("main","debug")

if (args.nodebug):
    debug=False

key= Config.get("vpnreport","key")
if (key ==''):
    key=Config.get("main","key")

host= Config.get("vpnreport","device")
mode = Config.get("vpnreport","mode")
filtercmd= Config.get("vpnreport","filter")
record_time= Config.get("vpnreport","record_time")

records = [x.strip(' ') for x in Config.get('vpnreport','records').split(',')]

if ((mode !="panorama" ) and (mode !="firewall")):
    print ("Modo no permitido, debe ser panorama o firewall")
    sys.exit("Error")

if (mode == 'firewall'):
   dodebug('Modo de configuracion: +' + mode)
   h= Config.get("vpnreport","device").split(',')
   hosts= [x.strip(' ') for x in h]
elif  (mode =="panorama"):
    dodebug ("Modo de configuracion "+mode )
    dodebug("OK , doki\n" + "key=" + key + "fw="+host +"\nmode=" + mode)

    try:
        xapi = pan.xapi.PanXapi(
                tag='pa-200' ,
                api_key= key ,
                hostname= host 
                )
    except pan.xapi.PanXapiError as msg:
        print('pan.xapi.PanXapi:', msg)
        sys.exit(1)
    # estamos en modo "Panorama, asi que primero tenemos que buscar que FW hay
    cmd="<show><devices><connected></connected></devices></show>" 
    xpath="/" 

    try:
        connected=xapi.op(cmd=cmd,vsys=None,cmd_xml=False)
    except pan.xapi.PanXapiError as msg:
        print('edit:', msg)
        sys.exit(1)

    dodebug("OK se ejecuta el comando:" + cmd)
    #dodebug("result:\n"+xapi.xml_result())
    pp = pprint.PrettyPrinter(indent=4)
    dict= xmltodict.parse(xapi.xml_result())
    #pp.pprint(dict)
    dodebug("**** priting ddict['devices']['entry']")
    node=dict['devices']['entry']
    #pp.pprint(node)
    hosts=[]
    for device in (node):
        serial= device['serial'] 
        hostname= device['hostname']
        ip4= device['ip-address']
        model= device['model']
        dodebug(hostname + " " + model + " " + " " + ip4 + " " + serial )
        hosts.append(serial)

##OK ahora lo importante , tenemos:
# mode el modo = panorama o firewall
# Si  mode=firewall , iteramos sobre los objetos en hosts y hacemos la búsqueda en el elemento
# Si mode= panorama , iteramos sobre los objetos en hosts, y hacemos la busqueda en panorama con el tarjet

# Por ahora solo DEBUG, es decir, sacamos los los equipos que hay y exit

dodebug("Modo:" + mode)
for device in hosts:
    dodebug ("serial/host: "+  device)

# OK ahora la busqueda 

for device in hosts:
    if (mode == 'panorama'):
        dodebug("Launching panorama search for "+ device + " on panorama=" +host)
        try:
            xapi= pan.xapi.PanXapi(
                    tags= 'fw01-1',
                    api_key=key ,
                    hostname=host,
                    serial = '013201016524'
                    )
        except pan.xapi.PanXapiError as msg:
            print('pan.xapi.PanXapi:', msg)
            sys.exit(1)
        #dodebug ("FW=013201016524\nsearch= "+ filtercmd )

    elif (mode =='firewall'):
        dodebug("Launching search on firewall " +device)
        try:
            xapi=pan.xapi.PanXapi(
                    tags=device ,
                    api_key=key, 
                    hostname=device
                    )
        except pan.xpai.PanXapiError as msg:
            print('pan.xapi.PanXapi:',msg)
            sys.exit(1)
        #dodebug("Firewall="+device +"\nsearch=" +filtercmd)

    try: 
        connected = xapi.log(
                    nlogs = 5000 ,
                    log_type='system' , 
                    filter= filtercmd
                )   
    except pan.xapi.PanXapiError as msg:
            print('edit:', msg)
            sys.exit(1)

    dodebug("OK se ejecuta la busqueda: :" + filtercmd)
    result_dirty= xapi.xml_result() ;
    result='<xml>' + result_dirty  +'</xml>'
    # Generate logs entries
    pp = pprint.PrettyPrinter(indent=4) 
    dict= xmltodict.parse(result)
    logs=dict['xml']['log']['logs']
    dodebug("Print Read " +  logs['@count'] + " progress " + logs['@progress'] + "%") 
    lines=logs['entry']
    #pp.pprint(lines)
    # 
    #OK now the log extraction
    for  r in lines:
        #pp.pprint(r)
        timestr= r[record_time]
        #dodebug("timestr= " + timestr)
        unixtime= time.mktime(datetime.datetime.strptime(timestr,"%Y/%m/%d %H:%M:%S").timetuple())
        #dodebug("timstr=" +timestr + " unixtime= " + str(unixtime))
        lenr= len(records)
        for k in range(lenr -1):
        #    dodebug("k es :" + str(k) + " records["+str(k)+"] = " + records[k] +" " + r[records[k]])
            print(r[records[k]] + ";", end="")
        print(r[records[lenr-1]] )
sys.exit(0)

#

# y lo borramos 

# Aqui vendria el procesamiento


sys.exit(0)
# Poner un TAG
#
#paco@telmad.fw(active)# set shared tag "middlware"
#(container-tag: shared container-tag: tag container-tag: entry key-tag: name value: middlware)
#((eol-matched: . #t) (eol-matched: . #t) (xpath-prefix: . /config) (context-inserted-at-end-p: . #f))
#(shared (tag (entry (@ (name middlware)))))
#(entry (@ (name middlware)))

#<request cmd="set" obj="/config/shared/tag" cookie="1736877363563317"><entry name='middlware'/></request>

sys.exit(10)

xpath = "/config/shared/tag"
element="<entry name='prueba_paco'/>"

try:
    xapi.set(xpath=xpath,
              element=element)
except pan.xapi.PanXapiError as msg:
    print('edit:', msg)
    sys.exit(1)

print("OK funciona el tag !!!")

### Definir una IPv4
#<request cmd="set" obj="/config/shared/address/entry[@name='ZR_ext_mds.edugain.org_IPv4']" cookie="1736877363563317"><ip-netmask>150.254.161.84</ip-netmask></request>
#
xpath = "/config/shared/address/entry[@name='ZR_prueba_paco_IPv4']"
element="<ip-netmask>22.22.22.22</ip-netmask>"

try:
    xapi.set(xpath=xpath,
              element=element)
except pan.xapi.PanXapiError as msg:
    print('edit:', msg)
    sys.exit(1)

print("OK funciona el LA IPv4 !!!")

## 
# Poner un TAG a un objeto
#paco@telmad.fw(active)# set shared address ZR_ext_mds.edugain.org_IPv4 tag "IPv4"
#(container-tag: shared container-tag: address container-tag: entry key-tag: name value: ZR_ext_mds.edugain.org_IPv4 container-tag: tag leaf-tag: member value: IPv4 pop-tag:)
#((eol-matched: . #t) (xpath-prefix: . /config) (context-inserted-at-end-p: . #f))
#(shared (address (entry (@ (name ZR_ext_mds.edugain.org_IPv4)) (tag (member IPv4)))))
#(member IPv4)
#<request cmd="set" obj="/config/shared/address/entry[@name='ZR_ext_mds.edugain.org_IPv4']/tag" cookie="1736877363563317"><member>IPv4</member></request>
 #

# Y definir un objeto compuesto
#
#<request cmd="set" obj="/config/shared/address-group/entry[@name='Red_ext_mds.edugain.org']/static" cookie="1736877363563317"><member>ZR_ext_mds.edugain.org_IPv4</member></request>
# 

