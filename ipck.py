#!/usr/bin/env python3

# coding: -*- utf-8 -*-

import os
import subprocess
import re
import json
import argparse
import datetime

from pathlib import Path

class IfIpInfo:
    __KEY_IFACES = "ifaces"
    __KEY_TIME   = "time"
    __PROTOCOL_V4 = "inet"
    __PROTOCOL_V6 = "inet6"
    
    def __init__(self, ifname, json_dir):
        self.__ifMap = {}
        self.__prevMap = {}
        trgdir = Path(json_dir)
        if not trgdir:
            filepath = __file__
            trgdir =  Path(os.path.dirname(filepath))
        self.__trgdir = trgdir
        self.__recpath = trgdir.joinpath(Path('{}.json'.format(ifname)))
        self.__target_if = ifname
        self.__goneList = None
        self.__appearList = None
        self.__remainList = None
        self.__is_changed = False

    def take_ifconfig_snapshot(self):
        p = subprocess.Popen(
                "ifconfig",
                #stdin=subprocess.PIPE
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, 
                env={'LANG':'C'},
                shell=True
            )
        (out, err) = p.communicate()
        str_out = out.decode("utf-8", "ignore")
        str_out_lines = str_out.splitlines()
        
        ifptn = re.compile(r"^(\w+)\:")
        ipv4ptn = re.compile(r"inet[ ]+([.0-9]+)[ ]+netmask")
        ipv6ptn = re.compile(r"inet6[ ]+([:0-9a-fA-F]+)[ ]+prefixlen") 
        cur_if_name = None
        inet4 = []
        inet6 = []
        for line in str_out_lines:
            if line.startswith(' '):
                if cur_if_name:
                    # print('data : {}'.format(line) )
                    mc4 = ipv4ptn.search(line)
                    if mc4:
                        if mc4.lastindex > 0:
                            #print(mc4.group(1))
                            inet4.append(mc4.group(1))
                    else:
                        mc6 = ipv6ptn.search(line)
                        if mc6:
                            if mc6.lastindex > 0:
                                #print(mc6.group(1))
                                inet6.append(mc6.group(1))
            else:
                mc = ifptn.search(line)
                if (mc):
                    if mc.lastindex == 1:
                        ifnm = mc.group(1)
                        if cur_if_name:
                            if cur_if_name != ifnm:
                                self.__commit_info(cur_if_name, inet4, inet6)
                                inet4.clear()
                                inet6.clear()
                            
                        if ifnm == self.__target_if:
                            cur_if_name = ifnm
                        else:
                            cur_if_name = None
        if cur_if_name:
            self.__commit_info(cur_if_name, inet4, inet6)
    
    def save_current_snapshot(self):
        # mkdir -p
        os.makedirs(self.__trgdir, exist_ok=True)
        if len(self.__ifMap) > 0:
            with open(self.__recpath, 'w', encoding='utf-8') as fp:
                json.dump(self.__ifMap, fp)
            
    def load_previous_snapshot(self):
        if os.path.exists(self.__recpath):
            with open(self.__recpath, 'r', encoding='utf-8') as fp:
                self.__prevMap = json.load(fp)
    
    def calc_addr_difference(self, protocol, type):
        (appList, remList, goneList) = self.__calc_changed_ipaddr(protocol)
        filterop = self.__is_true
        if protocol == 'inet6':
            if (type == 'gua'):
                filterop = self.__is_gua
            elif (type == 'ula'):
                filterop = self.__is_ula
            self.__goneList   = list(filter(filterop, goneList))
            self.__appearList = list(filter(filterop, appList))
            self.__remainList = list(filter(filterop, remList))
        else:
            self.__goneList   = goneList
            self.__appearList = appList
            self.__remainList = remList
        
        # copy primary ip
        prevPm = None
        keyfmt = '{}_primary'
        if self.__KEY_IFACES in self.__prevMap:
            node = self.__prevMap[self.__KEY_IFACES]
            if self.__target_if in node:
                prevPm = node[self.__target_if]
                
        newPm = None
        if self.__KEY_IFACES in self.__prevMap:
            node = self.__ifMap[self.__KEY_IFACES]
            if self.__target_if in node:
                newPm = node[self.__target_if]

        prim_addr = None
        if newPm:
            if prevPm:
                prots = [self.__PROTOCOL_V6, self.__PROTOCOL_V4]
                for prot in prots:
                    primkey = keyfmt.format(prot)
                    if primkey in prevPm:
                        newPm[primkey] = prevPm[primkey]
            
            remSize  = len(self.__remainList)
            appSize  = len(self.__appearList)
            goneSize = len(self.__goneList)
            
            primKey = keyfmt.format(protocol)
            cur_primary = None
            if primKey in newPm:
                cur_primary = newPm[primKey]
                if cur_primary in self.__remainList:
                    pass 
                else:
                    cur_primary = None
            if not(cur_primary):
                primary_candidate = None
                if remSize > 0:
                    primary_candidate = next(iter(self.__remainList))
                elif appSize > 0:
                    primary_candidate  = next(iter(self.__appearList))
                newPm[primKey] = primary_candidate
                
            self.__is_changed = bool(appSize != 0 or goneSize != 0) 
            prim_addr = newPm[primKey]
        return (self.__is_changed, prim_addr)
    
    def get_state_lists(self):
        return (self.__appearList, self.__remainList, self.__goneList)
    
    def get_ifconf_info(self):
        return self.__ifMap
    
    def __calc_changed_ipaddr(self, protocol):
        ret = set()
        prev_ips: list = []
        cur_ips: list = []
        if self.__KEY_IFACES in self.__prevMap:
            previfs = self.__prevMap[self.__KEY_IFACES]
            if self.__target_if in previfs:
                ifips = previfs[self.__target_if]
                if protocol in ifips:
                    prev_ips = ifips[protocol]
        if self.__KEY_IFACES in self.__ifMap:
            curifs = self.__ifMap[self.__KEY_IFACES]
            if self.__target_if in curifs:
                ifips = curifs[self.__target_if]
                if protocol in ifips:
                    cur_ips = ifips[protocol]  
        
        prevSet = set(prev_ips)
        curSet  = set(cur_ips)
        remain = list(prevSet & curSet)
        gone   = list(prevSet - curSet)
        appear = list(curSet - prevSet)
        return (appear, remain, gone)
    
    def __is_gua(self, addr: str) -> bool :
        return addr.startswith("2")
    
    def __is_ula(self, addr: str) -> bool :
        return (addr.startswith("fd") or addr.startswith("fc")) 
    
    def __is_true(self, addr: str) -> bool :
        return True
        
    def __commit_info(self, ifname, v4list, v6list):
        ipkinds = { }
        ipkinds[self.__PROTOCOL_V4] = v4list.copy()
        ipkinds[self.__PROTOCOL_V6] = v6list.copy()
        dtnow = datetime.datetime.now().astimezone()
        if not(self.__KEY_IFACES in self.__ifMap):
            self.__ifMap[self.__KEY_IFACES] = {}
        self.__ifMap[self.__KEY_IFACES][ifname] = ipkinds
        self.__ifMap[self.__KEY_TIME] = dtnow.isoformat()


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='ip-address change monitor.')
    parser.add_argument('-d', '--dir', default='', help='A directory path that save current state snapshot file into.')
    parser.add_argument('-f','--family', default='inet6', choices=['inet', 'inet6'], help='IP protocol family.')
    parser.add_argument('-t','--type', default='gua', choices=['gua', 'ula'], help='IPv6 address type.')
    parser.add_argument('-n','--noupdate', action='store_true', help='Checking without updating snapshot.')
    parser.add_argument('-s','--simple', action='store_true', help='Print only estimated stable IP address.')
    parser.add_argument('-b','--bool', action='store_true', help='Print only whether IP address has been changed or not.')
    parser.add_argument('ifname', help='The interface name for checking.')
    args = parser.parse_args()
    
    ipinfo = IfIpInfo(ifname=args.ifname, json_dir=args.dir) 
    ipinfo.take_ifconfig_snapshot()
    ipinfo.load_previous_snapshot()
    (is_changed, primary_addr) = ipinfo.calc_addr_difference(args.family, args.type)
    if (args.noupdate == False):
        ipinfo.save_current_snapshot()
     
    (appear, remains, gone) = ipinfo.get_state_lists()    
    if (args.simple == True) :
        print(primary_addr)
    elif (args.bool == True) :
        print (is_changed)
    else :
        print('ip appears -> {}'.format(appear))
        print('ip remains -> {}'.format(remains))
        print('ip gone    -> {}'.format(gone))
        print('estimated stable address   : {}'.format(primary_addr))
        print('different from previous ss : {}'.format(is_changed))

