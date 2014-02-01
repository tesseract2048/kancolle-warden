#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
 @author:   hty0807@gmail.com
"""
# require requests 1.2.1, higher version would not compat with https proxies
import requests
import logging
import httplib
import json
import re
import time
import threading
import sys
import signal
import os
import hashlib

VERSION = 'EUSTIA'
DATE = 'Feb 1st, 2014'

if os.name == 'nt':
    DEFAULT, BLACK, BLUE, LIGHTGREEN, LIGHTCYAN, LIGHTRED, MAGENTA, BROWN, LIGHTGRAY, DARKGRAY, LIGHTBLUE, GREEN, CYAN, RED, LIGHTMAGENTA, YELLOW, WHITE = range(17)
    try:
        from ctypes import *
        from win32con import *
    except:
        pass
    CloseHandle = windll.kernel32.CloseHandle
    GetStdHandle = windll.kernel32.GetStdHandle
    GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo
    SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
    STD_OUTPUT_HANDLE = -11
    class COORD(Structure):
        _fields_ = [
            ('X', c_short),
            ('Y', c_short),
        ]

    class SMALL_RECT(Structure):
        _fields_ = [
            ('Left', c_short),
            ('Top', c_short),
            ('Right', c_short),
            ('Bottom', c_short),
        ]

    class CONSOLE_SCREEN_BUFFER_INFO(Structure):
        _fields_ = [
            ('dwSize', COORD),
            ('dwCursorPosition', COORD),
            ('wAttributes', c_uint),
            ('srWindow', SMALL_RECT),
            ('dwMaximumWindowSize', COORD),
        ]

else:
    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

def println(msg, color):
    dt = time.strftime('%Y-%m-%d %H:%M:%S')
    msg = '[%s] %s' % (dt, msg)
    if os.name == 'nt':
        # windows behavior
        hconsole = GetStdHandle(STD_OUTPUT_HANDLE)
        cmd_info = CONSOLE_SCREEN_BUFFER_INFO()
        GetConsoleScreenBufferInfo(hconsole, byref(cmd_info))
        old_color = cmd_info.wAttributes
        fore = color
        if fore: fore = fore - 1
        else: fore = old_color & 0x0F
        back = 1
        if back: back = (back - 1) << 4
        else: back = old_color & 0xF0
        SetConsoleTextAttribute(hconsole, fore + back)
        print msg
        SetConsoleTextAttribute(hconsole, old_color)
    else:
        # linux / osx behavior
        print '\x1b[1;3%sm%s\x1b[0m' % (color, msg)
        sys.stdout.flush()

class ClientSimulator:
    def __init__(self, proxy):
        self.worldaddrs = {
            1: '203.104.105.167',
            2: '125.6.184.15',
            3: '125.6.184.16',
            4: '125.6.187.205',
            5: '125.6.187.229',
            6: '125.6.187.253',
            7: '125.6.188.25',
            8: '203.104.248.135',
            9: '125.6.189.7',
            10: '125.6.189.39',
            11: '125.6.189.71',
            12: '125.6.189.103',
            13: '125.6.189.135',
            14: '125.6.189.167',
            15: '125.6.189.215'
        }
        self.mutex = threading.Lock()
        self.membercookie = None
        self.serveraddr = None
        self.inbattle = False
        if proxy is None:
            println('WARNING: not using any proxy', YELLOW)
            self.proxies = None
        else:
            println('proxy enabled: %s' % proxy, YELLOW)
            self.proxies = {'http': proxy, 'https': proxy}

    def __timestamp(self):
        d = long(time.time() * 1000)
        return str(d)

    def __raw_request(self, url, method, params, cookies, **kwargs):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip,deflate,sdch',
            'Accept-Langauge': 'en-US,en;q=0.8'
        }
        if 'host' in kwargs:
            headers['Host'] = kwargs['host']
        if method == 'POST':
            if 'data' in kwargs:
                headers['Content-Type'] = kwargs['type']
                data = kwargs['data']
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                data = params
                params = None
        else:
            data = None
        resp = requests.request(method, url, verify=False, headers=headers, params=params, data=data, proxies=self.proxies, cookies=cookies, allow_redirects=False)
        setcookie = None
        if 'Set-Cookie' in resp.headers:
            setcookie = resp.headers['Set-Cookie']
        return resp.text, setcookie

    def __request(self, method, params):
        if self.serveraddr is None:
            raise Exception('no world assigned')
        if self.token is None:
            raise Exception('world not logged in')
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'http://%s/kcs/port.swf?version=1.5.1' % self.serveraddr,
            'Origin': 'http://%s' % self.serveraddr
        }
        fields = {
            'api_verno': 1,
            'api_token': self.token
        }
        if params is not None:
            for key in params:
                fields[key] = params[key]
        url = "http://%s/kcsapi/%s" % (self.serveraddr, method)
        while True:
            try:
                resp = requests.request('POST', url, verify=False, headers=headers, data=fields, proxies=self.proxies)
                data = resp.text[(resp.text.find('=') + 1):]
                data = json.loads(data)
                break
            except Exception, e:
                println('network problem, retry in 5 secs', YELLOW)
                time.sleep(5)
                continue
        if data['api_result'] != 1:
            raise Exception('error occured during api request')
        return data

    def __make_request(self, method, params):
        resp = self.__raw_request('http://osapi.dmm.com/gadgets/makeRequest', method, params, self.membercookie)[0]
        data = json.loads(resp[resp.find('{'):])
        for key in data:
            val = data[key]
            if val['rc'] != 200:
                raise Exception('error occured during makeRequest')
            body = val['body']
            body = body[(body.find('=') + 1):]
            apidata = json.loads(body)
            return apidata
        return None

    def login(self, dmmid, dmmpass):
        println('logging in as %s...' % dmmid, CYAN)
        resp = self.__raw_request('https://www.dmm.com/my/-/login', 'GET', None, None)[0]
        mch = re.search('name="token" value="([^"]+)"', resp)
        token = mch.group(1)
        println('token GET!', GREEN)
        params = {'token': token, 'login_id': dmmid, 'save_login_id': 1, 'password': dmmpass, 'save_password': 1}
        cookies = {'ckcy': '1', 'check_open_login': '1'}
        resp = self.__raw_request('https://www.dmm.com/my/-/login/auth/', 'POST', params, cookies)
        if resp[1] is None:
            raise Exception("incorrect username or password")
        setcookie = resp[1].split(',')
        self.membercookie = {'ckcy': '1', 'check_open_login': '1', 'sc_evar18': '3'}
        for seg in setcookie:
            if seg.find(' GMT;') > 0:
                continue
            cols = seg.split(';')
            ins = cols[0].strip()
            key = ins[0:ins.find('=')]
            value = ins[(ins.find('=') + 1):]
            self.membercookie[key] = value
        println('session & cookie GET!', GREEN)
        self.logingame()

    def logingame(self):
        println('logging into game...', CYAN)
        resp = self.__raw_request('http://www.dmm.com/netgame/social/-/gadgets/=/app_id=854854/', 'GET', None, self.membercookie)[0]
        mch = re.search('<img src="([^"]*)" width="1" height="1" />', resp)
        if mch is None:
            raise Exception('incorrect account or password!')
        log = mch.group(1)
        mch = re.search('URL       : "([^"]*)"', resp, re.MULTILINE)
        if mch is None:
            raise Exception('no url url found in gadgets')
        self.ifr = mch.group(1)
        mch = re.search('OWNER_ID  : (\\d*)', resp, re.MULTILINE)
        if mch is None:
            raise Exception('no ownerid url found in gadgets')
        self.uid = mch.group(1)
        mch = re.search('ST        : "([^"]*)"', resp, re.MULTILINE)
        if mch is None:
            raise Exception('no st url found in gadgets')
        st = mch.group(1)
        println('gadget loaded!', GREEN)
        self.__raw_request(log, 'GET', None, self.membercookie)
        self.__raw_request(self.ifr, 'GET', None, self.membercookie)
        self.__raw_request('http://osapi.dmm.com/social/rpc', 'POST', {'st': st}, self.membercookie, data='[{"method":"people.get","params":{"userId":["@viewer"],"groupId":"@self","fields":["userType","id","name","thumbnailUrl","id","displayName"]},"id":"viewer"}]', type='application/json')
        params = {
            'refresh': 3600, 
            'url': 'http://203.104.105.167/kcsapi/api_world/get_id/%s/1/%s' % (self.uid, self.__timestamp()),
            'httpMethod': 'GET',
            'headers': '',
            'postData': '',
            'authz': '',
            'st': '',
            'contentType': 'JSON',
            'numEntries': '3',
            'getSummaries': 'false',
            'signOwner': 'true',
            'signViewer': 'true',
            'gadget': 'http://203.104.105.167/gadget.xml',
            'container': 'dmm',
            'bypassSpecCache': '',
            'getFullHeaders': 'false'
        }
        data = self.__make_request('GET', params)
        if 'api_data' not in data:
            raise Exception("server is down, or don't you have account?")
        self.worldid = data['api_data']['api_world_id']
        self.serveraddr = self.worldaddrs[self.worldid]
        println('world info GET! world id: %s, ip: %s' % (self.worldid, self.serveraddr), GREEN)
        self.loginworld(st)

    def loginworld(self, st):
        println('connecting to world...', CYAN)
        params = {
            'url': 'http://%s/kcsapi/api_auth_member/dmmlogin/%s/1/%s' % (self.serveraddr, self.uid, self.__timestamp()),
            'httpMethod': 'GET',
            'headers': '',
            'postData': '',
            'authz': 'signed',
            'st': st,
            'contentType': 'JSON',
            'numEntries': '3',
            'getSummaries': 'false',
            'signOwner': 'true',
            'signViewer': 'true',
            'gadget': 'http://203.104.105.167/gadget.xml',
            'container': 'dmm',
            'bypassSpecCache': '',
            'getFullHeaders': 'false',
            'oauthState': ''
        }
        data = self.__make_request('POST', params)
        self.token = data['api_token']
        println('api_token GET!', GREEN)
        println('successfully logged in.', GREEN)

    def deckport(self):
        if self.inbattle:
            return
        data = self.__request('api_get_member/deck_port', None)
        idledecks = ''
        livedecks = ''
        for deck in data['api_data']:
            mission = deck['api_mission']
            if mission[0] == 2:
                println('deck %s is coming back from mission %s...' % (deck['api_id'], mission[1]), YELLOW)
                self.result(mission[1], deck['api_id'])
            elif mission[0] == 1:
                livedecks += str(deck['api_id']) + ',' 
            elif mission[0] == 0:
                idledecks += str(deck['api_id']) + ','
        println('deck(s) on mission: %s, deck(s) idle: %s' % (livedecks, idledecks), WHITE)

    def result(self, missionid, deckid):
        data = self.__request('api_req_mission/result', {'api_deck_id': deckid})
        data = data['api_data']
        exp = data['api_get_exp']
        clearresult = data['api_clear_result']
        material = data['api_get_material']
        if clearresult == 0:
            println('mission failed, Exp: %s GET! better luck next time.' % exp, RED)
        else:
            println('Material: %s, %s, %s, %s GET! Exp: %s GET!' % (material[0], material[1], material[2], material[3], exp), GREEN)
        self.charge(data['api_ship_id'])
        self.startmission(missionid, deckid)

    def getincentive(self):
        self.__request('api_req_member/get_incentive', None)

    def start(self):
        self.__request('api_start', None)

    def startmission(self, missionid, deckid):
        self.__request('api_req_mission/start', {'api_deck_id': deckid, 'api_mission_id': missionid})
        println('new mission started, deck: %d, mission: %d' % (deckid, missionid), GREEN)

    def __process_map_move(self, data):
        eventid = data['api_event_id']
        if eventid == 4:
            println('normal war start!', RED)
            self.battle(1)
        elif eventid == 5:
            println('boss war start!', RED)
            self.battle(1)
        elif eventid == 2:
            itemget = data['api_itemget']
            println('item GET! usemst: %s, count: %s' % (itemget['api_usemst'], itemget['api_getcount']), RED)
            self.mapnext()

    def battle(self, formation):
        data = self.__request('api_req_sortie/battle', {'api_formation': formation})
        self.battleresult()

    def battleresult(self):
        data = self.__request('api_req_sortie/battleresult', None)
        data = data['api_data']
        println('battle end! rank: %s' % data['api_win_rank'], RED)
        if 'api_get_ship' in data:
            getship = data['api_get_ship']
            println('new ship %s GET!' % getship['api_ship_name'], RED)
        self.endbattle()

    def endbattle(self):
        self.inbattle = False
        self.logincheck()

    def mapstart(self, formationid, deckid, mapno, areaid):
        self.inbattle = True
        println('出發, %s-%s! ' % (mapno, areaid), CYAN)
        data = self.__request('api_req_map/start', {'api_formationid': formationid, 'api_deck_id': deckid, 'api_mapinfo_no': mapno, 'api_maparea_id': areaid})
        data = data['api_data']
        self.__process_map_move(data)

    def mapnext(self):
        data = self.__request('api_req_map/next', None)
        data = data['api_data']
        self.__process_map_move(data)

    def charge(self, ships):
        shipid = ''
        for id in ships:
            if id == -1:
                continue
            shipid += str(id) + ','
        if shipid.endswith(','):
            shipid = shipid[0:-1]
        data = self.__request('api_req_hokyu/charge', {'api_kind': 3, 'api_id_items': shipid})
        data = data['api_data']
        material = data['api_material']
        println('ship(s) charged, id: %s' % shipid, GREEN)
        println('current material: %s, %s, %s, %s' % (material[0], material[1], material[2], material[3]), GREEN)

    def ndock(self):
        data = self.__request('api_get_member/ndock', None)
        data = data['api_data']
        busyslots = []
        idleslots = []
        slottime = {}
        for entry in data:
            if entry['api_state'] == 0:
                idleslots.append(entry['api_id'])
            elif entry['api_state'] == 1:
                busyslots.append(entry['api_id'])
                completetime = entry['api_complete_time']
                remain = completetime - long(self.__timestamp()) + 5
                remain /= 1000
                slottime[entry['api_id']] = remain
        return idleslots, busyslots, slottime

    def repair(self, shipid, highspeed):
        idleslots, busyslots, slottime = self.ndock()
        if len(idleslots) == 0:
            return False, -1
        try:
            slot = idleslots[0]
            println('repair ship %s on slot %s' % (shipid, slot), GREEN)
            self.__request('api_req_nyukyo/start', {'api_ship_id': shipid, 'api_ndock_id': slot, 'api_highspeed': highspeed})
            idleslots, busyslots, slottime = self.ndock()
            return True, slottime[slot]
        except Exception, e:
            return False, -1

    def ship2(self):
        data = self.__request('api_get_member/ship2', {'api_sort_order': 2, 'api_sort_key': 1})
        shipdata = data['api_data']
        ships = {}
        for ship in shipdata:
            ships[ship['api_id']] = ship
        deckdata = data['api_data_deck']
        decks = {}
        for deck in deckdata:
            shipids = deck['api_ship']
            deckships = []
            for shipid in shipids:
                if shipid == -1:
                    continue
                deckships.append(ships[shipid])
            decks[deck['api_id']] = {'name': deck['api_name'], 'ships': deckships}
        return decks

    def logincheck(self):
        if self.inbattle:
            return
        self.__request('api_auth_member/logincheck', None)

    def lock(self):
        self.mutex.acquire()

    def unlock(self):
        self.mutex.release()

    def md5(self, key):
        return hashlib.md5(key).hexdigest()

class LoopWorker(threading.Thread):
    def __init__(self, client, name, interval):
        threading.Thread.__init__(self)
        self.client = client
        self.name = name
        self.interval = interval

    def run(self):
        println('%s every %s secs' % (self.name, self.interval), YELLOW)
        while True:
            time.sleep(self.interval)
            self.client.lock()
            method = getattr(self.client, self.name)
            method()
            self.client.unlock()

def getworker(client, name, interval):
    th = LoopWorker(client, name, interval)
    th.start()
    return th

def signal_handler(signal, frame):
    sys.exit(0)

def main():
    if len(sys.argv) < 3:
        println('Usage: kancolle_warden.py <username> <password> [proxy]', RED)
        return
    proxy = None
    if len(sys.argv) > 3:
        proxy = sys.argv[3]
    signal.signal(signal.SIGINT, signal_handler)
    println('KanColle WARDEN', CYAN)
    println('Version: %s (%s)' % (VERSION, DATE), CYAN)
    println('Please wait while client simulator is initializing...', YELLOW)
    client = ClientSimulator(proxy)
    try:
        client.login(sys.argv[1], sys.argv[2])
        client.getincentive()
        client.start()
    except Exception, e:
        println('ERROR: %s' % str(e), RED)
        return
    println('entered mission loop.', RED)
    threads = []
    threads.append(getworker(client, 'logincheck', 29))
    threads.append(getworker(client, 'deckport', 17))
    for th in threads:
        th.join()

main()
