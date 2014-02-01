#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
 @author:   hty0807@gmail.com
"""
import time
import sys
import os

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

def md5(self, key):
    return hashlib.md5(key).hexdigest()
