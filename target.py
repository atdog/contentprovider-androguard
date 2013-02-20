#!/usr/bin/env python

import sys, os, re, androlyze
import __builtin__
import json
from androlyze import AnalyzeAPK
from androguard.core.analysis import analysis
import dm4

# default value is 1000
sys.setrecursionlimit(100000)
apk_session_dir = "session/" 
ERROR_MSG_PREFIX = "\033[1;31m[!]\033[m "
OK_MSG_PREFIX = "\033[1;32m[+]\033[m "
WARN_MSG_PREFIX = "\033[1;33m[*]\033[m "


if __name__ == "__main__" :
    print OK_MSG_PREFIX + "Start to get malicious actions..."
    apk_name = "/Users/atdog/Desktop/com.texty.sms-1.apk"
#     apk_name = "/Users/atdog/Desktop/eva_3/jp.naver.line.android.apk"

    a, d, dx = dm4.read_apk(apk_name)
    # a: androguard.core.bytecodes.apk.APK
    # d: androguard.core.bytecodes.dvm.DalvikVMFormat
    # dx: androguard.core.analysis.analysis.uVMAnalysis

    cm = d.get_class_manager()
    dm4.a, dm4.d, dm4.dx, dm4.cm = a, d, dx, cm

    class_hierarchy = dm4.construct_class_hierarchy()
    dm4.class_hierarchy = class_hierarchy

    intent_service_link = None
    dm4.intent_service_link = None

    intent_service_link = dm4.service_link()
    dm4.broadcast_link()
    dm4.intent_service_link = intent_service_link
    
    print dm4.get_target_methods()
