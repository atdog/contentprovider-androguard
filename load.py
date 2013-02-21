#!/usr/bin/env python

import sys, os, re, androlyze
import __builtin__
from androlyze import AnalyzeAPK
from androguard.core.analysis import analysis
import dm4

# default value is 1000
sys.setrecursionlimit(100000)
apk_session_dir = "session/" 
ERROR_MSG_PREFIX = "\033[1;31m[!]\033[m "
OK_MSG_PREFIX = "\033[1;32m[+]\033[m "
WARN_MSG_PREFIX = "\033[1;33m[*]\033[m "

def load(apk_name):
    # check apk file exist
    if not os.path.exists(apk_name):
        print ERROR_MSG_PREFIX + "APK not found: {}".format(apk_name)
        sys.exit(-1)

    print OK_MSG_PREFIX + "Load APK: {}".format(apk_name)

    a, d, dx = dm4.read_apk(apk_name)
#     a, d, dx = AnalyzeAPK(apk_name)
    # a: androguard.core.bytecodes.apk.APK
    # d: androguard.core.bytecodes.dvm.DalvikVMFormat
    # dx: androguard.core.analysis.analysis.uVMAnalysis

    cm = d.get_class_manager()
    dm4.a, dm4.d, dm4.dx, dm4.cm = a, d, dx, cm

    return a, d, dx, cm

def get_path_info(path):
    analyzed_method = dm4.get_analyzed_method_from_path(path)

    method = analyzed_method.get_method()

    ins = dm4.get_instruction_by_idx(analyzed_method, path.get_idx())
    # print source class & method name
    print OK_MSG_PREFIX + "Class  {0}".format(method.get_class_name())
    print OK_MSG_PREFIX + "Method {0}".format(method.get_name())
    print OK_MSG_PREFIX + "Desc   {0}".format(method.get_descriptor())
    print OK_MSG_PREFIX + "Offset 0x{0:04x}".format(path.get_idx())
    print OK_MSG_PREFIX + "Instruction {} {}".format(ins.get_name(), ins.get_output())
