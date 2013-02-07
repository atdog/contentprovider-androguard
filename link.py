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

    paths = dx.tainted_packages.search_methods("^Landroid/content/Context;$", "^startService$", "^\(Landroid/content/Intent;\)Landroid/content/ComponentName;$")

    for path in paths:
        # get analyzed method
        analyzed_method = dm4.get_analyzed_method_from_path(path)
        method = analyzed_method.get_method()

        # print source class & method name
        print OK_MSG_PREFIX + "Class  {0}".format(method.get_class_name())
        print OK_MSG_PREFIX + "Method {0}".format(method.get_name())
        print OK_MSG_PREFIX + "Offset 0x{0:04x}".format(path.get_idx())

        # get variable name
        target_ins = dm4.get_instruction_by_idx(analyzed_method, path.get_idx())
        intent_variable = dm4.get_instruction_variable(target_ins)[1]

        print WARN_MSG_PREFIX + target_ins.get_name(), target_ins.get_output()
        print WARN_MSG_PREFIX, dm4.get_instruction_variable(target_ins)

        print WARN_MSG_PREFIX, intent_variable
        result = dm4.backtrace_variable(analyzed_method, path.get_idx(), intent_variable)
        dm4.print_backtrace_result(result, 0)
        dm4.print_backtrace_result(result)
        print WARN_MSG_PREFIX + "--------------------------------------------------"
