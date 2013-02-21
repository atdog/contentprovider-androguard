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
    apk_name = "/Users/atdog/Desktop/eva_3/com.jb.gosms.apk"
    eva_type = 1
    if len(sys.argv) == 3:
        apk_name = sys.argv[1]
        eva_type = sys.argv[2]

    # check apk file exist
    if not os.path.exists(apk_name):
        print ERROR_MSG_PREFIX + "APK not found: {}".format(apk_name)
        sys.exit(-1)

    print OK_MSG_PREFIX + "APK: {}".format(apk_name)
    print OK_MSG_PREFIX + "Start to get malicious actions..."

    a, d, dx = dm4.read_apk(apk_name)
#     a, d, dx = AnalyzeAPK(apk_name)
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
    broadcast_link = dm4.broadcast_link()
    dm4.intent_service_link = intent_service_link
    dm4.broadcast_link = broadcast_link
    # combine
    dm4.intent_service_link = dict(intent_service_link.items() + broadcast_link.items())

    # unique
    target_methods = list(set(dm4.get_target_methods()))


    print "Service link:", intent_service_link
    print "Broadcast link:", broadcast_link
    print "Hierarchy:", class_hierarchy
    print "Target {!s} methods:".format(len(target_methods)), target_methods

    permission_paths = []
    if eva_type == "1":
        permission_paths = dm4.dx.tainted_packages.search_methods("^Ljava/lang/.*$", "^valueOf$", "^\(Ljava/lang/String;\).*$")
    elif eva_type == "2":
#         permission_paths = dx.get_permissions(["SEND_SMS"])["SEND_SMS"]
        permission_paths = dm4.dx.tainted_packages.search_methods("^Landroid/telephony/SmsManager;$", "^sendTextMessage$", "^\(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;\)V$")
    elif eva_type == "3":
        permission_paths = dx.get_permissions(["INTERNET"])["INTERNET"]
    for i in range(0, len(permission_paths)):
#     for i in range(39, 40):
        path = permission_paths[i]
        print "Path ", i
        src_method = cm.get_method_ref(path.get_src_idx())
        src_class_name, src_method_name, src_descriptor = src_method.get_class_name(), src_method.get_name(), src_method.get_descriptor()
        print "Class:  " + src_class_name
        print "Method: " + src_method_name
        print "Descriptor: " + src_descriptor
        # Get analyzed method
        method = d.get_method_descriptor(src_class_name, src_method_name, src_descriptor)
        # androguard.core.bytecodes.dvm.EncodedMethod
        analyized_method = dx.get_method(method)
        #BasicBlocks.get(self):
        #   :rtype: return each basic block (:class:`DVMBasicBlock` object)
        blocks = analyized_method.get_basic_blocks().get()
        idx = 0
        query_index = 0
        query_block = None
        trace_var_list = None
        for block in blocks:
            instructions = block.get_instructions()
            for index in range(0, len(instructions)):
                ins = instructions[index]
                # get instruction node
                if idx == path.get_idx():
                    query_index = index
                    query_block = block
                    trace_var_list = dm4.get_instruction_variable(ins)

                    print "Ins:    0x{0:04x}".format(idx)," " + ins.get_name() + " / " + ins.get_output()
                    print OK_MSG_PREFIX + "Get the critical instruction"
                idx += ins.get_length()
        # trace back in block
        # case 1
        #   URL->URLConnection
        instructions = query_block.get_instructions()
        ins_output = instructions[query_index].get_output()
        if eva_type == "2":
            var_url = trace_var_list[1]
            print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(var_url)
            result = dm4.backtrace_variable(analyized_method, path.get_idx(), var_url)
            dm4.check_target_in_result(target_methods, result)

            var_url = trace_var_list[2]
            print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(var_url)
            result = dm4.backtrace_variable(analyized_method, path.get_idx(), var_url)
            dm4.check_target_in_result(target_methods, result)
        else:
            var_url = trace_var_list[-1]
            print WARN_MSG_PREFIX + "\033[0;33mBacktrace ivar {}\033[0m".format(var_url)
            result = dm4.backtrace_variable(analyized_method, path.get_idx(), var_url)
            dm4.check_target_in_result(target_methods, result)
#         dm4.print_backtrace_result(result, 0)
#         dm4.print_backtrace_result(result)
        # seperated line
        print WARN_MSG_PREFIX + "\033[1;30m------------------------------------------------------\033[0m"
