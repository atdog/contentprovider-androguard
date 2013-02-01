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

    __builtin__.a, __builtin__.d, __builtin__.dx = dm4.read_apk(apk_name)
    # a: androguard.core.bytecodes.apk.APK
    # d: androguard.core.bytecodes.dvm.DalvikVMFormat
    # dx: androguard.core.analysis.analysis.uVMAnalysis

    __builtin__.cm = d.get_class_manager()

    for path in dx.get_permissions(["INTERNET"])["INTERNET"]:
        src_method = cm.get_method_ref(path.get_src_idx())
        src_class_name, src_method_name, src_descriptor = src_method.get_class_name(), src_method.get_name(), src_method.get_descriptor()
        print WARN_MSG_PREFIX + src_class_name, src_method_name, src_descriptor
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
                    print OK_MSG_PREFIX + "Get the critical instruction"
                idx += ins.get_length()
        # trace back in block
        # case 1
        #   URL->URLConnection
        instructions = query_block.get_instructions()
        ins_output = instructions[query_index].get_output()
        var_url = trace_var_list[-1]
        result = dm4.backtrace_variable(analyized_method, path.get_idx(), var_url)
        dm4.print_backtrace_result(result)
        # seperated line
        print WARN_MSG_PREFIX + "\033[1;30m------------------------------------------------------\033[0m"
