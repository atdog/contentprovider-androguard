#!/usr/bin/env python

import sys, os, re, androlyze
from androlyze import AnalyzeAPK
from androguard.core.analysis import analysis

# default value is 1000
sys.setrecursionlimit(100000)
apk_session_dir = "session/" 
ERROR_MSG_PREFIX = "\033[1;31m[!]\033[m "
OK_MSG_PREFIX = "\033[1;32m[+]\033[m "
WARN_MSG_PREFIX = "\033[1;33m[*]\033[m "

def read_apk(apk_name):
    """ Read apk file and return a, d, dx """
    apk_basename = os.path.basename(apk_name)
    apk_session_name = apk_session_dir + apk_basename

    # mkdir session
    if not os.path.isdir(apk_session_dir):
        os.system("mkdir '{}'".format(apk_session_dir))

    # check if session saved
    if not os.path.isfile(apk_session_name):
        a, d, dx = AnalyzeAPK(apk_name)
        androlyze.save_session([a, d, dx], apk_session_name)
    else:
        a, d, dx = androlyze.load_session(apk_session_name)

    return a, d, dx

def get_variable_list(method):
    """ Return local variable list and parameter list """
    # get number of local variables
    nb  = method.get_code().get_registers_size()

    # parameters pass in
    ret = method.proto.split(')')
    params = ret[0][1:].split()

    # NOT SAVE CLASS OF PARAMS YET
    if params:
        return [ "v{:d}".format(i) for i in range(0, nb - len(params)) ], [ "v{:d}".format(i) for i in range(nb - len(params), nb) ]
    else :
        return [ "v{:d}".format(i) for i in range(0, nb) ], []

def find_instruction_by_re(block, index, name_re, output_re):
    """
        Return the matched instruction block, index and re match object

        :param block: start match the instruction from this block

        :param index: start match the instruction from this index of this block

        :param name_re: regular expression to match string ins.get_name()

        :param output_re: regular expression to match string ins.get_output()

        :rtype: Tuple - block, index, match_obj
    """
    found_ins = None
    instructions = None
    re_match = None
    re_pattern = re.compile(output_re)
    # find URL init
    while found_ins is None:
        instructions = block.get_instructions()
        for index in xrange(index - 1, -1, -1):        
            ins = instructions[index]
            ins_output = ins.get_output()
            ins_name = ins.get_name()
            if re.match(name_re, ins_name):
                re_match = re_pattern.match(ins_output)
                # match regular_expression
                if re_match:
                    index = index
                    found_ins = ins
                    break

        if found_ins is None:
            block_list = block.get_prev()
            if len(block_list) > 1:
                # future work
                print WARN_MSG_PREFIX + "More than one block in previous block list"
            block = block_list[0][2]
            index = len(block.get_instructions())

    return block, index, re_match


if __name__ == "__main__" :
    print OK_MSG_PREFIX + "Start to get malicious actions..."
    apk_name = "/Users/atdog/Desktop/com.texty.sms-1.apk"

    a, d, dx = read_apk(apk_name)
    # a: androguard.core.bytecodes.apk.APK
    # d: androguard.core.bytecodes.dvm.DalvikVMFormat
    # dx: androguard.core.analysis.analysis.uVMAnalysis
    
    cm = d.get_class_manager()
    
    for path in dx.get_permissions(["INTERNET"])["INTERNET"]:
        src_method = cm.get_method_ref(path.get_src_idx())
        src_class_name, src_method_name, src_descriptor = src_method.get_class_name(), src_method.get_name(), src_method.get_descriptor()
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
        for block in blocks:
            instructions = block.get_instructions()
            for index in range(0, len(instructions)):
                ins = instructions[index]
                # get instruction node
                if idx == path.get_idx():
                    query_index = index
                    query_block = block
                    print OK_MSG_PREFIX + "Get the critical instruction"
                idx += ins.get_length()
    
        # trace back in block
        # case 1
        #   URL->URLConnection
        re_url_openconnection = re.compile("(.*), Ljava/net/URL;->openConnection\(\)Ljava/net/URLConnection")
    
        instructions = query_block.get_instructions()
        ins_output = instructions[query_index].get_output()
        match_url_openconnection = re_url_openconnection.match(ins_output)
        if match_url_openconnection:
            print OK_MSG_PREFIX + 'Match "Ljava/net/URL;->openConnection()"'
            var_url = match_url_openconnection.group(1)
            # find the instruction matching URL->openConnection 
            query_block, query_index, match_url_init = find_instruction_by_re(query_block, query_index, "invoke-direct", "{}, ([^ ,]*), Ljava/net/URL;-><init>\(Ljava/lang/String;\)V".format(var_url))
            # find URL.<init>
            trace_var = None
            if match_url_init:
                trace_var = match_url_init.group(1)
                print OK_MSG_PREFIX + 'Match "new java.net.URL(\033[1;34m{var}\033[0m)"'.format(var=trace_var)
            else:
                print ERROR_MSG_PREFIX + 'Not found URL init statement'
                # continue to next path if not match the url_init re
                continue
            # find move-result-object or iget-object
            local_list, param_list = get_variable_list(method)
            if trace_var in local_list:
                print WARN_MSG_PREFIX + "In local variables list: [ {} ]".format(' '.join([ ("\033[0;34m{}\033[m".format(i) if i == trace_var else i ) for i in local_list]))
                # trace back if in local_list
                query_block, query_index, re_match = find_instruction_by_re(query_block, query_index, "move-result-object|iget-object", "^"+trace_var) 
                # trace back found
                if re_match:
                    instructions = query_block.get_instructions()
                    print OK_MSG_PREFIX + "Found {idx!s}: {name} {output}".format(idx=query_index-1, name=instructions[query_index-1].get_name(), output=instructions[query_index-1].get_output())
                    print OK_MSG_PREFIX + "Found {idx!s}: {name} {output}".format(idx=query_index, name=instructions[query_index].get_name(), output=instructions[query_index].get_output())

                else:
                    print ERROR_MSG_PREFIX + 'Not found local variable init statement'
                    continue
            # jmp function if var in param_list
            elif trace_var in param_list:
                print WARN_MSG_PREFIX + "In parameters list: [ {} ]".format(' '.join([ ("\033[0;34m{}\033[m".format(i) if i == trace_var else i ) for i in param_list]))

        # not match any malicious pattern
        else:
            print ERROR_MSG_PREFIX + "Pattern not found"
        # seperated line
        print WARN_MSG_PREFIX + "..."
