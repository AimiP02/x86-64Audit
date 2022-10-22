"""

Created by i3r0ny@ 2022/10/22

"""

from prettytable import PrettyTable
from functable import *
from idaapi import *
import idc


start_version = """
____  ___ ______   ________           ________   _____    _____            .___.__  __   
\   \/  //  __  \ /  _____/          /  _____/  /  |  |  /  _  \  __ __  __| _/|__|/  |_ 
 \     / >      </   __  \   ______ /   __  \  /   |  |_/  /_\  \|  |  \/ __ | |  \   __|
 /     \/   --   \  |__\  \ /_____/ \  |__\  \/    ^   /    |    \  |  / /_/ | |  ||  |  
/___/\  \______  /\_____  /          \_____  /\____   |\____|__  /____/\____ | |__||__|  
      \_/      \/       \/                 \/      |__|        \/           \/           
                                                        coded by i3r0ny@                
"""

# 打印
def PrintFunc(func_name):
    string1 = "========================================"
    string2 = "========== Aduiting " + func_name + " "
    strlen = len(string1) - len(string2)
    return (string1 + "\n" + string2 + "=" * strlen + "\n" + string1)

# 获取function的地址
def GetFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != BADADDR:
        PrintFunc(func_name)
        return func_addr
    return False

def GetArgAddr(call_addr, num):
    x86condition = ["jn", "jz" , "jc", "jo", "js", "jp", "jr", "ja", "jb", "jg", "jl"]
    scan_deep = 50
    cnt = 0
    
    # if num >= len():
    return 1
        

def GetArg(start_addr, num):
    x86mov = ["mov", "lea"]
    arg_addr = GetArgAddr(start_addr, num)

def AuditFormat(call_addr, func_name, arg_num):
    addr = hex(call_addr)
    ret_list = [func_name, addr]
    local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        local_buf_size == "NULL"
    else:
        local_buf_size = hex(local_buf_size)
    
    
def AuditAddr(call_addr, func_name, arg_num):
    addr = hex(call_addr)
    ret_list = [func_name, addr]
    local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        local_buf_size = "Get failed"
    else:
        local_buf_size = hex(local_buf_size)
    for num in range(arg_num):
        ret_list.append(GetArg(call_addr, num))
    ret_list.append(local_buf_size)
    return ret_list
    

def audit(func_name):
    func_addr = GetFuncAddr(func_name)
    # 如果function不存在，返回False
    if func_addr == False:
        return False
    arg_num = 0
    # 提取出函数的argc
    if func_name in one_arg_function:
        arg_num = 1
    elif func_name in two_arg_function:
        arg_num = 2
    elif func_name in three_arg_function:
        arg_num = 3
    elif func_name in format_function_offset_dict:
        arg_num = format_function_offset_dict[func_name] + 1
    else:
        print("The {} function didn't write in the describe arg num of function array, please add it in 'functable.py'.".format(func_name))
        return
    
    table_head = ["func_name", "addr"]
    for num in range(arg_num):
        table_head.append("arg" + str(num + 1))
    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)
    
    # 交叉引用获取地址
    got_addr = get_first_dref_to(func_addr)
    plt_addr = get_first_dref_to(got_addr)
    call_addr = get_first_cref_to(plt_addr)
    
    # print(got_addr, plt_addr, call_addr)

    while call_addr != BADADDR:
        idc.set_color(call_addr, idc.CIC_ITEM, 0x90e667)
        
        Mnemonics = idc.print_insn_mnem(call_addr)
        
        if Mnemonics == "call":
            if func_name in format_function_offset_dict:
                info = AuditFormat(call_addr, func_name, arg_num)
            else:
                info = AuditAddr(call_addr, func_name, arg_num)
            table.add_row(info)
        call_addr = get_next_cref_to(plt_addr, call_addr)
    
    print(table)
        

def x86_64_audit():
    print(start_version)
    
    print("Auditing dangerous functions...")
    
    for func in dangerous_functions:
        audit(func)
    
    # print("Auditing attention functions...")
    # for func in attention_function:
    #     audit(func)
    
    # print("Auditing command execution functions...")
    # for func in command_execution_function:
    #     audit(func)
    
    print("Auditing has finished. The results were showed.")

if __name__ == "__main__":
      breakpoint()
      x86_64_audit()