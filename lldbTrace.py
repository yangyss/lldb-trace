#!/usr/bin/python3
# -*- encoding: utf-8 -*-
#@File    :   lldb-trace.py
#@Time    :   2021/06/25 22:16:01
#@Author  :   wt 

import re
import lldb
import shlex
import optparse
import threading
import ctypes
import os
 


log_default_path = '~/Desktop/' # 默认路径 , 

options = None
d_log_file = None   # fileName : Redirect debug log in d_log_file
d_log_file_name = None
t_log_file = None   # fileName : Redirect trace log in t_log_file
t_log_file_name = None
t_only_self_module = None 
t_parser_msgsend_parameters = None
ASLR = None
num_for_print_progress = 500 # 进度条

def log_d(msg): # debug log
    global d_log_file,options
    if options.log_type == 'debug':
        d_log_file.write(msg)
        d_log_file.write('\n')

def log_t(msg): # trace log
    global t_log_file
    t_log_file.write(msg)
    t_log_file.write('\n')

def log_c(msg): # console log
    global options
    if options.print_tracing_progress:
        print(msg)
    
def log_flush():
    global d_log_file,t_log_file
    if d_log_file is not None:
        d_log_file.flush()
    if t_log_file is not None:
        t_log_file.flush()

def dlog(msg):
    print("xxxxxxxxx-> {}".format(msg))

# 调试类型
TRACE_TYPE_Instrument = 0,
TRACE_TYPE_Function = 1,
# 设备架构 
DEVICE_BSD32 = 'BSD32'
DEVICE_BSD64 = 'BSD64'
DEVICE_Arm64 = 'Arm64'
DEVICE_x8664 = 'x86-64'
DEVICE_x8632 = 'x86-32'
# 调试中需要处理的 汇编指令信息
CONST_INS_call = 'call',
CONST_INS_jmp = 'jmp',
CONST_INS_condition_jmp = 'condition_jmp',
CONST_INS_syscall = 'syscall',
CONST_INS_end = 'func_end_mnemonic'
CONST_FUNC_NAME_ignore_list = 'ignore_func_name_list'
CONST_FUNC_NAME_protect_list = 'protect_func_name_list'
CONST_PRINT_obj = 'obj'
CONST_PRINT_char_star = 'char_star'
CONST_REGISTER_re = 're'
CONST_REGISTER_default_return_register = 'default_return_register'


# 断点列表里的 key 
CONST_BREAKPOINT_BREAKPOINE = 'breakpoint',
CONST_BREAKPOINT_INDEX = 'index',  # 引用计数

# deal_with 的 返回值
CONST_DEAL_WITH_error = 0,
CONST_DEAL_WITH_continue = 1,
CONST_DEAL_WITH_wait_breakpoint = 2,
CONST_DEAL_WITH_break = 3,
# check ins end type
CONST_CHECK_ins_default = 0
CONST_CHECK_ins_ret = 1
CONST_CHECK_ins_end_address =2


#########################################################
CONST_DEVICE_info_list = {
    DEVICE_BSD64 : {
        CONST_FUNC_NAME_ignore_list : ['printf','objc_unsafeClaimAutoreleasedReturnValue','objc_storeStrong'],
        CONST_FUNC_NAME_protect_list : {
            'objc_msgSend' : {
                # if trace function,need to analyse parameters. if parser_msgsend_parameters was true, need to analyse parameters too.
                CONST_PRINT_obj:['po [$x0 class]'],
                CONST_PRINT_char_star:['x1']
            }
        },
        CONST_REGISTER_re : [r'\b[xwd][0-9]{1,2}',r'\b[xwd][0-9]{1,2},',r'sp'], # r'\b[xw][0-9]{1,2}[,]{0,1}'
        CONST_REGISTER_default_return_register:'x0',

        CONST_INS_call : ['bl'],#,'bl',
        CONST_INS_jmp  : ['cb','b','tb'],#'b',
        CONST_INS_condition_jmp : ['b'],
        CONST_INS_syscall : ['svc'],#'svc'
        CONST_INS_end : ['ret']
    },
    DEVICE_Arm64 : {},
    DEVICE_x8664 : {},
    DEVICE_x8632 : {}
}
#########################################################
# 当前设备类型
DEVICE = DEVICE_BSD64
#########################################################


class WTListeningThread(threading.Thread):
    def __init__(self, wait_event, notify_event,listener,process):
        super(WTListeningThread, self).__init__()
        self.wait_event = wait_event
        self.notify_event = notify_event
        self.listener = listener
        self.process = process
        self.exiting = False
        self.wait_timeout = False

    def wait_timed_out(self):
        return self.wait_timeout

    def exit(self):
        self.exiting = True

    def run(self):
        steam :lldb.SBStream = lldb.SBStream()
        while True:
            self.wait_event.wait()
            self.wait_event.clear()
            if self.exiting:
                log_d('=>>>Listener thread was asked to exit, complying')
                self.notify_event.set()
                return
            while True:
                event = lldb.SBEvent()
                steam.Clear()
                log_d('=>>>Listener waiting for events')
                wait_result = self.listener.WaitForEvent(10, event)
                event.GetDescription(steam)
                log_d('=>>>Listener wait exited: {}, {}'.format(str(wait_result), steam.GetData()))

                if not wait_result:
                    log_d('=>>>Listener thread timed out waiting for notification')
                    self.wait_timeout = True
                    self.notify_event.set()
                    break
                processState = self.process.GetState()
                if processState == lldb.eStateStopped:
                    log_d('=>>>Listener detected process state change, but it is not stopped: {}'.format(str(processState)))
                    break
                log_d('=>>>Process not stopped, listening for the next event')
            log_d('=>>>Listener thread got event, notifying')
            self.notify_event.set()

def get_c_char_star(address):
    retstr = ''
    curr_addr = address
    while True:
        p = ctypes.cast(curr_addr,ctypes.POINTER(ctypes.c_char))
        value = p.contents.value
        if not (value[0] == 0) :
            retstr = retstr + chr(value[0])
            curr_addr = curr_addr + 1
        else:
            break
    return retstr

def handle_command(command,debugger:lldb.SBDebugger):
    log_d('handle_command -> command : {}'.format(command))
    interpreter:lldb.SBCommandInterpreter = debugger.GetCommandInterpreter()
    re_obj:lldb.SBCommandReturnObject = lldb.SBCommandReturnObject()
    interpreter.HandleCommand(command,re_obj)
    result = ''
    log_d('handle_command -> re_obj status : {}'.format(re_obj.GetStatus()))
    if re_obj.GetStatus() == lldb.eReturnStatusSuccessFinishResult:
        result = re_obj.GetOutput()
    # print('|{}|'.format(result.replace('\n','')))
    return result.replace('\n','')

def continue_and_wait_for_breakpoint(process, thread, listening_thread, wait_event, notify_event):
    wait_event.set()
    log_d("Process in state: {}".format(str(process.GetState())))
    process.Continue()
    log_d('Process continued, waiting for notification')
    notify_event.wait()
    notify_event.clear()
    log_d('Got notification, process in state: {}, sanity checks follow'.format(str(process.GetState())))
    if listening_thread.wait_timed_out():
        log_d('Listener thread exited unexpectedly')
        return False
    if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        log_d("Thread {} didn't stop due to a breakpoint".format(str(thread)))
        return False
    return True

def suspend_threads_escape_select_thread(process:lldb.SBProcess,flag:bool):
    select_thread :lldb.SBThread = process.GetSelectedThread()
    if flag :
        for item in process:
            if select_thread.GetThreadID() == item.GetThreadID():
                log_d('current run thread : {}'.format(item))
            else:
                log_d('Suspend thread : {}'.format(item))
                item.Suspend()
    else:
        log_d('Resume all threads.')
        for item in process:
            item.Resume()
    
            

def match_registers(text):
    now_list = []
    fileters = CONST_DEVICE_info_list[DEVICE][CONST_REGISTER_re]
    for item in fileters:
        find_result = re.finditer(item,text)
        match : str = ''
        for match in find_result:
            tmpStr = '{}'.format(match.group())
            if tmpStr.find(',') >= 0 :
                if not(tmpStr[:-1] in now_list) :
                    now_list.append(tmpStr[:-1])
            else:
                if not(tmpStr in now_list):
                    now_list.append(tmpStr)
    return now_list

class WTInstruction():
    def __init__(self, target, thread, frame,debugger,traceType=TRACE_TYPE_Instrument,traceMsgSend=False,endAddress=None):
        self.target:lldb.SBTarget = target
        self.thread:lldb.SBThread = thread
        self.frame:lldb.SBFrame = frame
        self.debugger:lldb.SBDebugger = debugger

        self.trace_type = traceType      # Trace 类型

        self.next_instruction:lldb.SBInstruction = None   # 下一条 instruction
        self.current_instruction:lldb.SBInstruction = None # 当前 instruction
        self.last_instruction:lldb.SBInstruction = None # 上一条 instruction

        self.begin_trace_address = None  # 开始 Trace 地址
        self.end_trace_address = []

        for item in re.split(';',endAddress):
            self.end_trace_address.append(int(item,16)) # 结束 Trace 地址

        # 包含 breakpoint : 以及 引用计数 used_num :
        self.breakpoint_list = {}   # 所有断点 的 list
        self.current_instruction_list = {} # 当前 symbol 下的 所有的 instruction 列表
        self.current_instruction_end_address_list = [] # 当前 symbol 下的 所有的  end_address 列表
        self.call_return_instruction_list = {} # tracing 中，所有函数返回的地址 列表

        self.current_module_name:str = None # 当前模块

        self.append_msg = '' # 附加消息

        self.print_index = 0
        self.print_text = '    '

    def increase_print_index(self):
        log_d('@@@@ increase print index. {} : {}'.format(self.print_index,self.print_index + 1))
        self.print_index = self.print_index + 1
        
    
    def check_in_call_return_instruction_list(self):
        pc = self.get_current_pc()
        if pc in self.call_return_instruction_list:
            log_d('@@@@ {} in call_return_instruction_list'.format(hex(pc)))
            return True
        log_d('@@@@ {} not in call_return_instruction_list'.format(hex(pc)))
        return False

    def decrease_print_index(self):
        log_d('@@@@ decrease print index. {} : {}'.format(self.print_index,self.print_index - 1))
        self.print_index = self.print_index - 1

    def check_str_in_arr(self,cur_str:str,cur_arr):
        for item in cur_arr:
            if cur_str.startswith(item):
                return True
        return False

    def init_env(self):

        frame :lldb.SBFrame = self.thread.GetSelectedFrame()
        symbol:lldb.SBSymbol = frame.GetSymbol()

        if self.current_module_name is None:
            self.current_module_name:str = '{}'.format(self.frame.GetModule())
            log_d('current module name : {}'.format(self.current_module_name))

        
        instructionlist : lldb.SBInstructionList = symbol.GetInstructions(self.target)
        # 清空 current_instruction_list  和 current_instruction_end_address_list
        if self.current_instruction_list:
            self.current_instruction_list = {}
            self.current_instruction_end_address_list = []
            
        # endaddress 加入到 end tracing 地址列表中
        cur_end_address = symbol.GetEndAddress().GetLoadAddress(self.target) - 4
        self.end_trace_address.append(cur_end_address)   
        
        # 把 返回指令的 地址 加入到 end tracing 地址列表中
        instruction :lldb.SBInstruction = None
        for instruction in instructionlist:
            address :lldb.SBAddress = instruction.GetAddress()
            cur_mnemonic:str = instruction.GetMnemonic(self.target)
            load_address = address.GetLoadAddress(self.target)
            if self.check_str_in_arr(cur_mnemonic,CONST_DEVICE_info_list[DEVICE][CONST_INS_end]):
                if not load_address in self.end_trace_address:
                    self.end_trace_address.append(load_address)


    # 获得当前 pc
    def get_current_pc(self):
        now_frame :lldb.SBFrame = self.thread.GetSelectedFrame()
        if now_frame:
            return now_frame.GetPC()
        return None

    # 判断当前 pc 是否在 list 中
    # 不在的话，更新所有 list
    def checkPCInList_transferCurrentSymbolInstrucionsToList(self,address):
        # current_instruction_list 为空，或者  cur_pc(有效) 不在 current_instruction_list 里
        if not self.current_instruction_list or (address and (not (address in self.current_instruction_list))) :
            frame :lldb.SBFrame = self.thread.GetSelectedFrame()
            symbol:lldb.SBSymbol = frame.GetSymbol()
            ################## 给 current_instruction_end_address_list 赋值
            # 获得 当前 symbol 下的 endAddress
            cur_end_address = symbol.GetEndAddress().GetLoadAddress(self.target) - 4
            log_d('cur symbol end addr : {}'.format(hex(cur_end_address)))
            self.current_instruction_end_address_list = []
            # 把 结束地址，加入到 current_instruction_end_address_list 中
            self.current_instruction_end_address_list.append(cur_end_address)

            # 给 current_instruction_list 赋值
            # 获得 当前 symbol 下的 instructionlist
            instructionlist : lldb.SBInstructionList = symbol.GetInstructions(self.target)

            # 清空 current_instruction_list
            if self.current_instruction_list:
                self.current_instruction_list = {}
                self.current_instruction_end_address_list = {}

            instruction :lldb.SBInstruction = None            
            # 处理 所有的 instruction，
            for instruction in instructionlist:
                address :lldb.SBAddress = instruction.GetAddress()
                cur_mnemonic:str = instruction.GetMnemonic(self.target)
                load_address = address.GetLoadAddress(self.target)
                self.current_instruction_list[load_address] = instruction  

            return False
        return True

    def updata_instruction_instructionList(self):
        cur_pc = self.get_current_pc()     
        self.checkPCInList_transferCurrentSymbolInstrucionsToList(cur_pc)

        if cur_pc in self.current_instruction_list:
            self.current_instruction = self.current_instruction_list[cur_pc]
        else:
            self.current_instruction = None


    def clean_env(self):
        for item in self.breakpoint_list.values():
            breakpoint :lldb.SBBreakpoint = item[CONST_BREAKPOINT_BREAKPOINE]
            self.target.BreakpointDelete(breakpoint.GetID())     
        self.breakpoint_list = {}


    def deal_with(self):
        return self.deal_with_ins()

    def updata_last_instruction(self):
        self.last_instruction = self.current_instruction

    def get_current_symbol_name(self):
        frame:lldb.SBFrame = self.thread.GetSelectedFrame()
        sym:lldb.SBSymbol = frame.GetSymbol()
        return sym.GetName()

    def get_next_instruction(self):
        pc = self.get_current_pc()
        size = self.current_instruction.GetByteSize()
        next_pc = pc + size
        self.checkPCInList_transferCurrentSymbolInstrucionsToList(next_pc)
        if next_pc in self.current_instruction_list:
            self.next_instruction = self.current_instruction_list[next_pc]
        else:
            self.next_instruction = None

    def print_tracing_progress(self,count):
        # 当前trace的总行数 内存地址:文件地址: <函数名>
        global ASLR
        mem_addr = 0
        file_addr = 0
        if self.current_instruction:
            mem_addr = self.current_instruction.GetAddress().GetLoadAddress(self.target)
        if not (mem_addr == 0) :
            file_addr = mem_addr - ASLR   
        out_str = '{: <10}  {} : {} <{}>'.format(count,hex(mem_addr),hex(file_addr),self.get_current_symbol_name())
        log_c(out_str)

    def log_current_instruction(self,cur_pc):
        cur_mnemonic:str = self.current_instruction.GetMnemonic(self.target)
        cur_operands:str = self.current_instruction.GetOperands(self.target)
        aligns = self.print_text * self.print_index
        if self.last_instruction:
            last_mnemonic:str = self.last_instruction.GetMnemonic(self.target)      
            if self.check_str_in_arr(last_mnemonic,CONST_DEVICE_info_list[DEVICE][CONST_INS_call]) :
                frame:lldb.SBFrame = self.thread.GetSelectedFrame()
                return_register = CONST_DEVICE_info_list[DEVICE][CONST_REGISTER_default_return_register]
                value:lldb.SBValue = frame.FindRegister(return_register)
                data_str = '{: <3} : {} '.format(return_register,value.GetValue())
                log_t('{}{: <15}{: <6}{: <30}// {} {}'.format(aligns,hex(cur_pc),cur_mnemonic,cur_operands,data_str,self.append_msg))
                self.append_msg = ''
                return  
            last_operands:str = self.last_instruction.GetOperands(self.target)      
            register_arr = match_registers(last_operands)
            data_str = ''
            for now_reg in register_arr:
                frame:lldb.SBFrame = self.thread.GetSelectedFrame()
                value:lldb.SBValue = frame.FindRegister(now_reg)
                data_str = '{}{: <3} : {} '.format(data_str,now_reg,value.GetValue())
            
            log_t('{}{: <15}{: <6}{: <30}// {} {}'.format(aligns,hex(cur_pc),cur_mnemonic,cur_operands,data_str,self.append_msg))
            self.append_msg = ''
            return
        log_t('{}{: <15}{: <6}{: <30} {}'.format(aligns,hex(cur_pc),cur_mnemonic,cur_operands,self.append_msg))
        self.append_msg = ''

    def parser_ins_symbol_name(self,last_symbole_name:str,cur_symbol_name : str):

        if not cur_symbol_name  or not last_symbole_name:
            log_d('err : cur_symbol_name or last_symbole_name is None')
            return True

        if cur_symbol_name in CONST_DEVICE_info_list[DEVICE][CONST_FUNC_NAME_ignore_list]:
            # 忽略的 符号名
            log_d('cur_symbol_name in ignore_function_names')
            return True

        if cur_symbol_name in CONST_DEVICE_info_list[DEVICE][CONST_FUNC_NAME_protect_list]:
            # # 设置 附加信息 
            
            # # log_t('{}<< current frame name >> :  {}'.format(aligens,cur_symbol_name))
            # frame :lldb.SBFrame = self.thread.GetSelectedFrame()
            
            # for pro_key,pro_value in CONST_DEVICE_info_list[DEVICE][CONST_FUNC_NAME_protect_list].items():
                
            #     if pro_key == cur_symbol_name:

            #         objs = pro_value[CONST_PRINT_obj]
            #         char_stars = pro_value[CONST_PRINT_char_star]
                    
            #         for char_star_item in char_stars: 
            #             func_name_register:lldb.SBValue = frame.FindRegister(char_star_item)
            #             addr = int(func_name_register.GetValue(),16)
                        # self.append_msg = ' : {}{: <3} ==> {} '.format(self.append_msg,char_star_item,get_c_char_star(addr))
                    
            #         for obj_item in objs:
            #             item_value =  handle_command(obj_item,self.debugger)
            #             self.append_msg = '{}{: <3} ==> {} '.format(self.append_msg,obj_item,item_value)

            #         break

            # log_d('cur_symbol_name in protect_function_names')
            # return True
            pass

        return False

    def add_next_breakpoint(self):
        if self.next_instruction:
            next_pc = self.next_instruction.GetAddress().GetLoadAddress(self.target)
            if next_pc in self.breakpoint_list:
                breakpoint = self.breakpoint_list[next_pc][CONST_BREAKPOINT_BREAKPOINE]
                log_d('->>> increase index on breakpoint : {}'.format(str(breakpoint)))
                self.breakpoint_list[next_pc][CONST_BREAKPOINT_INDEX] = self.breakpoint_list[next_pc][CONST_BREAKPOINT_INDEX] + 1
            else:
                breakpoint :lldb.SBBreakpoint = self.target.BreakpointCreateByAddress(next_pc)
                breakpoint.SetThreadID(self.thread.GetThreadID())
                item = {}
                item[CONST_BREAKPOINT_BREAKPOINE] = breakpoint
                item[CONST_BREAKPOINT_INDEX] = 1
                self.breakpoint_list[next_pc] = item
                log_d('->>> add address : {}  breakpoint : {}'.format(hex(next_pc),str(breakpoint)))
    
    def add_call_return_addr(self):
        if self.next_instruction:
            next_pc = self.next_instruction.GetAddress().GetLoadAddress(self.target)
            log_d('add {} index in call_return_instruction_list.'.format(hex(next_pc)))
            if next_pc in self.call_return_instruction_list:
                self.call_return_instruction_list[next_pc] = self.call_return_instruction_list[next_pc] + 1
            else:
                self.call_return_instruction_list[next_pc] = 1

    def sub_call_return_addr(self):
        pc = self.get_current_pc()
        if pc in self.call_return_instruction_list:
            log_d('@@@@ delete call return addr : {} out of call_return_instruction_list.'.format(hex(pc)))
            if self.call_return_instruction_list[pc] > 1:
                tmp = self.call_return_instruction_list[pc]
                self.call_return_instruction_list[pc] = tmp - 1
            else:
                self.call_return_instruction_list.pop(pc)


    def check_need_delete_breakpoint_in_current_call_return_list_and_decrease_index(self,cur_pc):
        if cur_pc in self.call_return_instruction_list:
            index = self.call_return_instruction_list[cur_pc]
            if index > 0 :
                self.call_return_instruction_list[cur_pc] = index - 1
                return True
            else:
                self.call_return_instruction_list.pop(cur_pc)
        return False 

    def delete_current_breakpoint(self):
        if self.current_instruction:
            curr_pc = self.current_instruction.GetAddress().GetLoadAddress(self.target)
            if not curr_pc in self.breakpoint_list:
                log_d('->>> {} not in breakpoint_list'.format(hex(curr_pc)))
                return
            item = self.breakpoint_list[curr_pc]
            if not item :
                log_d('->>> curr address : {} not in breakpoint_list'.format(hex(curr_pc)))
                return
            index = item[CONST_BREAKPOINT_INDEX]
            if index > 1 :
                log_d('->>> increase index on breakpoint : {}'.format(str(item[CONST_BREAKPOINT_BREAKPOINE])))
                self.breakpoint_list[curr_pc][CONST_BREAKPOINT_INDEX] = index - 1
            elif index == 1:
                delete_breakpoint :lldb.SBBreakpoint = item[CONST_BREAKPOINT_BREAKPOINE]
                if not self.check_need_delete_breakpoint_in_current_call_return_list_and_decrease_index(curr_pc):
                    self.target.BreakpointDelete(delete_breakpoint.GetID())
                    log_d('**** delet breakpoint at : {}'.format(hex(self.get_current_pc())))
                self.breakpoint_list.pop(curr_pc)
            else:
                log_c('->>> {} : breakpoint delete error'.format(hex(curr_pc)))
                log_d('->>> {} : breakpoint delete error'.format(hex(curr_pc)))

    def check_currentIns_is_endIns(self):
        if self.current_instruction:
            size = self.current_instruction.GetByteSize()
            pc = self.get_current_pc()
            nextpc = pc + size
            if nextpc in self.current_instruction_end_address_list:
                log_d('addr : {} in current_instruction_end_address_list'.format(hex(nextpc)))
                return True,CONST_CHECK_ins_end_address

            mnemonic:str = self.current_instruction.GetMnemonic(self.target)
            for ins_end_item in CONST_DEVICE_info_list[DEVICE][CONST_INS_end]:
                if mnemonic.startswith(ins_end_item):
                    log_d('addr : {} is CONST_INS_end'.format(hex(pc)))
                    return True,CONST_CHECK_ins_ret
            log_d('addr : {} is default ins.'.format(hex(pc)))
            return False,CONST_CHECK_ins_default
        else:
            log_d('warning : current ins is None.')
            log_c('warning : current ins is None.')
        return False,CONST_CHECK_ins_default

    def check_ins_call(self,mnemonic:str,cur_symbol:lldb.SBSymbol):
        for call_item  in CONST_DEVICE_info_list[DEVICE][CONST_INS_call]:
            if not mnemonic.startswith(call_item):
                continue
            pc = self.get_current_pc()
            self.get_next_instruction() # 获得下一条指令
            if not self.next_instruction is None:       
                self.add_next_breakpoint()
                self.add_call_return_addr()

            last_symbol_name = self.get_current_symbol_name()
            self.delete_current_breakpoint()# 删除当前断点
            self.thread.StepInstruction(False) # 单步进入
            sym_name = self.get_current_symbol_name()

            if self.parser_ins_symbol_name(last_symbol_name,sym_name) :  # 解析 symbol_name
                self.append_msg = sym_name + self.append_msg
                self.log_current_instruction(pc)
                self.increase_print_index()
                log_d('####### return : check_ins_call. ignore fun or protect fun. value : CONST_DEAL_WITH_wait_breakpoint')
                return True,CONST_DEAL_WITH_wait_breakpoint
                
            self.log_current_instruction(pc) # 打印信息
            if not(sym_name == last_symbol_name) :
                if sym_name and (not (sym_name == '')):
                    log_t('{}{} : '.format(self.print_text * self.print_index,sym_name))

            # 忽略的，保护的，需要  CONST_DEAL_WITH_wait_breakpoint
            self.increase_print_index()

            log_d('####### return : check_ins_call. value : CONST_DEAL_WITH_continue')
            return True,CONST_DEAL_WITH_continue
        
        return False,None

    def check_ins_jmp(self,mnemonic:str,cur_symbol:lldb.SBSymbol):
        for jmp_item  in CONST_DEVICE_info_list[DEVICE][CONST_INS_jmp]:
            if not mnemonic.startswith(jmp_item):
                continue
            
            pc = self.get_current_pc()
            self.get_next_instruction() # 获得下一条指令
            if not self.next_instruction is None:       
                self.add_next_breakpoint()

            last_symbol_name = self.get_current_symbol_name()
            self.delete_current_breakpoint()
            self.thread.StepInstruction(False)

            sym_name = self.get_current_symbol_name()

            if sym_name and self.parser_ins_symbol_name(last_symbol_name,sym_name):
                print('type : {} symName : {}'.format(type(sym_name),sym_name))
                if self.append_msg == None:
                    self.append_msg = ''
                self.append_msg = sym_name + self.append_msg
                self.log_current_instruction(pc)
                log_d('####### return : check_ins_jmp. ignore fun or protect fun. value : CONST_DEAL_WITH_wait_breakpoint')
                return True,CONST_DEAL_WITH_wait_breakpoint

            self.log_current_instruction(pc) # 打印信息

            log_d('####### return : check_ins_jmp. same module. value : CONST_DEAL_WITH_continue')
            return True,CONST_DEAL_WITH_continue
        
        return False,None

    def check_ins_syscall(self,mnemonic:str,cur_symbol:lldb.SBSymbol):
        for syscall_item in CONST_DEVICE_info_list[DEVICE][CONST_INS_syscall]:
            if not mnemonic.startswith(syscall_item):
                continue


            self.get_next_instruction() # 获得下一条指令
            if not self.next_instruction is None:       
                self.add_next_breakpoint()

            self.delete_current_breakpoint()
            
            self.log_current_instruction(self.get_current_pc()) # 打印信息
            log_d('####### return : check_ins_syscall. value : CONST_DEAL_WITH_wait_breakpoint')
            return True,CONST_DEAL_WITH_wait_breakpoint

        return False,None

    def check_ins_other(self,cur_symbol:lldb.SBSymbol):
        self.get_next_instruction() # 获得下一条指令
        if not self.next_instruction is None:       
            self.add_next_breakpoint()

        self.delete_current_breakpoint()
        self.log_current_instruction(self.get_current_pc())        # 打印信息

    def check_out_tracing(self):
        # 递归函数的处理 。。。。。。。
            
        pc = self.get_current_pc()
        if pc in self.end_trace_address:
            self.delete_current_breakpoint()
            self.log_current_instruction(pc)
            log_d('end trace addr list : {}'.format(self.end_trace_address))
            log_d('cur pc : {}'.format(pc))
            return True
        return False

    def check_end_fun(self):
        # 当前在结束地址       
        flag,ret = self.check_currentIns_is_endIns()
        if flag :
            if ret == CONST_CHECK_ins_ret:
                pc = self.get_current_pc()
                self.delete_current_breakpoint()
                self.log_current_instruction(pc)
                log_d('@@@@ check_end_fun : address : {} is ret ins.'.format(hex(pc)))
                return  True,CONST_DEAL_WITH_wait_breakpoint
            elif ret == CONST_CHECK_ins_end_address:
                last_pc = self.get_current_pc()
                self.thread.StepInstruction(False)
                self.delete_current_breakpoint()
                # 判断当前pc 是否在 instructionList中
                pc = self.get_current_pc()
                if pc in self.current_instruction_list:
                    self.log_current_instruction(last_pc)
                    log_d('@@@@ check_end_fun : address : {} is call end address,and in current_instruction_list.'.format(hex(last_pc)))
                    return True,CONST_DEAL_WITH_continue
                else:
                    # 可以 decrease print index
                    self.log_current_instruction(last_pc)
                    log_d('@@@@ check_end_fun : address : {} is call end address,and not in current_instruction_list.'.format(hex(last_pc)))
                    return True,CONST_DEAL_WITH_wait_breakpoint
            else:
                pass
        log_d('@@@@ check_end_fun : address : {} is not call end address or ret ins.'.format(hex(self.get_current_pc())))
        return False,None

    def check_symbol_valid(self):
        now_frame :lldb.SBFrame =  self.thread.GetSelectedFrame()
        if now_frame:
            sym:lldb.SBSymbol = now_frame.GetSymbol()
            if not sym.IsValid():
                log_d('####### return : check_symbol_valid not valid. value : CONST_DEAL_WITH_wait_breakpoint')
                return False,CONST_DEAL_WITH_wait_breakpoint
        log_d('@@@@ check_symbol_valid : valid.')
        return True,None

    def check_in_module(self):
        frame :lldb.SBFrame = self.thread.GetSelectedFrame()
        now_module_name = '{}'.format(frame.GetModule())
        log_d('@@@@ current module name : {}'.format(now_module_name))
        if now_module_name == self.current_module_name :
            return True,None
        log_d('####### return : check_in_module. is not current module. value : CONST_DEAL_WITH_wait_breakpoint')
        return False,CONST_DEAL_WITH_wait_breakpoint


    def deal_with_ins(self):

        if self.check_in_call_return_instruction_list():
            self.decrease_print_index()
            self.sub_call_return_addr()

        # 结束tracing
        if self.check_out_tracing():
            log_d('####### return : check_out_tracing value : CONST_DEAL_WITH_break')
            return CONST_DEAL_WITH_break

        # 函数结束的判断
        flag,ret = self.check_end_fun()
        if flag:
            log_d('####### return : check_end_fun')
            return ret
        
        # frame.GetFunction 和 frame.GetSymbol 是否有效
        flag,ret = self.check_symbol_valid()
        if not flag :
            return ret

        global t_only_self_module
        if t_only_self_module :
            flag,ret = self.check_in_module()
            if not flag:
                return ret
        
        instruction:lldb.SBInstruction = self.current_instruction
        mnemonic = None
        if instruction :
            mnemonic:str = instruction.GetMnemonic(self.target)
        else:
            log_d('warning : instruction is None')
            log_c('warning : instruction is None')

        cur_frame:lldb.SBFrame = self.thread.GetFrameAtIndex(0)
        cur_symbol:lldb.SBSymbol = cur_frame.GetSymbol()  
        flag,value = self.check_ins_call(mnemonic,cur_symbol) # call 指令 操作
        if flag:
            log_d('check_ins_call')
            return value
            
        flag,value = self.check_ins_jmp(mnemonic,cur_symbol) # jmp 指令 操作
        if flag:
            log_d('check_ins_jmp')
            return value

        flag,value = self.check_ins_syscall(mnemonic,cur_symbol)  # syscall 指令 操作
        if flag :
            log_d('check_ins_syscall')
            return value

        self.check_ins_other(cur_symbol)  # 其他指令的操作
        log_d('####### return : check_ins_other. value : CONST_DEAL_WITH_wait_breakpoint')
        return CONST_DEAL_WITH_wait_breakpoint
        
    

       


class WTFunction():
    def __init__(self, *args):
        pass
    def deal_with_fun(self):
        pass
        

class TraceOptionParser(optparse.OptionParser):
    def __init__(self, result):
        optparse.OptionParser.__init__(self)
        self.result = result
        self.exited = False

    def get_prog_name(self):
        return "trace"

    def exit(self, status=0, msg=None):
        if msg is not None:
            # print >>self.result, msg
            print(msg,file=self.result)
        self.exited = True

def parse_options(command, result):
    global options
    command_tokens = shlex.split(command)
    parser = TraceOptionParser(result)
    parser.add_option("-e","--end-address",action="store",metavar="END_ADDRESS",dest="end_address",help="End addresses of trace,using to stop trace thread.More address,use ';' to split.")
    parser.add_option("-o","--only-tracing-self-module",action="store_true",dest="only_tracing_self_module",default=True,help="Only tracing in current module.Default is True")
    parser.add_option("-m","--mode-type",action="store",metavar="<instruction/function>",dest="mode_type",default="instruction",help='Tracing mode,contains function and instruction.Default is instruction mode.')
    parser.add_option("-l","--log-type",action="store",metavar="<trace/debug>",dest="log_type",default='trace',help="Set log type for this tracing. With trace type redirect trace output file. With debug type redirect trace and debug output files.Default is trace type.")
    parser.add_option("-P","--parser-msgsend-parameters",action="store_true",dest="parser_msgsend_parameters",default=False,help="Parser objc_msgsend function's parameters.Default is False")
    parser.add_option("-p","--print-tracing-progress",action="store_true",dest="print_tracing_progress",default=True,help="Print tracing progress in console.Default is True")
    parser.add_option("-s","--suspend-threads-except-current-thread",action="store_true",dest="suspend_threads",default=True,help="Suspend threads except current thread,to clean env.Default is True")
    (options, _) = parser.parse_args(command_tokens)

    return parser.exited

def check_parser_command():
    global options
    global t_only_self_module,t_parser_msgsend_parameters
    global t_log_file,t_log_file_name,d_log_file,d_log_file_name

    if options.end_address is None :
        print('err : plz input an address where you want to end tracing.')
        return False

    log_type_arr = ['trace','debug']
    if not options.log_type in log_type_arr :
        print('err : plz input -l --log-type value, use "trace" or "debug".')
        return False

    mode_type_arr = ['function','instruction']
    if not options.mode_type in mode_type_arr:
        print('err : plz input -m --mode-type value, use "function" or "instruction".')
        return False

    if options.log_type == 'trace':
        print(type(t_log_file_name))
        print(t_log_file_name)
        t_log_file = open(t_log_file_name,'w')

    if options.log_type == 'debug':
        t_log_file = open(t_log_file_name,'w')
        d_log_file = open(d_log_file_name,'w')

    t_only_self_module = options.only_tracing_self_module
    t_parser_msgsend_parameters = options.parser_msgsend_parameters
    return True

def ini_log_file(mode_name:str):
    import time
    global log_default_path,t_log_file_name,d_log_file_name
    timeName = int(time.time())
    if mode_name == 'instruction':
        if log_default_path.endswith('/'):
            t_log_file_name = "{}{}{}".format(log_default_path,timeName,'instrace.log')
            d_log_file_name = "{}{}{}".format(log_default_path,timeName,'insdebug.log')
            log_c('trace log file : {}'.format(t_log_file_name))
            log_c('debug log file : {}'.format(d_log_file_name))
        else:
            t_log_file_name = "{}/{}{}".format(log_default_path,timeName,'instrace.log')
            d_log_file_name = "{}/{}{}".format(log_default_path,timeName,'insdebug.log')
            log_c('trace log file : {}'.format(t_log_file_name))
            log_c('debug log file : {}'.format(d_log_file_name))
        
    elif mode_name == 'function':

        if log_default_path.endswith('/'):
            t_log_file_name = "{}{}{}".format(log_default_path,timeName,'funtrace.log')
            d_log_file_name = "{}{}{}".format(log_default_path,timeName,'fundebug.log')
            log_c('trace log file : {}'.format(t_log_file_name))
            log_c('debug log file : {}'.format(d_log_file_name))
        else:
            t_log_file_name = "{}/{}{}".format(log_default_path,timeName,'funtrace.log')
            d_log_file_name = "{}/{}{}".format(log_default_path,timeName,'fundebug.log')
            log_c('trace log file : {}'.format(t_log_file_name))
            log_c('debug log file : {}'.format(d_log_file_name))
    else:
        print('err : trace mode err.')    


def test(debugger:lldb.SBDebugger):
    return False
    # import sys
    # import os
    # print(sys.argv[0])
    # print(__file__)
    # current_path = os.path.abspath(__file__)
    # print(current_path)
    # father_path = os.path.abspath(os.path.dirname(current_path) + os.path.sep + ".")
    # print(father_path)
    # global options
    # endAddress = options.end_address
    # a = re.split(';',endAddress)
    # for item in a:
    #     print(type(int(item,16)))
    #     print(int(item,16))
    #     print(item)
    # print(a)
    # target: lldb.SBTarget = debugger.GetSelectedTarget()
    # process: lldb.SBProcess = target.GetProcess()
    # thread: lldb.SBThread = process.GetSelectedThread()
    # frame: lldb.SBFrame = thread.GetSelectedFrame()
    # symbol :lldb.SBSymbol = frame.GetSymbol()
    
    # print(frame.GetModule())
    # print('frame : {}'.format(frame))
    # print('symbol.Instructions : ')
    # print(symbol.GetInstructions(target))
    # print('symbol : {}'.format(symbol))
    # print('symbol.Name : "{}"'.format(symbol.GetName()))
    # print('thread : {}'.format(thread))
    # print('thread name : {}'.format(thread.GetName()))
    # ins:lldb.SBInstruction = None
    # stream:lldb.SBStream = lldb.SBStream()
    # for ins in symbol.GetInstructions(target):
    #     # print(ins.GetData(target))
    #     ins.GetDescription(stream)
    #     addr :lldb.SBAddress = ins.GetAddress()
    #     module : lldb.SBModule = addr.GetModule()
    #     print('module : {}'.format(module))
    #     sym : lldb.SBSymbol = None
    #     for sym in module:
    #         print('sym name : {}'.format(sym.GetName()))

    #     break
    # print('symbol valid : {}'.format(symbol.IsValid()))
    # print('symbol DisplayName : {}'.format(symbol.GetDisplayName()))
    # print('symbol MangledName : {}'.format(symbol.GetMangledName()))


    return True

def trace(debugger: lldb.SBDebugger, command: str, result: lldb.SBCommandReturnObject, internal_dict):
    '''
    Traces execution of the symbol in the currently selected frame.
    trace -h/--help, for full help
    '''
    global options
    if parse_options(command, result):
        return
    
    ####################################################
    ########################测 试########################
    ####################################################
    if test(debugger):
            return
    ####################################################

    ini_log_file(options.mode_type)

    if not check_parser_command():
        return
    

    wait_event = threading.Event()
    wait_event.clear()
    notify_event = threading.Event()
    notify_event.clear()
    
    target: lldb.SBTarget = debugger.GetSelectedTarget()
    broadcaster: lldb.SBBroadcaster = target.GetBroadcaster()
    log_d("Target: {}".format(str(target)))
    process: lldb.SBProcess = target.GetProcess()
    log_d("Process: {}".format(str(process)))
    log_d("Broadcaster: {}".format(str(broadcaster)))
    if options.suspend_threads :
        suspend_threads_escape_select_thread(process,True)

    listener = lldb.SBListener("trace breakpoint listener")
    rc = broadcaster.AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    my_thread = WTListeningThread(wait_event, notify_event,listener, process)
    my_thread.start()

    thread: lldb.SBThread = process.GetSelectedThread()
    log_d("Thread: {}".format(str(thread)))
    
    frame: lldb.SBFrame = thread.GetSelectedFrame()
    
    module: lldb.SBModule = frame.GetModule()
    if frame.GetFrameID() == 0xFFFFFFFF:
        log_d("Invalid frame, has your process started?")
        return

    insObj = WTInstruction(target,thread,frame,debugger,TRACE_TYPE_Instrument,endAddress=options.end_address)
    ## 初始化 环境 
    insObj.init_env()
    global num_for_print_progress
    insCount = 0
    test_index = 0
    while True:
        log_d('index : {}'.format(test_index))
        # 打印进度
        if options.print_tracing_progress :
            if insCount % num_for_print_progress == 0 and insCount > 0:
                insObj.print_tracing_progress(insCount)
            insCount = insCount + 1

        # 更新当前 instruction / instructionList
        log_d("////////////////////////////////loop begin////////////////////////////////")
        insObj.updata_instruction_instructionList() # 更新所有的 指令 ，更新当前 指令 

        # ins : 设置断点，进行有必要的 单步 调试
        # fun : 设置断点
        ret = insObj.deal_with() # 处理 指令

        # 保存指令
        insObj.updata_last_instruction()

        log_d("=================== Stopped at: ====================")
        log_d("Frame: {}, symbol: {}, pc: {pc:#x}".format(str(frame), str(frame.GetSymbol()), pc=frame.GetPC()))
        # 判断结果
        if ret == CONST_DEAL_WITH_error:
            log_c('err : deal with error.')
            log_d('err : deal with error.')
            insObj.clean_env()
            break

        if ret == CONST_DEAL_WITH_continue:
            continue

        if ret == CONST_DEAL_WITH_break :
            break
        continue_and_wait_for_breakpoint(process,thread,my_thread,wait_event,notify_event)



    if options.suspend_threads :
        suspend_threads_escape_select_thread(process,False)
    my_thread.exit()
    wait_event.set()
    my_thread.join()
    broadcaster.RemoveListener(listener)
    log_d('Listener thread exited completing')
    log_flush()


############################################################################################################################################################
#######################################################################traceblock###########################################################################
############################################################################################################################################################

class WTBlock():
    def __init__(self, target, thread, frame,debugger,endAddress=None):
        self.target:lldb.SBTarget = target
        self.thread:lldb.SBThread = thread
        self.frame:lldb.SBFrame = frame
        self.debugger:lldb.SBDebugger = debugger

        self.current_instruction_list = {}
        self.end_trace_address = []
        self.block_list = {} # 存贮所有的 block

        # 
        # {
        #     addr : {  # 这里是断点地址
        #         'index' : 0 # 这里是断点信息
        #         'breakpoint' : None # 这里是 lldb.SBBreakpoint
        #     }
        # }
        self.breakpoint_list = {} # 断点列表
        
        self.loop_flag = False
        self.append_msg = ''  

        # log
        self.last_block_msg = '' 
        self.last_isnts_msg = ''
        self.last_reg_msg = ''

        ## 
        self.test_test_index = 0

        for item in re.split(';',endAddress):
            self.end_trace_address.append(int(item,16)) # 结束 Trace 地址

    def initEnv(self):
        cur_pc = self.get_current_pc()
        self.block_add_block_to_block_list(cur_pc)
        for item in self.end_trace_address :
            self.block_add_breakpoint(item)  # 给结束地址下断点

    def block_set_loop_flag(self,flag_value):
        self.loop_flag = flag_value

    def block_add_append_msg(self,msg):
        self.append_msg = '{}[{}]'.format(self.append_msg,msg)            
        

    def block_clear_append_msg(self):
        self.append_msg = ''

    def block_delete_breakpoint(self,inst_addr):
        if inst_addr in self.breakpoint_list :
            index_value = self.breakpoint_list[inst_addr]['index']
            delete_breakpoint:lldb.SBBreakpoint = self.breakpoint_list[inst_addr]['breakpoint']
            if index_value > 1 :
                self.breakpoint_list[inst_addr]['index'] = index_value -1
            elif index_value == 1:
                log_d('delete breakpoint at : {}'.format(hex(inst_addr)))
                self.target.BreakpointDelete(delete_breakpoint.GetID())
                self.breakpoint_list[inst_addr]['index'] = 0
                self.breakpoint_list.pop(inst_addr)
            else:
                log_d('err : delete breakpoint with wrong index . < index : {} >'.format(index_value))

    def block_add_breakpoint(self,inst_addr):
        if inst_addr in self.breakpoint_list:
            # index_value = self.breakpoint_list[inst_addr]['index']
            # if index_value > 0 :
            #     print('increase breakpoint index at : {}'.format(hex(inst_addr)))
            #     self.breakpoint_list[inst_addr]['index'] = index_value + 1
            # else:
            #     print('err : add breakpoint with wrong index. < index : {} >'.format(index_value))
            log_d('breakpoint at {} had been exist.'.format(hex(inst_addr)))
        else:
            item = {}
            breakpoint :lldb.SBBreakpoint = self.target.BreakpointCreateByAddress(inst_addr)
            breakpoint.SetThreadID(self.thread.GetThreadID())
            item['index'] = 1
            item['breakpoint'] = breakpoint
            self.breakpoint_list[inst_addr] = item
            log_d('add breakpoint at : {}'.format(hex(inst_addr)))
    def block_add_block_to_block_list(self,block_id):
        if  not (block_id in self.block_list) :
            log_d('>>>>>> add block : {}  >>> value : None.'.format(hex(block_id)))
            self.block_list[block_id] = None

    # 获得当前 pc
    def get_current_pc(self):
        now_frame :lldb.SBFrame = self.thread.GetSelectedFrame()
        if now_frame:
            return now_frame.GetPC()
        return None
    # 
    def block_update_current_ins(self):
        frame : lldb.SBFrame = self.thread.GetSelectedFrame()
        # symbol:lldb.SBSymbol = frame.GetSymbol()
        # # 给 current_instruction_list 赋值
        # # 获得 当前 symbol 下的 instructionlist
        # insts : lldb.SBInstructionList = symbol.GetInstructions(self.target)

        cur_pc = self.get_current_pc()
        
        if not (cur_pc in self.current_instruction_list)  :
            # 清空一哈
            self.current_instruction_list = {}
            # 更新 self.current_instruction_list

            target: lldb.SBTarget = self.debugger.GetSelectedTarget()
            process: lldb.SBProcess = target.GetProcess()
            thread: lldb.SBThread = process.GetSelectedThread()
            frame: lldb.SBFrame = thread.GetSelectedFrame()
            symbol :lldb.SBSymbol = frame.GetSymbol()
            insts :lldb.SBInstructionList = symbol.GetInstructions(target)
            # func : lldb.SBFunction = frame.GetFunction()
            # insts : lldb.SBInstructionList = func.GetInstructions(self.target)     
            for inst in insts :
                instAddr :lldb.SBAddress = inst.GetAddress()
                addr = instAddr.GetLoadAddress(self.target)
                if not (addr in self.current_instruction_list) :
                    self.current_instruction_list[addr] = inst
        
        return cur_pc


    # 判断当前 ins 是否在 trace 的结束列表中
    def block_check_current_ins_in_end_tracing_address_list(self,curIns):
        if curIns in self.end_trace_address :
            return True
        return False
    
    def block_update_block_data(self,block_id,block_dic):
        if block_id in self.block_list:
            block_data = self.block_list[block_id]
            if not block_data :
                self.block_list[block_id] = block_dic
            else :
                log_d('>> block : {} had been update'.format(hex(block_id)))
        else:
            log_d('err : block id dont input to block list.')

    def block_update_current_block(self):        
        # 需要在 bl 以及 jmp 目标地址，和条件jmp的下一条指令处下断点，以及 增加对应的 block 到 blockList 中
        cur_pc = self.get_current_pc()
        # print(self.current_instruction_list)
        inst :lldb.SBInstruction = self.current_instruction_list[cur_pc]

        if (cur_pc in self.block_list) and ( self.block_list[cur_pc]) :  
            self.block_set_loop_flag(True)
            self.block_delete_breakpoint(cur_pc)
            return self.block_list[cur_pc]

        use_inst = inst
        block_ins_list = {}
        need_break = False
        log_d('update block : {} insts :'.format(hex(cur_pc)))
        while True :
            mnemonic: str = use_inst.GetMnemonic(self.target)
            inst_addr = use_inst.GetAddress().GetLoadAddress(self.target)
            next_addr = inst_addr + use_inst.GetByteSize()
            operands = use_inst.GetOperands(self.target)

            flag = False
            for item in CONST_DEVICE_info_list[DEVICE][CONST_INS_call] :
                if mnemonic.startswith(item) :
                    flag = True
                    break
            
            if flag :
                self.block_add_breakpoint(inst_addr)
                block_ins_list[inst_addr] = use_inst # 代码加入到 block_ins_list 
                if next_addr in self.current_instruction_list :
                    use_inst = self.current_instruction_list[next_addr] # 更新 use_inst
                else :
                    break
                continue

            flag = False
            for item in CONST_DEVICE_info_list[DEVICE][CONST_INS_jmp]:
                if item == mnemonic :
                    flag = True
                    need_break = True
                    break
            
            if flag :  
                self.block_add_block_to_block_list(int(operands,16))    # 添加block 到 block_list 中 
                self.block_add_breakpoint(int(operands,16))# 在 int(operands,16) 处下断点

            if not need_break :        
                flag = False
                for item in CONST_DEVICE_info_list[DEVICE][CONST_INS_condition_jmp] :
                    if  mnemonic.startswith(item):
                        flag = True
                        need_break = True
                        break
                if flag :
                    if int(operands,16) > inst_addr :    
                        self.block_add_block_to_block_list(int(operands,16)) 
                        self.block_add_breakpoint(int(operands,16)) # 在 operands 下断点

                    self.block_add_block_to_block_list(next_addr)
                    self.block_add_breakpoint(next_addr) # 在 next_addr 下断点

            
            block_ins_list[inst_addr] = use_inst # 代码加入到 block_ins_list 
            if need_break :
                break

            if next_addr in self.current_instruction_list :
                use_inst = self.current_instruction_list[next_addr] # 更新 use_inst
            else :
                break
        # self.block_list[cur_pc] = block_ins_list
        # print('block : {} \n{}:'.format(hex(cur_pc),self.block_list[cur_pc]))
        return block_ins_list


    def block_at_bl(self,curIns):
        ins:lldb.SBInstruction = self.current_instruction_list[curIns]
        mnem:str = ins.GetMnemonic(self.target)
        for item in CONST_DEVICE_info_list[DEVICE][CONST_INS_call]:
            if mnem.startswith(item) :
                return True
        return False

    def block_at_header(self,curIns):
        if curIns in self.block_list :
            return True
        return False

    ##############################
    def block_step_into(self):
        self.thread.StepInstruction(False)

    def block_get_data_about_function_and_symbol(self,curIns):
        target: lldb.SBTarget = self.debugger.GetSelectedTarget()
        process: lldb.SBProcess = target.GetProcess()
        thread: lldb.SBThread = process.GetSelectedThread()
        frame: lldb.SBFrame = thread.GetSelectedFrame()
        symbol :lldb.SBSymbol = frame.GetSymbol()
        func : lldb.SBFunction = frame.GetFunction()
        # insts:lldb.SBInstructionList = func.GetInstructions(target)
        # inst:lldb.SBInstruction = None
        # block_delete_breakpoint
        self.block_delete_breakpoint(curIns)

        if func.IsValid():
            return True,symbol.GetName()

        return False,symbol.GetName()


    def block_get_reg_msg(self):
        reg_msg = ''
        target: lldb.SBTarget = self.debugger.GetSelectedTarget()
        process: lldb.SBProcess = target.GetProcess()
        thread: lldb.SBThread = process.GetSelectedThread()
        frame: lldb.SBFrame = thread.GetSelectedFrame()

        registerSet :lldb.SBValueList = frame.GetRegisters()
        regs:lldb.SBValue = registerSet.GetValueAtIndex(0)
        for reg in regs :     
            if reg_msg == "" :
                reg_msg = '{}:{}'.format(reg.name,reg.value)
            else:
                reg_msg = '{}|{}:{}'.format(reg_msg,reg.name,reg.value)

            if reg.name == 'pc' :
                break

        return reg_msg

    def block_get_current_insts_msg(self,block_id):
        global ASLR
        target: lldb.SBTarget = self.debugger.GetSelectedTarget()
        isnts_msg = ''
        if  not self.loop_flag :
            # isnts_msg = '0x12345 mov x0,1'
            if block_id in self.block_list:
                cur_block = self.block_list[block_id]
                inst:lldb.SBInstruction = None
                if cur_block :
                    for key,inst in cur_block.items():
                        inst_msg = '{: <5} {}'.format(inst.GetMnemonic(target),inst.GetOperands(target))
                        if isnts_msg == "" :
                            isnts_msg = '{: <10}  {}'.format(hex(key - ASLR),inst_msg)
                        else:
                            isnts_msg = '{}\n\t{: <10}  {}'.format(isnts_msg,hex(key - ASLR),inst_msg)

        return isnts_msg

    ################################
    # log 输出 格式
    # block_id :
	# {
	#     addr : inst
	# 	...
	# }<函数名|函数名|..>[x0:value|x1:value|....]
    # block_id :
	#     {}<函数名|函数名|..>[x0:value|x1:value|....]
    #
    # out_msg = "%s\n{\n\t%s\n}<%s>[%s]" % ('block id : 0x1233333','0x12345 mov x0,1','malloc|strlen','x0:0x1234|x1:0x222222')
    def block_log_msg(self,block_id):
        global ASLR
        self.test_test_index = self.test_test_index + 1
        
        block_msg = "{} =>> block id : {}".format(self.test_test_index,hex(block_id-ASLR))
        isnts_msg = self.block_get_current_insts_msg(block_id)   
        reg_msg = self.block_get_reg_msg()

        if not (self.last_block_msg == '' and self.last_isnts_msg == '' and self.last_reg_msg == '') :
            out_msg = "%s\n{\n\t%s\n}<%s>[%s]" % (self.last_block_msg,self.last_isnts_msg,self.append_msg,self.last_reg_msg)
            log_t(out_msg)

        self.last_block_msg = block_msg
        self.last_isnts_msg = isnts_msg
        self.last_reg_msg = reg_msg

        # 清空 append_msg
        self.append_msg = ''

    def block_log_end_msg(self):
        if not (self.last_block_msg == '' and self.last_isnts_msg == '' and self.last_reg_msg == '') :
            out_msg = "%s\n{\n\t%s\n}<%s>[%s]" % (self.last_block_msg,self.last_isnts_msg,self.append_msg,self.last_reg_msg)
            log_t(out_msg)

        self.last_block_msg = ''
        self.last_isnts_msg = ''
        self.last_reg_msg = ''
        
        self.append_msg = ''
        

    def block_get_symbol_name(self):
        target: lldb.SBTarget = self.debugger.GetSelectedTarget()
        process: lldb.SBProcess = target.GetProcess()
        thread: lldb.SBThread = process.GetSelectedThread()
        frame: lldb.SBFrame = thread.GetSelectedFrame()
        symbol :lldb.SBSymbol = frame.GetSymbol()
        return symbol.GetName()


    def block_print_tracing_progress(self,count):
        # 当前trace的总行数 内存地址:文件地址: <函数名>
        global ASLR
        file_addr = 0
        cur_pc = self.get_current_pc()
        if  cur_pc == 0 :
            log_c('{: <10}  err .'.format(count))
        else:
            file_addr = cur_pc - ASLR
            if cur_pc in self.current_instruction_list:   
                out_str = '{: <10}  {} : {} <{}>'.format(count,hex(cur_pc),hex(file_addr),self.block_get_symbol_name())
                log_c(out_str)
            else:
                out_str = '{: <10} {}'.format(count,hex(cur_pc))
                log_c(out_str)

    def block_get_block_id(self,block):
        retaddr = 0
        for addr in block.keys():
            if retaddr == 0 :
                retaddr = addr
            else:
                if retaddr > addr :
                    retaddr = addr
        
        return retaddr


    def block_print(self):
        print('---> block_list <---')
        for item in self.block_list:
            print(hex(item))

        print('---> breakpoint_list <---')
        for item in self.breakpoint_list :
            print(hex(item))

        print('--------------------------')




def block_parser_options(command, result):
    global options
    command_tokens = shlex.split(command)
    parser = TraceOptionParser(result)
    parser.add_option("-e","--end-address",action="store",metavar="END_ADDRESS",dest="end_address",help="End addresses of trace,using to stop trace thread.More address,use ';' to split.")
    parser.add_option("-l","--log-type",action="store",metavar="<trace/debug>",dest="log_type",default='trace',help="Set log type for this tracing. With trace type redirect trace output file. With debug type redirect trace and debug output files.Default is trace type.")
    parser.add_option("-p","--print-tracing-progress",action="store_true",dest="print_tracing_progress",default=True,help="Print tracing progress in console.Default is True")
    parser.add_option("-s","--suspend-threads-except-current-thread",action="store_true",dest="suspend_threads",default=True,help="Suspend threads except current thread,to clean env.Default is True")
    
    (options, _) = parser.parse_args(command_tokens)

    return parser.exited


def block_ini_log_file():
    import time
    global log_default_path,t_log_file_name,d_log_file_name
    timeName = int(time.time())

    if log_default_path.endswith('/'):
        t_log_file_name = "{}{}{}".format(log_default_path,timeName,'blocktrace.log')
        d_log_file_name = "{}{}{}".format(log_default_path,timeName,'blockdebug.log')
        log_c('trace log file : {}'.format(t_log_file_name))
        log_c('debug log file : {}'.format(d_log_file_name))
    else:
        t_log_file_name = "{}/{}{}".format(log_default_path,timeName,'blocktrace.log')
        d_log_file_name = "{}/{}{}".format(log_default_path,timeName,'blockdebug.log')
        log_c('trace log file : {}'.format(t_log_file_name))
        log_c('debug log file : {}'.format(d_log_file_name))
 


def block_check_parser_command():
    global options
    global t_log_file,t_log_file_name,d_log_file,d_log_file_name

    if options.end_address is None :
        print('err : plz input an address where you want to end tracing.')
        return False

    log_type_arr = ['trace','debug']
    if not options.log_type in log_type_arr :
        print('err : plz input -l --log-type value, use "trace" or "debug".')
        return False

    if options.log_type == 'trace':
        print(type(t_log_file_name))
        print(t_log_file_name)
        t_log_file = open(t_log_file_name,'w')

    if options.log_type == 'debug':
        t_log_file = open(t_log_file_name,'w')
        d_log_file = open(d_log_file_name,'w')

    return True


def test_block(debugger:lldb.SBDebugger):
    
    return False

    target: lldb.SBTarget = debugger.GetSelectedTarget()
    process: lldb.SBProcess = target.GetProcess()
    thread: lldb.SBThread = process.GetSelectedThread()
    frame: lldb.SBFrame = thread.GetSelectedFrame()
    symbol :lldb.SBSymbol = frame.GetSymbol()
    func : lldb.SBFunction = frame.GetFunction()

    # out_msg = "%s\n{\n\t%s\n}<%s>[%s]" % ('block id : 0x1233333','0x12345 mov x0,1','malloc|strlen','x0:0x1234|x1:0x222222')

    # print(out_msg)
    # registerSet :lldb.SBValueList = frame.GetRegisters()
    # regs:lldb.SBValue = registerSet.GetValueAtIndex(0)
    # print('num is : {}'.format(regs.GetNumChildren()))
    # for reg in regs :     
    #     print('{} : {}'.format(reg.name,reg.value))
    #     if reg.name == 'pc' :
    #         break
    # print(symbol.GetInstructions(target))

    # # symbol 可执行文件里有，链接库里有
    # # func 可执行文件里有，但是 链接库里 没有
    # if func.IsValid() :
    #     # insts:lldb.SBInstructionList = func.GetInstructions(target)
    #     # inst:lldb.SBInstruction = None
    #     # print('isnts : ')
    #     # print(insts)
    #     print('func : {}'.format(func))
    #     print('func name : {}'.format(func.GetName()))  
    # # print('symbol : {}'.format(symbol))
    # # print('symbol DisplayName : {}'.format(symbol.GetDisplayName()))
    # # print('symbol MangledName : {}'.format(symbol.GetMangledName()))
    # print('symbol name : {}'.format(symbol.GetName()))


    # for inst in insts :  
    #     print('|{}|-----|{}|'.format(inst.GetMnemonic(target),inst.GetOperands(target)))
    #     pass
    cur_block_ins_list = None # 直接更新
    blockObj = WTBlock(target,thread,frame,debugger)
    blockObj.initEnv()
    cur_ins = blockObj.block_update_current_ins()
    print('cur ins : {}'.format(hex(cur_ins)))
    if not cur_block_ins_list :
        cur_block_ins_list = blockObj.block_update_current_block()

    # if not (cur_ins in cur_block_ins_list) :
    #     cur_block_ins_list = blockObj.block_update_current_block()

    print('--> block_ins_list <---')
    item : lldb.SBInstruction = None  
    for _,item in cur_block_ins_list.items() :
        print('{}      {}  {}'.format(hex(item.GetAddress().GetLoadAddress(target)),item.GetMnemonic(target),item.GetOperands(target)))


    blockObj.block_print()

def trace_block(debugger: lldb.SBDebugger, command: str, result: lldb.SBCommandReturnObject, internal_dict):
    global options
    if block_parser_options(command, result):
        return
    
    ####################################################
    ########################测 试########################
    ####################################################
    if test_block(debugger):
            return
    ####################################################

    block_ini_log_file()


    if not block_check_parser_command():
        return
    
    wait_event = threading.Event()
    wait_event.clear()
    notify_event = threading.Event()
    notify_event.clear()
    
    target: lldb.SBTarget = debugger.GetSelectedTarget()
    broadcaster: lldb.SBBroadcaster = target.GetBroadcaster()
    print("Target: {}".format(str(target)))
    process: lldb.SBProcess = target.GetProcess()
    print("Process: {}".format(str(process)))
    print("Broadcaster: {}".format(str(broadcaster)))
    if options.suspend_threads :
        suspend_threads_escape_select_thread(process,True)

    listener = lldb.SBListener("trace breakpoint listener")
    rc = broadcaster.AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    my_thread = WTListeningThread(wait_event, notify_event,listener, process)
    my_thread.start()

    thread: lldb.SBThread = process.GetSelectedThread()
    print("Thread: {}".format(str(thread)))
    
    frame: lldb.SBFrame = thread.GetSelectedFrame()
    
    module: lldb.SBModule = frame.GetModule()
    if frame.GetFrameID() == 0xFFFFFFFF:
        print("Invalid frame, has your process started?")
        return
    
    blockObj = WTBlock(target,thread,frame,debugger,endAddress=options.end_address)
    blockObj.initEnv()
    
    cur_block = None # 直接更新
    blockCount = 0
    while True :
        # 打印进度
        if options.print_tracing_progress :
            if blockCount % num_for_print_progress == 0 and blockCount > 0:
                blockObj.block_print_tracing_progress(blockCount)
            blockCount = blockCount + 1
        log_d("=================== Stopped at: ====================")
        log_d("Frame: {}, symbol: {}, pc: {pc:#x}".format(str(frame), str(frame.GetSymbol()), pc=frame.GetPC()))
        cur_ins = blockObj.block_update_current_ins()

        if blockObj.block_check_current_ins_in_end_tracing_address_list(cur_ins):
            print('end tracing....... at : {}'.format(hex(cur_ins)))
            blockObj.block_log_end_msg()
            log_d('end tracing....... at : {}'.format(hex(cur_ins)))
            # blockObj.block_print()
            break
        
        if (not cur_block ) or not (cur_ins in cur_block): 
            cur_block = blockObj.block_update_current_block() # 需要在 bl 以及 jmp 目标地址，和条件jmp的下一条指令处下断点，以及 增加对应的 block 到 blockList 中
            blockObj.block_update_block_data(cur_ins,cur_block)


        at_bl_flag = blockObj.block_at_bl(cur_ins)
        at_header_flag = blockObj.block_at_header(cur_ins)

        if at_bl_flag and at_header_flag :
            # 当前指令 是 bl 而且是 block 头
            # 输出 信息
            blockObj.block_log_msg(cur_ins)
            blockObj.block_set_loop_flag(False)
            # 单步进入，然后获得 symble name 和 function name
            blockObj.block_step_into()
            _,symbol_name = blockObj.block_get_data_about_function_and_symbol(cur_ins) 
            blockObj.block_add_append_msg('') # blockObj.block_add_append_msg(msg) # 把信息 加入 到 

        elif at_bl_flag and (not at_header_flag):
            # 当前指令 仅仅是 bl
            # 单步进入，然后获得 symble name 和 function name
            blockObj.block_step_into()
            _,symbol_name = blockObj.block_get_data_about_function_and_symbol(cur_ins)
            blockObj.block_add_append_msg(symbol_name) # blockObj.block_add_append_msg(msg) # 把信息 加入 到 
            
        elif at_header_flag and (not at_bl_flag):
            # 当前指令 仅仅是 block 头,在进来的时候，已经搞定
            # 输出 信息
            blockObj.block_log_msg(cur_ins)
            blockObj.block_set_loop_flag(False)
        else:
            log_d('err : ins out of control.')
            print('err : ins out of control.')
            break
        
        # 10分钟 刷新一次缓存，把缓存 写入到 block list 文件中  xxxxx_block_list.txt
        # 清空 blockObj.block_list

        continue_and_wait_for_breakpoint(process,thread,my_thread,wait_event,notify_event)      

    if options.suspend_threads :
        suspend_threads_escape_select_thread(process,False)
    my_thread.exit()
    wait_event.set()
    my_thread.join()
    broadcaster.RemoveListener(listener)
    print('Listener thread exited completing')
    log_flush()



def init_ASLR(debugger:lldb.SBDebugger):   
    global ASLR
    interpreter:lldb.SBCommandInterpreter = debugger.GetCommandInterpreter()
    returnObject = lldb.SBCommandReturnObject()
    interpreter.HandleCommand('image list -o', returnObject)
    output = returnObject.GetOutput()
    match = re.match(r'.+(0x[0-9a-fA-F]+)', output)
    if match:
        ASLRHexStr:str = match.group(1)
        ASLR = int(ASLRHexStr,16)
        print('ALSR : {}'.format(ASLRHexStr))
        return ASLRHexStr
    else:
        ASLR = ''
        print('err : ALSR is None')
        return None

def setDefaultPath(debugger: lldb.SBDebugger, command: str, result: lldb.SBCommandReturnObject, internal_dict):
    global log_default_path
    log_default_path = command
    # 还需要判断这个 路径存在否
    print(command)
    
def defaultPath(debugger: lldb.SBDebugger, command: str, result: lldb.SBCommandReturnObject, internal_dict):
    global log_default_path
    print(log_default_path)

def __lldb_init_module(debugger:lldb.SBDebugger, internal_dict):
    global log_default_path
    init_ASLR(debugger)
    log_default_path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + os.path.sep + ".")
    debugger.HandleCommand('command script add -f lldbTrace.trace trace')
    debugger.HandleCommand('command script add -f lldbTrace.setDefaultPath setlogpath')
    debugger.HandleCommand('command script add -f lldbTrace.defaultPath logpath')
    print('WT::The "trace" python command has been installed and is ready for use.')



    print('WT::Default path =>>>> {}'.format(log_default_path))
    print('    use : logpath command to look up logfile default path.')
    print('    use : setlogpath <PATH> command to reset logfile default path.')

    debugger.HandleCommand('command script add -f lldbTrace.trace_block trace_b')
    print('WT::The "trace_b" python command has been installed and is ready for use.')


