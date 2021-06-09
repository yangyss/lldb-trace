#!/usr/bin/env python3
import lldb
import optparse
import shlex
import threading
import re
import ctypes

options = None
debug_log_file = None  # debug log
trace_log_file = None # trace log

def log(msg):
    global options
    global debug_log_file
    debug_log_file.write(msg)
    debug_log_file.write('\n')

def log_d(msg):
    global options
    global debug_log_file
    if (debug_log_file is not None):
        debug_log_file.write(msg)
        debug_log_file.write('\n')

def log_t(msg):
    global options
    global trace_log_file
    if trace_log_file is not None:
        trace_log_file.write(msg)
        trace_log_file.write('\n')

def log_flush():
    global trace_log_file,debug_log_file
    if debug_log_file is not None:
        debug_log_file.flush()
    if trace_log_file is not None:
        trace_log_file.flush()
    
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
CONST_DEAL_WITH_wait_breakpoint = 2


#########################################################
CONST_DEVICE_info_list = {
    DEVICE_BSD64 : {
        CONST_FUNC_NAME_ignore_list : ['printf','usleep','objc_unsafeClaimAutoreleasedReturnValue','objc_storeStrong'],
        CONST_FUNC_NAME_protect_list : {
            'objc_msgSend' : {
                # 需要解析参数
                CONST_PRINT_obj:['po [$x0 class]'],
                CONST_PRINT_char_star:['x1']
            }
        },
        CONST_REGISTER_re : [r'\b[xwd][0-9]{1,2}',r'\b[xwd][0-9]{1,2},',r'sp'], # r'\b[xw][0-9]{1,2}[,]{0,1}'
        CONST_REGISTER_default_return_register:'x0',

        CONST_INS_call : ['bl'],#,'bl',
        CONST_INS_jmp  : ['cb','b','tb'],#'b',
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

    return result
    
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

#########################################################

class WTInstrument():
    # false : trace Instrument, true : trace function
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
        self.end_trace_address.append(endAddress) # 结束 Trace 地址

        # 包含 breakpoint : 以及 引用计数 used_num :
        self.breakpoint_list = {}   # 所有断点 的 list
        self.current_instruction_list = {} # 当前 symbol 下的 所有的 instruction 列表
        self.current_instruction_end_address_list = {} # 当前 symbol 下的 所有的  end_address 列表
        self.current_call_return_instruction_list = {} # 所有函数 continue后，返回的地址 列表

        self.append_msg = '' # 附加消息
        # 
        self.last_symbol_name = 'None'    # 上一个symbol

        self.print_index = 0
        self.print_text = '    '

    def init_last_symbol_name(self):
        now_frame :lldb.SBFrame = self.thread.GetFrameAtIndex(0)
        now_symbol:lldb.SBSymbol = now_frame.GetSymbol()
        self.last_symbol_name = now_symbol.GetName()
        if len(self.last_symbol_name) < 1 :
            log_d('err : init_last_name : {}'.format(self.last_symbol_name))

    def init_end_address(self):

        frame :lldb.SBFrame = self.thread.GetFrameAtIndex(0)
        symbol:lldb.SBSymbol = frame.GetSymbol()
        instructionlist : lldb.SBInstructionList = symbol.GetInstructions(self.target)

        if self.current_instruction_list:
            self.current_instruction_list = {}
            self.current_instruction_end_address_list = {}

        instruction :lldb.SBInstruction = None
        cur_end_address = symbol.GetEndAddress().GetLoadAddress(self.target)
            
        for instruction in instructionlist:
            address :lldb.SBAddress = instruction.GetAddress()
            cur_mnemonic:str = instruction.GetMnemonic(self.target)
            load_address = address.GetLoadAddress(self.target)
            if cur_end_address == load_address:
                if not load_address in self.end_trace_address:
                    self.end_trace_address.append(cur_end_address)
                    continue
            if self.check_str_in_arr(cur_mnemonic,CONST_DEVICE_info_list[DEVICE][CONST_INS_end]):
                if not load_address in self.end_trace_address:
                    self.end_trace_address.append(load_address)
      
    def check_wait_breakpoint_in_current_call(self,cur_symbol_name):
        if not cur_symbol_name:
            log_d('err : None cur_symbol_name')
            return True

        if cur_symbol_name in CONST_DEVICE_info_list[DEVICE][CONST_FUNC_NAME_ignore_list]:
            # 忽略的 符号名
            log_d('cur_symbol_name in ignore_function_names')
            return True

        if cur_symbol_name in CONST_DEVICE_info_list[DEVICE][CONST_FUNC_NAME_protect_list]:
            # 设置 附加信息 
            
            # log_t('{}<< current frame name >> :  {}'.format(aligens,cur_symbol_name))
            frame :lldb.SBFrame = self.thread.GetFrameAtIndex(0)
            
            for pro_key,pro_value in CONST_DEVICE_info_list[DEVICE][CONST_FUNC_NAME_protect_list].items():
                
                if pro_key == cur_symbol_name:

                    objs = pro_value[CONST_PRINT_obj]
                    char_stars = pro_value[CONST_PRINT_char_star]
                    
                    for char_star_item in char_stars: 
                        func_name_register:lldb.SBValue = frame.FindRegister(char_star_item)
                        addr = int(func_name_register.GetValue(),16)
                        self.append_msg = '{}{: <3} ==> {} '.format(self.append_msg,char_star_item,get_c_char_star(addr))
                        log_d('===>>>char_star_item : {}  append_msg : {}'.format(char_star_item,self.append_msg))
                    
                    for obj_item in objs:
                        item_value =  handle_command(obj_item,self.debugger)
                        self.append_msg = '{}{: <3} ==> {} '.format(self.append_msg,obj_item,item_value)
                        log_d('===>>>obj_item : {}  append_msg : {}'.format(obj_item,self.append_msg))
                    break

            log_d('cur_symbol_name in protect_function_names')
            return True

        if cur_symbol_name == self.last_symbol_name:
            log_d('err : ')
            return True
        else:
            log_d('<< current frame name >> :  {}'.format(cur_symbol_name))
            log_t('{}<< current frame name >> :  {}'.format(self.print_text*(self.print_index + 1),cur_symbol_name))
            self.print_index = self.print_index + 1
            log_d('increase : print_index')
            # continue
            return False

    # 获得当前 pc
    def get_current_pc(self):
        now_frame :lldb.SBFrame = self.thread.GetFrameAtIndex(0)
        if now_frame:
            return now_frame.GetPC()
        return None
  
    def check_address_in_instruction_list_and_instruction_end_address_list(self,address):
        # current_instruction_list 为空，或者  cur_pc(有效) 不在 current_instruction_list 里
        if not self.current_instruction_list or (address and (not (address in self.current_instruction_list))) :
            frame :lldb.SBFrame = self.thread.GetFrameAtIndex(0)
            symbol:lldb.SBSymbol = frame.GetSymbol()
            instructionlist : lldb.SBInstructionList = symbol.GetInstructions(self.target)

            if self.current_instruction_list:
                self.current_instruction_list = {}
                self.current_instruction_end_address_list = {}

            instruction :lldb.SBInstruction = None
            cur_end_address = symbol.GetEndAddress().GetLoadAddress(self.target)
            
            for instruction in instructionlist:
                address :lldb.SBAddress = instruction.GetAddress()
                cur_mnemonic:str = instruction.GetMnemonic(self.target)
                load_address = address.GetLoadAddress(self.target)
                self.current_instruction_list[load_address] = instruction  

                if cur_end_address == load_address:
                    self.current_instruction_end_address_list[load_address] = instruction
                    continue
                if self.check_str_in_arr(cur_mnemonic,CONST_DEVICE_info_list[DEVICE][CONST_INS_end]):
                    if not load_address in self.current_instruction_end_address_list:
                        self.current_instruction_end_address_list[load_address] = instruction
                            
    # 获得下一句 instruction 的偏移
    def get_offset(self):
        # 不同的指令集，返回的 指令长度不一样
        # self.current_instruction.GetByteSize()
        return 4

    def get_next_instrument(self):
        cur_pc = self.get_current_pc()
        if not cur_pc :
            self.next_instruction = None
            return
        offset = self.get_offset()
        next_pc = cur_pc + offset
        self.check_address_in_instruction_list_and_instruction_end_address_list(next_pc)

        if next_pc in self.current_instruction_list:
            self.next_instruction = self.current_instruction_list[next_pc]
        else:
            self.next_instruction = None

    def update_current_instrument(self):
        cur_pc = self.get_current_pc()     
        self.check_address_in_instruction_list_and_instruction_end_address_list(cur_pc)

        if cur_pc in self.current_instruction_list:
            self.current_instruction = self.current_instruction_list[cur_pc]
        else:
            self.current_instruction = None

    def update_last_instrument(self):
        self.last_instruction = self.current_instruction
        
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

    def check_in_current_call_return_list_and_increase_index(self,next_pc):
        if next_pc in self.current_call_return_instruction_list:
            index = self.current_call_return_instruction_list[next_pc]
            self.current_call_return_instruction_list[next_pc] = index + 1
        else:
            self.current_call_return_instruction_list[next_pc] = 1

    def check_need_delete_breakpoint_in_current_call_return_list_and_decrease_index(self,cur_pc):
        if cur_pc in self.current_call_return_instruction_list:
            index = self.current_call_return_instruction_list[cur_pc]
            if index > 0 :
                self.current_call_return_instruction_list[cur_pc] = index - 1
                return True
            else:
                self.current_call_return_instruction_list.pop(cur_pc)
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
                
                self.breakpoint_list.pop(curr_pc)
            else:
                log_d('->>> {} : breakpoint delete error'.format(hex(curr_pc)))

    def opration_breakpoint(self):
        self.get_next_instrument()
        self.add_next_breakpoint()
        self.delete_current_breakpoint()

    def check_instrument_in_current_end_addresss(self,ins:lldb.SBInstruction):
        addr = ins.GetAddress().GetLoadAddress(self.target)
        if addr in self.current_instruction_end_address_list:
            if not (addr in self.end_trace_address):
                self.print_index = self.print_index - 1
                log_d('decrease : print_index')
            
    # 处理 trace_instrument
    def deal_with_trace_instrument(self):
        instrument:lldb.SBInstruction = self.current_instruction
        mnemonic:str = instrument.GetMnemonic(self.target)
 
        self.check_instrument_in_current_end_addresss(instrument) # increase print_index

        if self.check_str_in_arr(mnemonic,CONST_DEVICE_info_list[DEVICE][CONST_INS_call]):
            self.opration_breakpoint()

            if self.next_instruction:
                next_pc = self.next_instruction.GetAddress().GetLoadAddress(self.target)
                self.check_in_current_call_return_list_and_increase_index(next_pc)

            self.thread.StepInstruction(False)
            cur_frame:lldb.SBFrame = self.thread.GetFrameAtIndex(0)
            cur_symbol:lldb.SBSymbol = cur_frame.GetSymbol()
            log_d('==> current symbol name : {}'.format(cur_symbol.GetName()))
            check_flag = self.check_wait_breakpoint_in_current_call(cur_symbol.GetName())

            if not check_flag:
                return CONST_DEAL_WITH_continue

            return CONST_DEAL_WITH_wait_breakpoint

        jmp_arr = CONST_DEVICE_info_list[DEVICE][CONST_INS_jmp]
        for jmp_item  in jmp_arr:
            if mnemonic.startswith(jmp_item):
                self.thread.StepInstruction(False)
                self.get_next_instrument()
                return CONST_DEAL_WITH_continue

        # if mnemonic.startswith(CONST_DEVICE_info_list[DEVICE][CONST_INS_syscall]):
        #     self.opration_breakpoint()
        #     return True
 
        self.opration_breakpoint()
        return CONST_DEAL_WITH_wait_breakpoint
        
    # 处理 trace_function
    def deal_with_trace_function(self):
        instrument:lldb.SBInstruction = self.current_instrument
        mnemonic:str = instrument.GetMnemonic()
        # if mnemonic.startswith(CONST_DEVICE_info_list[DEVICE][CONST_INS_call]):
        #     pass
        # elif mnemonic.startswith(CONST_DEVICE_info_list[DEVICE][CONST_INS_jmp]):
        #     pass
        # elif mnemonic.startswith(CONST_DEVICE_info_list[DEVICE][CONST_INS_syscall]):
        #     pass
        # else:
        pass

    def deal_with(self):
        if self.trace_type == TRACE_TYPE_Instrument:
            return self.deal_with_trace_instrument()
        elif self.trace_type == TRACE_TYPE_Function:
            return self.deal_with_trace_function()
        else:
            log_d('error trace type!')
            return CONST_DEAL_WITH_error

    def check_str_in_arr(self,cur_str:str,cur_arr):
        for item in cur_arr:
            if cur_str.startswith(item):
                return True
        return False

    def log_current_instrument(self):
        cur_mnemonic:str = self.current_instruction.GetMnemonic(self.target)
        cur_operands:str = self.current_instruction.GetOperands(self.target)
        cur_pc = self.get_current_pc()
        aligns = self.print_text * self.print_index
        if self.last_instruction:
            last_mnemonic:str = self.last_instruction.GetMnemonic(self.target)      
            if self.check_str_in_arr(last_mnemonic,CONST_DEVICE_info_list[DEVICE][CONST_INS_call]) :
                frame:lldb.SBFrame = self.thread.GetFrameAtIndex(0)
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
                frame:lldb.SBFrame = self.thread.GetFrameAtIndex(0)
                value:lldb.SBValue = frame.FindRegister(now_reg)
                data_str = '{}{: <3} : {} '.format(data_str,now_reg,value.GetValue())
            
            log_t('{}{: <15}{: <6}{: <30}// {} {}'.format(aligns,hex(cur_pc),cur_mnemonic,cur_operands,data_str,self.append_msg))
            self.append_msg = ''
            return
        log_t('{}{: <15}{: <6}{: <30} {}'.format(aligns,hex(cur_pc),cur_mnemonic,cur_operands,self.append_msg))
        self.append_msg = ''

    def check_is_exit(self):
        if self.current_instruction:
            curr_pc = self.current_instruction.GetAddress().GetLoadAddress(self.target)
            if curr_pc in self.end_trace_address:
                return True
        return False

    def clear_breakpoint_list(self):
        for item in self.breakpoint_list.values():
            breakpoint :lldb.SBBreakpoint = item[CONST_BREAKPOINT_BREAKPOINE]
            log_d('==> {}'.format(str(breakpoint)))
            self.target.BreakpointDelete(breakpoint.GetID())     
        self.breakpoint_list = {}

    def clear(self):
        self.clear_breakpoint_list()
        self.current_call_return_instruction_list = {}

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

# trace <-e --end-address> [<-m --model-type instrucment/function>] [<-s --self-module-only>] <-l --log-type trace/debug> <-t\-d --trace-file-name\--debug-file-name FILENAME>
# trace <-e --end-address> [<-m --model-type instrucment/function>] [<-s --self-module-only>] <-l --log-type all> <-t --trace-file-name FILENAME_0> <-d --debug-file-name FILENAME_1>
def parse_options(command, result):
    global options
    command_tokens = shlex.split(command)
    parser = TraceOptionParser(result)
    parser.add_option("-e","--end-address",action="store",metavar="END_ADDRESS",dest="end_address",help="End address of trace,using to stop trace thread")
    parser.add_option("-s","--self-module-only",action="store_true",dest="self_module_only",default=False,help="Trace only in current module")
    parser.add_option("-m","--model-type",action="store",metavar="<function/instrucment>",dest="model_type",default="instrucment",help='Trace model,contains function and instrucment')
    parser.add_option("-l","--log-type",action="store",metavar="<trace/debug/all>",dest="log_type",default=None,help="Log type in current tracing")
    parser.add_option("-t","--trace-file-name",metavar="TRACE_FILE_NAME",dest="trace_file_name",help="Redirect output to log_file_file")
    parser.add_option("-d","--debug-file-name",metavar="DEBUG_FILE_NAME",dest="debug_file_name",default=None,help="Redirect debug output to log_file_file")
    (options, _) = parser.parse_args(command_tokens)

    return parser.exited

def check_parser_command():
    global options
    global debug_log_file
    global trace_log_file
    if options.end_address is None :
        print("error : end_address error")
        return False

    log_type_arr = ['trace','debug','all']
    if not (options.log_type in log_type_arr):
        print('err : log type error')
        return False

    model_type_arr = ['function','instrucment']
    if not (options.model_type in model_type_arr):
        print('err : model type arr')
        return False

    if options.log_type == 'all':
        if options.debug_file_name is None:
            print('err : plz input debug file path')
            return False
        else:
            debug_log_file = open(options.debug_file_name,'w')
            trace_log_file = open(options.trace_file_name,'w')
    elif options.log_type == 'trace':
        if options.trace_file_name is None:
            print('err : trace need trace_file_name')
            return True
        # if os.path.exists(options.trace_file_name):
        trace_log_file = open(options.trace_file_name,'w')
    elif options.log_type == 'debug' :
        if options.debug_file_name is None:
            print('err : debug need trace_file_name')
            return True
        # if os.path.exists(options.debug_file_name):
        debug_log_file = open(options.debug_file_name,'w')
    else:
        log_d('err : log type err')
        return False

    return True


def continue_and_wait_for_breakpoint(process, thread, listening_thread, wait_event, notify_event):
    wait_event.set()
    log_d("Process in state: {}".format(str(process.GetState())))
    process.Continue()
    log_d('Process continued, waiting for notification')
    notify_event.wait()
    notify_event.clear()
    log_d('Got notification, process in state: {}, sanity checks follow'.format(str(process.GetState())))
    # Some sanity checking
    if listening_thread.wait_timed_out():
        log_d('Listener thread exited unexpectedly')
        return False
    if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        log_d("Thread {} didn't stop due to a breakpoint".format(str(thread)))
        return False
    return True

def Suspend_thread_escape_select_thread(process:lldb.SBProcess):
    select_thread :lldb.SBThread = process.GetSelectedThread()
    thread_num = process.GetNumThreads()
    if thread_num <= 1 :
        return
    for index  in range(thread_num) :
        tmp_thread :lldb.SBThread = process.GetThreadAtIndex(index)
        if not(select_thread.GetThreadID() == tmp_thread.GetThreadID()):
            log_d('Suspend {}'.format(tmp_thread))
            tmp_thread.Suspend()
        else:
            log_d('current run thread : {}'.format(tmp_thread))

def get_pc_addresses(thread):
    def GetPCAddress(i):
        return thread.GetFrameAtIndex(i).GetPCAddress()

    return map(GetPCAddress, range(thread.GetNumFrames()))

def print_stacktrace(target, thread):
    depth = thread.GetNumFrames()
    addrs = get_pc_addresses(thread)
    for i in range(depth):
        frame = thread.GetFrameAtIndex(i)
        function = frame.GetFunction()

        load_addr = addrs[i].GetLoadAddress(target)
        if not function:
            file_addr = addrs[i].GetFileAddress()
            start_addr = frame.GetSymbol().GetStartAddress().GetFileAddress()
            symbol_offset = file_addr - start_addr
            log_d('  frame #{num}: {addr:#016x} `{symbol} + {offset}'.format(num=i, addr=load_addr, symbol=frame.GetSymbol().GetName(), offset=symbol_offset))
        else:
            log_d('  frame #{num}: {addr:#016x} `{func}'.format(num=i, addr=load_addr, func=frame.GetFunctionName()))

def trace(debugger: lldb.SBDebugger, command: str, result: lldb.SBCommandReturnObject, internal_dict):
    """
    Traces execution of the symbol in the currently selected frame.
        trace -h/--help, for full help
    """
    global options
    if parse_options(command, result):
        return

    if not check_parser_command():
        return

    log_d("arguments: {}".format(str(options)))

    if options.end_address is None:
        print('err : pls input end address <-e endaddress>')
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
    # Suspend_thread_escape_select_thread(process)
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


    insObj = WTInstrument(target,thread,frame,debugger,TRACE_TYPE_Instrument,endAddress=int(options.end_address,16))
    insObj.init_last_symbol_name()
    insObj.init_end_address()

    while True:
        insObj.update_current_instrument()
        insObj.log_current_instrument() # 记录指令集 和 上一条指令 的 寄存器 值
        
        if insObj.check_is_exit():  # 
            insObj.clear()
            break

        check = insObj.deal_with() # 区分需要不需要  continue_and_wait_for_breakpoint
        insObj.update_last_instrument() # 把 当前 指令 保存为

        if check == CONST_DEAL_WITH_error:
            print('error : CONST_DEAL_WITH_error')
            break

        if  check == CONST_DEAL_WITH_continue :
            continue   # jmp 系列指令，直接

        # frame = thread.GetFrameAtIndex(0)
        log_d("=================== Stopped at: ====================")
        log_d("Frame: {}, symbol: {}, pc: {pc:#x}".format(str(frame), str(frame.GetSymbol()), pc=frame.GetPC()))

        continue_and_wait_for_breakpoint(process,thread,my_thread,wait_event,notify_event)

    # it needs clearing
    my_thread.exit()
    wait_event.set()
    my_thread.join()
    broadcaster.RemoveListener(listener)
    log_d('Listener thread exited completing')
    log_flush()


# And the initialization code to add your commands
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldbTrace.trace trace')
    print('The "trace" python command has been installed and is ready for use.')
    
