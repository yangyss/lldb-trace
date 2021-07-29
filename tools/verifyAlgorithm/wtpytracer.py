#!/usr/bin/python3
# -*- encoding: utf-8 -*-
#@File    :   wtpytracer.py
#@Time    :   2021/07/27 18:17:18
#@Author  :   wt 

import re
import sys
import inspect
from collections import OrderedDict

class TracebackFancy:
    
    def __init__(self, traceback):
        self.t = traceback

    def getFrame(self):
        return FrameFancy(self.t.tb_frame)

    def getLineNumber(self):
        return self.t.tb_lineno if self.t is not None else None

    def getNext(self):
        return TracebackFancy(self.t.tb_next)

    def __str__(self):
        if self.t is None:
            return ""
        str_self = "%s @ %s" % (
            self.getFrame().getName(), self.getLineNumber())
        return str_self + "\n" + self.getNext().__str__()


class ExceptionFancy:

    def __init__(self, frame):
        self.etraceback = frame.f_exc_traceback
        self.etype = frame.exc_type
        self.evalue = frame.f_exc_value

    def __init__(self, tb, ty, va):
        self.etraceback = tb
        self.etype = ty
        self.evalue = va

    def getTraceback(self):
        return TracebackFancy(self.etraceback)

    def __nonzero__(self):
        return self.etraceback is not None or self.etype is not None or self.evalue is not None

    def getType(self):
        return str(self.etype)

    def getValue(self):
        return self.evalue


class CodeFancy:

    def __init__(self, code):
        self.c = code

    def getArgCount(self):
        return self.c.co_argcount if self.c is not None else 0

    def getFilename(self):
        return self.c.co_filename if self.c is not None else ""

    def getVariables(self):
        return self.c.co_varnames if self.c is not None else []

    def getName(self):
        return self.c.co_name if self.c is not None else ""

    def getFileName(self):
        return self.c.co_filename if self.c is not None else ""


class ArgsFancy:

    def __init__(self, frame, arginfo):
        self.f = frame
        self.a = arginfo

    def __str__(self):
        args, varargs, kwargs = self.getArgs(), self.getVarArgs(), self.getKWArgs()
        ret = ""
        count = 0
        size = len(args)
        for arg in args:
            ret = ret + ("%s = %s" % (arg, args[arg]))
            count = count + 1
            if count < size:
                ret = ret + ", "
        if varargs:
            if size > 0:
                ret = ret + " "
            ret = ret + "varargs are " + str(varargs)
        if kwargs:
            if size > 0:
                ret = ret + " "
            ret = ret + "kwargs are " + str(kwargs)
        return ret

    def getNumArgs(wantVarargs=False, wantKWArgs=False):
        args, varargs, keywords, values = self.a
        size = len(args)
        if varargs and wantVarargs:
            size = size + len(self.getVarArgs())
        if keywords and wantKWArgs:
            size = size + len(self.getKWArgs())
        return size

    def getArgs(self):
        args, _, _, values = self.a
        argWValues = OrderedDict()
        for arg in args:
            argWValues[arg] = values[arg]
        return argWValues

    def getVarArgs(self):
        _, vargs, _, _ = self.a
        if vargs:
            return self.f.f_locals[vargs]
        return ()

    def getKWArgs(self):
        _, _, kwargs, _ = self.a
        if kwargs:
            return self.f.f_locals[kwargs]
        return {}

class FrameFancy:
    
    def __init__(self, frame):
        self.f = frame

    def getCaller(self):
        return FrameFancy(self.f.f_back)

    def getLineNumber(self):
        return self.f.f_lineno if self.f is not None else 0

    def getCodeInformation(self):
        return CodeFancy(self.f.f_code) if self.f is not None else None

    def getExceptionInfo(self):
        return ExceptionFancy(self.f) if self.f is not None else None

    def getName(self):
        return self.getCodeInformation().getName() if self.f is not None else ""

    def getFileName(self):
        return self.getCodeInformation().getFileName() if self.f is not None else ""

    def getLocals(self):
        return self.f.f_locals if self.f is not None else {}

    def getArgumentInfo(self):
        return ArgsFancy(
            self.f, inspect.getargvalues(
                self.f)) if self.f is not None else None

class TracerClass:
    
    def callEvent(self, frame):
        pass

    def lineEvent(self, frame):
        pass

    def returnEvent(self, frame, retval):
        pass

    def exceptionEvent(self, frame, exception, value, traceback):
        pass

    def cCallEvent(self, frame, cfunct):
        pass

    def cReturnEvent(self, frame, cfunct):
        pass

    def cExceptionEvent(self, frame, cfunct):
        pass

tracer_impl = TracerClass()
data_dic = {}
old_trace_func = None

def parser_flag(flag):
    import re
    aa = re.split(r'_',flag)
    if len(aa) != 3 :
        return None,None
    return aa[1],aa[2]

class CheckFunctionTracer():
    def callEvent(self, frame):
        if 'check_value' == frame.getName():
            flag = frame.getArgumentInfo().getArgs()['check_flag']
            value = frame.getArgumentInfo().getArgs()['value']
            addr,register = parser_flag(flag)
            if addr in data_dic and register in data_dic[addr]:
                run_index = data_dic[addr][register]['run_index']
                data_len = len(data_dic[addr][register]['data'])
                if run_index >= data_len:
                    print('*** err : at address : {} . run_index : {} out of rang'.format(addr,run_index))
                    return
                if value == data_dic[addr][register]['data']['{}'.format(run_index + 1)] :
                    print('check : {} at {} times,match.'.format(addr,run_index + 1))
                    data_dic[addr][register]['run_index'] = run_index + 1

            # print("->>LoggingTracer : call " + frame.getName() + " from " + frame.getCaller().getName() + " @ " + str(frame.getCaller().getLineNumber()) + " args are " + str(frame.getArgumentInfo()))



# @ check_flag 为 携带了地址，和寄存器名称
# @ value 为当前需要 check 的值
# 在 sys.settracer设置的回调中，只接管此函数
def check_value(value,check_flag):
    pass


def set_trace_data(check_flag):
    global data_dic
    addr,register = parser_flag(check_flag)
    if not addr or not register :
        print('err : check_flag is wrong.')
        return
    
    if addr in data_dic:
        data_dic[addr][register] = {
            'data':{},
            'run_index':0   
        }
    else:
        addr_dic = {
            register:{
                'data':{},
                'run_index':0
            }
        }
        data_dic[addr] = addr_dic


def add_data_in_data_dic(addr,register,value):
    global data_dic
    cur_reg_dic = data_dic[addr][register]
    data_len = len(cur_reg_dic['data'])
    data_dic[addr][register]['data']['{}'.format(data_len + 1)] = value

def parser_trace_log_file(fileName):
    global data_dic
    file = open(fileName)
    while True:
        lines = file.readlines(100000)
        if not lines:
            break
        for line in lines:
            matchObj = re.match(r'\s*(\S+)\s+',line,re.M|re.I)
            if matchObj:
                addr = str(matchObj.group()).replace(' ','')
                if addr in data_dic:
                    reg = data_dic[addr]
                    for register in data_dic[addr].keys():
                        register_out = re.findall(register +r'  : (\S+)',line)
                        if register_out:
                            register_value = int(register_out[0],16)
                            add_data_in_data_dic(addr,register,register_value)
        
    file.close()
    # {'1234':{'1':0,"2":1}}  # flag : {...}  address:{'x0':{data:{},run_index:0},'x1':{data:{},run_index:0}}


def the_tracer_check_data(frame, event, args = None):
    global data_dic
    global tracer_impl

    code = frame.f_code 

    func_name = code.co_name 
  
    line_no = frame.f_lineno 
    if tracer_impl is None:
        print('@@@ tracer_impl : None.')
        return None

    if event == 'call':
        tracer_impl.callEvent(FrameFancy(frame))

    return the_tracer_check_data



def enable(tracer_implementation=None):
    global tracer_impl,old_trace_func
    if tracer_implementation:
        tracer_impl = tracer_implementation  # 传递 工厂实力的对象
    old_trace_func = sys.gettrace()
    sys.settrace(the_tracer_check_data) # 注册回调到系统中


def check_run_ok():
    global data_dic
    for addr,addr_dic in data_dic.items():
        for _,reg_dic in addr_dic.items():
            if reg_dic['run_index'] == len(reg_dic['data']):
                print('->>> at {} check value is perfect.'.format(addr))
            else:
                print('*** err : at {} check {} times.'.format(addr,reg_dic['run_index']))

def disable():
    check_run_ok()
    global old_trace_func
    sys.settrace(old_trace_func)
    
