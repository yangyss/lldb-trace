#!/usr/bin/python3
# -*- encoding: utf-8 -*-
#@File    :   test.py
#@Time    :   2021/07/29 15:15:38
#@Author  :   wt 

from wtpytracer import *

####################
## command :
##      python3 test.py ~/Desktop/1627533881instrace.log

## 定义需要检测的 变量 : flag + '_' + 地址 + '_' + 寄存器
Check_0x10000393c_w8 = 'Check_0x10000393c_w8'


### 翻译的测试代码
def f(x):
    ret = 0
    for index in range(x):
        ret = ret + index
        check_value(ret,Check_0x10000393c_w8) # check ret 和 0x10000393c 的 w8 的寄存器值
    return ret + x


if __name__ == '__main__':
    import sys
    args_list = sys.argv
    if len(args_list) != 2 :
        exit()
    file_name = args_list[1]

    try:
        set_trace_data(Check_0x10000393c_w8)
        parser_trace_log_file(file_name)
        enable(CheckFunctionTracer())
        f(5)
    finally:
        disable()
