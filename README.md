# lldb-trace
Tracing instruction in lldb debugger.
just a python-script for lldb.


##### How to use it?

>1. Break at an address where you want to begin tracing.
>2. Import  lldb python script.
>3. Set an address where you want to end tracing.
>4. Use  'trace' command,and  redirect log to file.

```python
trace -e 0x111111 -l all -t ~/tracelog.txt -d ~/debuglog.txt
```

> 参考：https://github.com/gm281/lldb-trace

