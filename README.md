# lldb-trace
Tracing instruction in lldb debugger.
just a python-script for lldb.


##### How to use it?

>1. Break at an address where you want to begin tracing.
>
>   []: https://github.com/yangyss/lldb-trace/blob/main/111.png
>
>2. Import  lldb python script.
>
>   []: https://github.com/yangyss/lldb-trace/blob/main/222.png
>
>3. Set an address where you want to end tracing.
>
>   []: https://github.com/yangyss/lldb-trace/blob/main/333.png
>
>4. Use  'trace' command,and  redirect log to file.
>
>   []: https://github.com/yangyss/lldb-trace/blob/main/444.png
>   []: https://github.com/yangyss/lldb-trace/blob/main/555.png

```python
trace -e 0x111111 -l all -t ~/tracelog.txt -d ~/debuglog.txt
```

> 参考：https://github.com/gm281/lldb-trace



