# Proxy Server Implementation

This repository is created to explore HTTP concepts and gain hands-on experience with socket APIs.
To do so, we implement a simple web proxy that passes requests and data between a web client and a web server. 

## Setup

1. Please fork this repository to a local directory of your choice and ensure that you have Python installed.

## Running the Proxy
#### Please refer to the following instructions to run and test your proxy server:

1. Launch a terminal in the directory containing ``proxy.py``
1. After the terminal is open, run the following command: 

    ``python proxy.py [PORT NUMBER] [IMG SUBSTITUTION FLAG = {0, 1}] [ATTACKER FLAG = {0, 1}]``
    
    where items in ``[]`` will require you to modify the input value respectively. Flags can take on binary values while ``PORT NUMBER`` can be any valid port value of your choice.
    
1. If the above command results in an error like: ``python not found``, 
    
    try replacing the ``python`` keyword above with ``python3`` instead.
    
1. Once your proxy is running, you should be able to see the following line printed on your terminal:

    ``[Server Activated] Listening on [IP ADDRESS]:[PORT]``
    
    where ``[IP ADDRESS]:[PORT]`` represents the IP address and port that your server has bind to respectively.

1. Lastly, head to your browser's network settings and opt for manual proxy configuration. This allows the browser to retrieve webpages through the sample proxy server created in this repo. The following is a sample FireFox browser configuration with ``xcne3`` as the IP Address and port ``5678``.

<img src="https://user-images.githubusercontent.com/48002577/205266928-9ac75c4f-1a05-4aba-bf75-923ba557e113.png" width="500">

    
## Telemetry
The proxy server has been configured to print the collective telemetry of all objects belonging to the same webpage <b>10 seconds after the webpage has been completely loaded</b>.

Additionally, telemetry results are not configured to match specific referer URLs and is configured to work accurately only when webpages are downloaded one at a time. 

## Telemetry for sample testcases

Please note that the telemetry results will only work for sites running on HTTP and not HTTPS. Below is a sample of the telemetry display for loading sites hosted on ``ocna``.

![image](https://user-images.githubusercontent.com/48002577/202711688-e329d283-94bb-4fdc-8d31-5cfd81ac5b58.png)


## Attacker Mode
When the attacker mode is engaged, it overwrites all incoming HTTP requests with the "You are being attacked" message. This technically overwrites the Image substitution flag since no images will be fetched in attacker mode.

## Extra
Input validation is also added for the proxy server and invalid flags (Attacker and Image Substitution) will result in the termination of the program with the following error messages:

![image](https://user-images.githubusercontent.com/48002577/205266268-0ecdde4a-c182-453b-9107-95c6579b74be.png)

