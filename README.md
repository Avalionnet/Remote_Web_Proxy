# CS3103 Programming Assignment

## Running the Proxy
#### Please refer to the following instructions to run and compile your proxy server:

1. Launch a terminal in the directory containing ``proxy.py``
1. After the terminal is open, run the following command: 

    ``python proxy.py [PORT NUMBER] [IMG SUBSTITUTION FLAG = {0, 1}] [ATTACKER FLAG = {0, 1}]``
    
1. If the above command results in an error like the following: ``python not found``, 
    
    try replacing the ``python`` keyword above with ``python3`` instead.
    
## Telemetry
The proxy server has been configured to print the collective telemetry of all objects belonging to the same webpage <b>10 seconds after the webpage has been completely loaded</b>. Hence, I seek your understanding in the slight delay of the printing.

Additionally, as stated in Piazza, telemetry results are not configured to match specific referer URLs and is configured to work accurately only when webpages are downloaded one at a time. 

This is made possible by the following clause announced in the updated FAQ:

If the following image is missing, please refer to markdown

![image](https://user-images.githubusercontent.com/48002577/202707570-1b8c1fc6-a838-47dc-9fc0-6b43b005a308.png)

## Telemetry for sample testcases provided

If the following image is missing, please refer to markdown

![image](https://user-images.githubusercontent.com/48002577/202711688-e329d283-94bb-4fdc-8d31-5cfd81ac5b58.png)



## Attacker Mode
When the attacker mode is engaged, it overwrites all incoming HTTP requests with the "You are being attacked" message. This technically overwrites the Image substitution flag since no images will be fetched in attacker mode.

## Extra
Input validation is also added for the proxy server and invalid flags (Attacker and Image Substitution) will result in the termination of the program with the following error messages:

If the following image is missing, please refer to markdown

![image](https://user-images.githubusercontent.com/48002577/202708599-99ed5e92-dbb5-4a5c-be68-fabc7a665aca.png)


