import sys
import socket
import threading

HTTP_MSG_TERMINATION = b'\r\n\r\n'
GET_REQ = "GET"
HTTP_VERSIONS = ["HTTP/1.0", "HTTP/1.1"]
HTTP_TAGS = ["http", "https"]
HOST_TAG = "Host:"
CONNECTION_TAG = "Connection:"
USER_AGENT_TAG = "User-Agent:"


def fetchArgs():
    port = int(sys.argv[1])
    imgSub = int(sys.argv[2])
    attackerMode = int(sys.argv[3])
    
    print(f"[Server Configs] \n Port: {port} \n Image Substitution: {imgSub} \n Attacker Mode: {attackerMode}")
    
    return port, imgSub, attackerMode

###################### Verification Functions ############################

def verifyRequestLine(requestLine):
    # add exceptions !!!!
    if len(requestLine) != 3:
        print("[Request Line Len] 404 - Bad Request")
        return False
        
    if requestLine[0] != GET_REQ:
        print("[Request Type not GET] 404 - Bad Request")
        return False
    
    if requestLine[2] not in HTTP_VERSIONS:
        print("[Invalid HTTP Ver] 404 - Bad Request")
        return False
    
    return True
                
# def verifyHeaderLines(msg):
    # hostPresent, connectionPresent, userAgentPresent = False
    # hostIdx = None
    
    # for i in range(1, len(msg)):
    #     if msg[i].startswith(HOST_TAG):
            # hostPresent = True
            # hostIdx = i
        # elif msg[i].startswith(CONNECTION_TAG):
        #     connectionPresent = True
        # elif msg[i].startswith(USER_AGENT_TAG):
        #     userAgentPresent = True
    
    # headerValidity = hostPresent and connectionPresent and userAgentPresent
    # return hostIdx

def retrieveHost(msg):
    hostIdx = None
    host = None
    port = None
    
    for i in range(1, len(msg)):
        if msg[i].startswith(HOST_TAG):
            hostIdx = i
    
    if hostIdx is not None:        
        hostContent = msg[hostIdx].split(" ")
        
        if ":" in hostContent[1]:
            hostAndPort = hostContent[1].split(":")
            host = hostAndPort[0]
            port = hostAndPort[1]
    
    return host, port

def deconstructReqLine(requestLine):
    url = requestLine[1]
    if "://" in url:
        urlParts = url.split("://")
        if len(urlParts) != 2 or urlParts[0] not in HTTP_TAGS:
            # Add exception
            print("Error")
        url = urlParts[1]
    
    pathIdx = url.find("/")
    hostLink = ""
    path = "/"
    
    if pathIdx != -1:
        hostLink = url[:pathIdx]
        path = url[pathIdx:]
    else:
        hostLink = url
    
    if ":" in hostLink:
        hostWithoutPort = hostLink.split(":")
        hostLink = hostWithoutPort[0]
    
    return hostLink, path

def reconstructReqLine(requestLine, path):
    newReqLine = requestLine[0] + " " + path + " " + requestLine[2]
    newReqLineByte = str.encode(newReqLine)
    newReqLineByte += b"\r\n"
    return newReqLineByte

def reconstructRequest(reqLine, msg):
    output = b""
    for i in range(1, len(msg)-1):
        encodedLine = str.encode(msg[i])
        encodedLine += b"\r\n"
        output += encodedLine
    
    output = reqLine + output
    return output

###################### Handle Client Thread ############################

def handleClientReq(conn, addr):
    print(f"[Server] Client Connected: {addr}")
    
    msg = None
    timeoutFlag = False
    while True:
        # try:
        msg = conn.recv(1024)
        # except socket.timeout as e:
        #     timeoutFlag = True
        # if len(msgChunk) > 0:
        #     msg += msgChunk
        if msg is None:
            break
        
        # Checks for carriage return at the end of header lines
        if msg[-4:] != HTTP_MSG_TERMINATION:
            print("[Missing Termination] 404 - Bad Request")
        
        msg = msg.decode("utf-8")
        print(f"\n[Client Message]:\n{msg}")
        msg = msg.split("\r\n")
        
        # Check if request line is of the right format
        requestLine = msg[0].split(" ")
        isReqLineValid = verifyRequestLine(requestLine)
        host, webServerPort = retrieveHost(msg)
        
        hostLink, urlPath = deconstructReqLine(requestLine)
        reconstructedReqLine = reconstructReqLine(requestLine, urlPath)
        newReq = reconstructRequest(reconstructedReqLine, msg)
        
        if webServerPort is None:
            webServerPort = 80
        
        if host is None:
            # retrieve host from request line
            host = hostLink
        
        print("[RECONSTRUCTED REQUEST]")
        print(newReq)
        connectWebServer(conn, newReq, host, int(webServerPort))    
    conn.close()

def connectWebServer(browserSocket, request, host, port):
    webServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    webServerSocket.settimeout(10)
    try:
        webServerSocket.connect((host, port))
        webServerSocket.sendall(request)
    except socket.timeout as e:
        # Should send bad request here
        print(e)

    response = b""
    responseChunk = b""
    timeoutFlag = False
    while True:
        try:
            responseChunk = webServerSocket.recv(4096)
        except socket.timeout as e:
            timeoutFlag = True
        
        if len(responseChunk) > 0:
            response += responseChunk
        else:
            break
        if timeoutFlag:
            break
    
    print("[RESPONSE FROM WEBSERVER]")
    print(response)
    # // To edit
    errorMessage = b"400 Bad Request Error"
    
    if len(response) == 0 and timeoutFlag:
        browserSocket.sendall(errorMessage)
    else:
        print("\n[SENDING PROXY -> BROWSER]")
        browserSocket.sendall(response)
        print("\n[SENT COMPLETE PROXY -> BROWSER]")
    
    webServerSocket.close()

def proxyServer(port):
    ipAddress = socket.gethostbyname(socket.gethostname())
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server.bind((ipAddress, port))
    server.listen()
    print(f"[Server Activated] Listening on {ipAddress}:{port}")
    
    while True:
        connection, addr = server.accept()
        thread = threading.Thread(target=handleClientReq, args=(connection, addr))
        thread.start()
        print(f"[Server] Active Threads: {threading.activeCount() - 1}")

if __name__ == "__main__":
    port, imgSub, attackerMode = fetchArgs()
    proxyServer(port)
    
    