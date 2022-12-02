import sys
import socket
import threading
from threading import current_thread
from queue import Queue
import time

HTTP_MSG_TERMINATION = b'\r\n\r\n'
GET_REQ = "GET"
HEAD_REQ = "HEAD"
HTTP_VERSIONS = ["HTTP/1.0", "HTTP/1.1"]
HTTP_TAGS = ["http", "https"]
HOST_TAG = "Host:"
CONNECTION_TAG = "Connection:"
USER_AGENT_TAG = "User-Agent:"
BAD_RESPONSE = str.encode("HTTP/1.1 400 Bad Request\r\n\r\n")


def fetchArgs():
    acceptableVals = [0,1]
    port = int(sys.argv[1])
    imgSub = int(sys.argv[2])
    attackerMode = int(sys.argv[3])
    
    if imgSub not in acceptableVals:
        raise Exception("[Invalid Image Substitution argument detected] - Please try again\n")
    
    if attackerMode not in acceptableVals:
        raise Exception("[Invalid Attacker Mode argument detected] - Please try again\n")
    
    # print(f"[Server Configs] \n Port: {port} \n Image Substitution: {imgSub} \n Attacker Mode: {attackerMode}")
    
    return port, imgSub, attackerMode

###################### Verification Functions ############################

def verifyRequestLine(requestLine):
    if len(requestLine) != 3:
        return True
        
    if requestLine[0] != GET_REQ:
        return True
    
    if requestLine[2] not in HTTP_VERSIONS:
        return True
    
    return False

def retrieveHost(msg, reqLine):
    hostIdx = None
    host = None
    port = None
    
    if reqLine[2] != HTTP_VERSIONS[1]:
        return host, port
    
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
    isInvalid = False
    url = requestLine[1]
    if "://" in url:
        urlParts = url.split("://")
        if len(urlParts) != 2 or urlParts[0] not in HTTP_TAGS:
            isInvalid = True
        url = urlParts[1]
    
    pathIdx = url.find("/")
    hostLink = ""
    path = "/"
    port = 80
    
    if pathIdx != -1:
        hostLink = url[:pathIdx]
        path = url[pathIdx:]
    else:
        hostLink = url
    
    if ":" in hostLink:
        hostWithoutPort = hostLink.split(":")
        hostLink = hostWithoutPort[0]
        if hostWithoutPort[1].isdigit():
                port = int(hostWithoutPort[1])
        else:
            isInvalid = True
    
    return hostLink, port, path, isInvalid

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

def attack(conn, url, q):
    attackResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    attackMsg = "<header><title>You are being attacked</title></header><body><h1>You are being attacked</h1></body>"
    conn.sendall(bytes(attackResponse, "UTF-8"))
    conn.sendall(bytes(attackMsg, "UTF-8"))
    q.put((url, len(attackMsg)))
    conn.close()
    return

def handleClientReq(conn, addr, imgSub, attackerMode, q):    
    isBadRequest = False
    msg = None
    # timeoutFlag = False
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
            isBadRequest = True
        
        msg = msg.decode("ISO-8859-1")
        msg = msg.split("\r\n")
        
        # Check if request line is of the right format
        requestLine = msg[0].split(" ")
        
        isBadRequest = verifyRequestLine(requestLine) or isBadRequest
        if isBadRequest:
            conn.sendall(BAD_RESPONSE)
            conn.close()
            return
        
        if attackerMode == 1:
            return attack(conn, requestLine[1], q)
        
        host, webServerPort = retrieveHost(msg, requestLine)
        hostLink, hostPort, urlPath, isUrlValid = deconstructReqLine(requestLine)
        isBadRequest = isUrlValid or isBadRequest
        reconstructedReqLine = reconstructReqLine(requestLine, urlPath)
        newReq = reconstructRequest(reconstructedReqLine, msg)
        
        if webServerPort is None:
            webServerPort = hostPort
        
        if host is None:
            # retrieve host from request line
            host = hostLink
            if requestLine[2] != HTTP_VERSIONS[1]:
                isBadRequest = False
        
        if isBadRequest:
            conn.sendall(BAD_RESPONSE)
            conn.close()
            return
        else:
            webServerResp = connectWebServer(conn, newReq, host, int(hostPort), imgSub, attackerMode, requestLine[1], q)
            if webServerResp == 0:
                conn.close()
                return   
    conn.close()

def isImgContent(resp):
    response = resp.decode("ISO-8859-1")
    response = response.split("\r\n")
    for i in range(0,len(response)):
        if response[i].startswith("Content-Type: image"):
            return True
    return False

def findPayloadSize(resp):
    length = ""
    
    decodedResp = resp.decode("ISO-8859-1")
    payloadIdx = decodedResp.find("\r\n\r\n", 1)
    
    header = decodedResp[:payloadIdx]
    contentIdx = header.find("Content-Length: ")
    
    if contentIdx != -1:
        endOfContent = header[contentIdx:].find("\r\n", 1)
        value = header[contentIdx:][:endOfContent]
        valueArr = value.split(": ")
        length = valueArr[1]
    else:
        payload = decodedResp[payloadIdx+4:]
        encodedPayload = bytes(payload, "ISO-8859-1")
        length = str(len(encodedPayload))
    
    return length

def connectWebServer(browserSocket, request, host, port, imgSub, attackerMode, url, q):
    webServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    webServerSocket.settimeout(2)
    
    if imgSub == 1:
        ogReq = request.decode("utf-8")
        newReq = ogReq.replace(GET_REQ, HEAD_REQ, 1)
        newReqBytes = str.encode(newReq)
    
    try:
        webServerSocket.connect((host, port))
        if imgSub == 0:
            webServerSocket.sendall(request)
        else:
            webServerSocket.sendall(newReqBytes)
    except:
        browserSocket.sendall(BAD_RESPONSE)
        webServerSocket.close()
        return 0

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
    
    if imgSub == 1:
        if isImgContent(response):
            subHost = "ocna0.d2.comp.nus.edu.sg"
            subPort = 50000
            substitute = b"GET /change.jpg HTTP/1.1\r\nHost: ocna0.d2.comp.nus.edu.sg:50000\r\n\r\n"
            webServerSocket.close()
            return connectWebServer(browserSocket, substitute, subHost, subPort, 0, attackerMode, url, q)
        else:
            webServerSocket.close()
            return connectWebServer(browserSocket, request, host, port, 0, attackerMode, url, q)
        
    if len(response) == 0 and timeoutFlag:
        browserSocket.sendall(BAD_RESPONSE)
    else:
        browserSocket.sendall(response)
        payloadSize = findPayloadSize(response)
        q.put((url, int(payloadSize)))
    
    webServerSocket.close()
    return 1

def printThread(q, filler):
    while True:
        totalSize = 0
        timer = 0
        collectedItems = []
        while timer < 8:
            try:
                objSize = q.get_nowait()
                
                # If thread server is closed but sadly this line will never be reached :(
                if objSize is None:
                    return
                
                collectedItems.append(objSize)
                timer = 0
                totalSize += objSize[1]
            except:
                timer += 1
                time.sleep(1)   
        try: 
            siteName = collectedItems.pop(0)
            print(siteName[0] + ", " + str(totalSize))
        except:
            continue

def proxyServer(port, imgSub, attackerMode):
    ipAddress = socket.gethostbyname(socket.gethostname())
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server.bind((ipAddress, port))
    # server.bind(('0.0.0.0', port))
    server.listen()
    
    objQueue = Queue()
    teleThread = threading.Thread(target=printThread, args=(objQueue,None))
    teleThread.start()
    print(f"[Server Activated] Listening on {ipAddress}:{port}")
    count = 0
    while True:
        connection, addr = server.accept()
        thread = threading.Thread(target=handleClientReq, args=(connection, addr, imgSub, attackerMode, objQueue))
        thread.name = count
        count += 1
        thread.start()
    
    # poison pill to kill thread when done
    objQueue.put(None)

if __name__ == "__main__":
    try:
        port, imgSub, attackerMode = fetchArgs()
        proxyServer(port, imgSub, attackerMode)
    except Exception as e:
        print(str(e))        
    
