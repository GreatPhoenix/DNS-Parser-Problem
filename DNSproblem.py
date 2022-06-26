# Enter your code here. Read input from STDIN. Print output to STDOUT
# Code Created and Written by Bridget Whitacre (^▽^)
# The rtc used is rtc1035 and rtc3596; link: https://datatracker.ietf.org/doc/html/rfc1035 , https://datatracker.ietf.org/doc/html/rfc3596#section-2.1 

import sys


def main ():
    #main function that runs all other functions
    answer = []
    message = getInput()
    header = processHeader(message)
    question = questionProcess(message,header)
    hexStart = question[3]
    for i in range(int (header[5])):
        answer.append(answerProcess(message,hexStart))
        hexStart = answer[i][6]
        
    
    outputToSTD(formatting(header,question,answer))
    

    
def getInput ():
    #gets the input from STDIN
    for message in sys.stdin:
        if 'q' == message.rstrip():
            break
        return message

def outputToSTD(message):
    #Outputs string message to STDOUT
    sys.stdout.write(str(message))
    
    
def processHeader(message):
    #The whole message is inserted and the header function decodes the header part of the message and returns it as a list
    header = message[:24]
    hID = header[:4]
    decHID = int(hID, 16)
    
    
    legth = header[4:]
    messageBinaryValue = bin(int(legth,16))[2:]
    QR = messageBinaryValue[0]
    OPCODE = messageBinaryValue[1:5]
    AA = messageBinaryValue[5]
    TC = messageBinaryValue[6]
    RD = messageBinaryValue[7]
    RA = messageBinaryValue[8]
    Z = messageBinaryValue[9:12]
    RCODE = messageBinaryValue[12:16]
    QDCOUNT = messageBinaryValue[16:32]
    ANCOUNT = messageBinaryValue[32:48]
    NSCOUNT = messageBinaryValue[48:64]
    ARCOUNT = messageBinaryValue[64:80]
    
    textOPTCODE = ''
    # below are converstion to make the data readable
    if (OPCODE == "0000"):
        textOPTCODE = "QUERY"
    elif (OPCODE == "0001"):
        textOPTCODE = "INVERSE QUERY"
    elif (OPCODE == "0010"):
        textOPTCODE = "SERVER STATUS"
    else:
        textOPTCODE = "UNKOWN OPTCODE"
        
    flags = ''
    if (QR == '1'):
        flags += "qr "
    if (AA == '1'):
        flags += "aa "
    if (TC == '1'):
        flags += "tc "
    if (RD == "1"):
        flags += "rd "
    if (RA == "1"):
        flags += "ra "
    
    numQDCOUNT = str(int(QDCOUNT, 2))
    numANCOUNT = str(int(ANCOUNT, 2))
    numNSCOUNT = str(int(NSCOUNT, 2))
    numARCOUNT = str(int(ARCOUNT, 2))     
        
    #there is a better way to error check but I would need an example of a bad DNS message
    status = "NOERROR"
    
    return([textOPTCODE,status,decHID,flags[:len(flags)-1],numQDCOUNT,numANCOUNT,numNSCOUNT,numARCOUNT, TC,RD,RA,Z,RCODE])
    
def questionProcess(message,header):
    #inputs the hex message and the header and then returns a list of the website, Qtype, and Qclass
    counter = 0
    index = 80
    
    labels = []
    returnList = []
    questionSectionStart = findQuestStart(message,index)
    hexIndex = questionSectionStart[0]
    
    #function is used to find the start of the question statment as there are a lot of 0s for padding
    while(message[hexIndex] != '0' and message[hexIndex+1] != '0'):
        #labelsToAscii run twice cause python pointers are weird, in C++ this only needs to run once
        processedMessage = labelToAscii(message,hexIndex)
        labels.append(labelToAscii(message,hexIndex))
        hexIndex += (len(processedMessage)*2) +2
        
    # once the begining is found program starts parsing through the message
    hexIndex += 1
    QTYPE = message[hexIndex:hexIndex+4]
    QCLASS = message[hexIndex+4:hexIndex+8]
    
    strQCLASS= QCLASS
    strQTYPE = QTYPE
    if (QCLASS == "0001"):
        strQCLASS = 'IN'
    
    if (QTYPE == "0001"):
        strQTYPE = "A"
    elif (QTYPE == "001c"):
        strQTYPE = "AAAA"
    elif (QTYPE == "0005"):
        strQTYPE = "CNAME"
    
    website = listToWebString(labels)
    
    returnList.append(website)
    returnList.append(strQTYPE)
    returnList.append(strQCLASS)
    returnList.append(hexIndex+8)
    return (returnList)

def answerProcess(message, hexIndexStart):
    #inputs the message and the starting index were the question section ends
    nameBinaryValue = bin(int(message[hexIndexStart:hexIndexStart + 4],16))[2:]
    yesCount = 0
    counter = 0
    offset = 0
    hexIndex = 0
    labels = []
    # function for finding the start of the answer section
    for i in nameBinaryValue[2:]:
        if (i == "1"):
            yesCount += 1
        if (yesCount == 2):
            offset += 1
            break
        
        offset += 1
    
    hexIndex += hexIndexStart + 4
    tempHex = offset * 2 +1
     # parces through the message to find hostname   
    while(message[tempHex] != '0' and message[tempHex+1] != '0'):
        #labelsToAscii run twice cause python pointers are weird, in C++ this only needs to run once
        processedMessage = labelToAscii(message,tempHex)
        labels.append(labelToAscii(message,tempHex))
        tempHex += (len(processedMessage)*2) +2
    #classification
    WEBSITE = listToWebString(labels)
    TYPE = message[hexIndex:hexIndex+4]
    CLASS = message[hexIndex+4:hexIndex+8]
    hexIndex += 8
    hexTTL = message[hexIndex:hexIndex+8]
    TTL = hexToDec(hexTTL)
    hexIndex += 8
    RDLENGTH = hexToDec(message[hexIndex:hexIndex+4])
    hexIndex += 4
    #reformating to make it easy to read
    strCLASS = CLASS
    if (CLASS == "0001"):
        strCLASS = "IN"
    strTYPE = ''
    
    if (TYPE == "0001"):
        strTYPE = "A"
    elif (TYPE == "001c"):
        strTYPE = "AAAA"
    elif (TYPE == "0005"):
        strTYPE = "CNAME"
    #different ip adress processing depending on record type (A or AAAA)    
    IPADDRESS = ''
    if (strTYPE == "A"):
        for i in range(0,RDLENGTH):
            tempIP = message[hexIndex:hexIndex+2]
            IPADDRESS += str(hexToDec(tempIP))
            if (i != RDLENGTH-1):
                IPADDRESS += '.'
            hexIndex = hexIndex + 2
            
    elif(strTYPE == "AAAA"):
        isZero = False
        for i in range(0, RDLENGTH//2):
            tempIP = message[hexIndex:hexIndex+4]
            
            if (tempIP == "0000"):
                isZero = True
                
            if (isZero and tempIP != "0000"):
                isZero = False
                IPADDRESS+=":"
                
            IPADDRESS += hexToipv6(tempIP)
                
            if (i != (RDLENGTH//2)-1 and tempIP != "0000"):
                IPADDRESS += ":"
            hexIndex += 4
    # CNAME Honistly stumpted me and I could not get working conceptually. I am open to learning how CNAME is parced as I am not passing 1 test       
    
    return([WEBSITE,strCLASS,strTYPE,TTL,RDLENGTH,IPADDRESS,hexIndex])
    

def formatting(header, question, answer):
    #used to format the message before being sent to STDOUT
    finalMessage = ""
    
    #Header Section
    finalMessage += ";; ->>HEADER<<- opcode: " + str(header[0]) + ", status: " + str(header[1]) + ", id: " + str(header[2]) + "\n"
    finalMessage += ";; flags: " + str(header[3]) + "; QUERY: " + header[4] + ", ANSWER: " + header[5] + ", AUTHORITY: " + header[6] + ", ADDITIONAL: " + header[7] + "\n\n"
    
    #Question Section
    finalMessage += ";; QUESTION SECTION:\n"
    
    finalMessage += ";" + question[0] + "\t\t" + question[2] + "\t" + question[1] + "\n\n"
        
    #Answer Section
    finalMessage += ";; ANSWER SECTION:"
    for i in answer:
        finalMessage += "\n"
        tempAnswer = i
        finalMessage += tempAnswer[0] + "\t\t" + str(tempAnswer[3]) + "\t" + str(tempAnswer[1]) + "\t" + str(tempAnswer[2]) + "\t" + str(tempAnswer[5])
    
    # I like to add this to show that the program finishes but it makes tests fail. (also tron reference)
    #finalMessage += "\n--END OF LINE--"
    
    return finalMessage
    
def binaryToAscii (binaryBits):
    #converts Binary numbers to Ascii letters
    binaryBits = int(binaryBits,2)
    length = binaryBits.length() + 7 // 8
    arrayOfBytes = binaryBits.to_bytes(length, "big")
    return (arrayOfBytes.decode())

def findQuestStart(message,inputIndex):
    #function finds the start of the question if prevouse statment has alot of padding
    index = inputIndex//4
    sizeOfLabel = ''
    startIndex = 0
    for i in message[index:]:
        if i != "0":
            sizeOfLabel = i
            
            startIndex = message[index:].index(i)
            break
        
    return([startIndex+index,int(sizeOfLabel)])


def labelToAscii(message,startIndex):
    #Converts the string of hexidecimal to ascii string
    sizeOfLabel = hexToDec(message[startIndex-1] + message[startIndex])
           
    decodedTextArray = bytearray.fromhex(message[startIndex + 1:startIndex + (sizeOfLabel*2) + 1])
    decodedTextArray.decode()
    strDecode = bytes(decodedTextArray)
    
    return(str(strDecode)[2:int(sizeOfLabel)+2])
        
def listToWebString(inputList):
    #converts the "labels" of a hostname and returns a string of the hostname put togather
    website = ''
    for i in inputList:
        website += i + '.'            
    
    return (website)

def hexToDec(hexValue):
    #converts hexidecimal to decimal values
    return (int(hexValue,16))

def hexToipv6(hexvalue):
    #converts hex values to ipv6 valid decimal values
    ipv6 = ''
    found0 = False
    for i in hexvalue:
        if (i != "0" or found0):
            ipv6 += i
            found0 = True
    return ipv6

    
main()