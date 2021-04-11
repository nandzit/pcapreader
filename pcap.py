import pdb

#The Header of a libpcap file
pca_hdr_s = 20 
pcaprec_hdr_s = 16
lenghtOffSet = 12

#Separator of a MAC ADRESS
separatorMAC = ':'
separatorIP = '.'



#Big Endian stores the most significant at the smallest adress in memory
#Little Endian stores the least significant at the smallest adress

frames = []

#Recursively individualize each packet

def getFrames(data):
    try:
        #GET lenght of frame and indivilualize the frame
        data.seek(lenghtOffSet,1)#.read(4) 
        lenght = int.from_bytes(data.read(4), "little")
        #Read frame using the lenght
        frame = data.read(lenght)
        #Check if frame is empty, in this case break the recursion
        if frame == b'':
            return frames
        #Append to Array and keep buffer    
        frames.append(frame)
        #Call recursion 
        return getFrames(data) 
    except:
        return frames
        #Except is caught only if EOF arrived

#----------------------------Extract Functions--------------------------------------#

#The below function is used to extract [Destination and Source] Mac Address
#It assumes you call it with the right amount of bytes to compose the Mac Address

def extractMac(data, isLittle=False):
        #Identity the OUI(Organizationally Unique Identifier) 
        OUI = [format(x, '02x') for x in bytearray(data[:3])]
        
        #Identity the UAD(Universally Administered Address) 
        UAD = [format(x, '02x') for x in bytearray(data[3:6])]
    
        _literalOUI = separatorMAC.join(OUI) 
        _literalUAD = separatorMAC.join(UAD)
        
        return _literalOUI + ':' + _literalUAD

def extractType(data):
        hexValue = data.hex()
        formatted = "0x{}".format(hexValue)
        return formatted


def extractIP(data, isLittle=False):
        ip  = [x for x in bytearray(data) if x != '\n']
        formatted = separatorIP.join(str(x) for x in ip)
        return formatted 

def extractProtocol(data, isLittle=False):
        protocol = int.from_bytes(data, 'little')
        return protocol
