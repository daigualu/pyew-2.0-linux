import re
        
searchChar = '([A-Za-z])'
startChar = '[\w<_\.<]'
searchIP = '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
searchEmail = '([\w+]@.+\..+)'
def showString(output,m):
    if len(output) <= 4:
        output = ''
        m = -1
        return

    if len(output) <= 16:
        if '@' in output:
            fetch = re.search(searchEmail,output)
            if fetch is None:
                output = ''
                m = -1
                return

        fetch = re.search(searchChar,output)
        if fetch is None:
            fetch = re.search(searchIP,output)
            if fetch is None:
                output = ''
                m = -1
                return

        #Filtering consecutive multiple characters
        count = 0
        b = False 
        weiyiArray=[]
        for i in output:
            if i not in weiyiArray:
                weiyiArray.append(i)
        for s in weiyiArray:               
            for val in output:
                if val == s:
                    count += 1
                    if count >= 5:
                        b = True
                        break
                else:                 
                    count = 0
            if b:
                output = ''
                m = -1
                break
            count = 0
        else:
            print '%04X    %s' % (m, output)
            output = ''
            m = -1
        weiyiArray[:] = []

    else:
        print '%04X    %s' % (m, output)
        output = ''
        m = -1

def checkString(pyew,doprint=True):
    """ Search strings in the current document """
    pyew.offset = 0
    pyew.seek(0)
    buf = pyew.buf + pyew.f.read()
    bufSize = len(buf)
    size = 0
    m = -1
    output = ''
    for i in range(0,len(buf)):
        size += 1
        if len(repr(buf[i])) == 3:
            fetch_starChar = re.search(startChar,buf[i])
            if fetch_starChar is None:
                if m == -1:
                    output = ''
                    continue
            #pdb.set_trace()
            if m == -1:
                m = i
            if '$' in buf[i]:
                output = ''
                m = -1
                continue

            output += buf[i]

            if size == bufSize:
                showString(output,m)
        else:                            
            showString(output,m)
            output = ''
            m = -1

#--------------------------------------------------------------------------------
def getOffsetFromVirtualAddr(pyew, va):
    if pyew.pe:
        ret = None
        try:
            ret = pyew.pe.get_offset_from_rva(va - pyew.pe.OPTIONAL_HEADER.ImageBase)
            if ret > pyew.maxsize:
                ret = None
        except:
            pass
        return ret
    
def extractMovMode(pyew, disLines):
    # extract string from 'mov eax, [offset]'
    searchMov = '(mov .+, \[?)(0x.+]?)'
    rList = []
    for line in disLines :
        result = re.search(searchMov,line)
        if result:
            if 'byte' in result.group():
                continue
            address = line.split(' ')[0]
            x = result.group(2).strip()
            data = x.strip(']')
            offset = getOffsetFromVirtualAddr(pyew, int(data,16))
            if offset :
                output = pyew.pe.get_string_at_rva(offset)
                if output:
                    output = output.strip()
                if output:
                    rList.append( [address , output ])
    return rList

def extractPushMode(pyew, disLines):
    # extract string from 'push [offset]'
    searchPush = '(push 0x.+)'
    rList = []
    for line in disLines :
        result = re.search(searchPush , line)
        if result:
            address = line.split(' ')[0]
            key = result.group(1)
            data = key.split(' ')[1]
            offset = getOffsetFromVirtualAddr(pyew, int(data,16))
            if offset :
                output = pyew.pe.get_string_at_rva(offset)
                if output:
                    output = output.strip()
                if output:
                    rList.append( [address , output ])
    return rList

def extractLeaMode(pyew, disLines):
    # extract string from 'lea eax, [offset]'
    searchLea = '(lea .+\[0x.+\])'
    rList = []
    address = ''
    for line in disLines :
        result = re.search(searchLea,line)
        if result:
            address = line.split(' ')[0]
            key = result.group(1)
            data = key.split(' ')[2]
            data = data.strip('[')
            data = data.strip(']')
            offset = getOffsetFromVirtualAddr(pyew, int(data,16))
            if offset :
                output = pyew.pe.get_string_at_rva(offset)
                if output:
                    output = output.strip()
                if output:
                    rList.append( [address , output ])
        break
    return rList

def referenceString(pyew,doprint=True):
    """ search reference strings in disassemble """
    if not pyew.pe : return

    length = 0
    offset = 0
    #executeChar = 0b1100000000000000000000000100000
    executeChar = 0x60000020
    for section in pyew.pe.sections:
        #Only check string from executable section..
        if(section.Characteristics & executeChar) == executeChar:           
            offset = section.PointerToRawData
            length = section.SizeOfRawData
            break
    else:
        return

    buf = pyew.getBuffer()
    if pyew.maxsize - offset < length:
        length = pyew.maxsize - offset
    MaxLines = 1024 * 1024
    disLines = pyew.disassemble(buf[offset:offset + length], baseoffset=offset, lines=MaxLines).lower().split('\n')

    # fix disassembled lines with comment
    newDisLines = []
    for line in disLines :
        pos = line.find(';')
        if pos != -1:
            line = line[:pos-1]
        newDisLines.append(line)
    disLines = newDisLines

    rList = extractMovMode(pyew, disLines )
    rList += extractPushMode(pyew, disLines)
    rList += extractLeaMode(pyew, disLines)
    rList.sort()
    for item in rList :
        print item [0], item[1]

functions = {"strings":checkString, "rstrings":referenceString}


