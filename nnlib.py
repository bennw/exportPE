from __future__ import division
from capstone import *
import collections
from datetime import datetime
import hashlib
import json
import math
import numpy as np
import os
from os.path import isfile, join
import pefile
import pickle
import pymysql
from scipy import misc
from shutil import copyfile
import subprocess
import sys
import time

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 

"""
getDump<X>: gets filename/sample statistics from a data dump collection
Dumps are identified by their ID (arg: dumpID) and the model/option (arg: option).

Args:
    dumpDir: directory containing dump files
    dumpID, option: see method description
    number: fetches the nth dump file

Returns:
    <X>=file: path to dump file
    <X>=stats: class weight for positive samples
"""
def getDumpFile(dumpDir, dumpID, option, number):
    return join(dumpDir, 'data-' + dumpID + '-' + option + '-' + str(number) + '.pickle')

def getDumpStats(dumpDir, dumpID, option):
    (n,n0,n1)=(0,0,0)
    while True:
        try:
            n += 1
            dumpFile = getDumpFile(dumpDir, dumpID, option, n)
            with open(dumpFile, "rb") as f:
                (x, y) = pickle.load(f)
                n0 += y.count(0)
                n1 += y.count(1)
        except (OSError, IOError) as e:
            break
    print("Negatives: " + str(n0))
    print("Positives: " + str(n1))
    print("Percentage positive: " + str(makePercentage(n1/(n0+n1))) + "%")
    print("Class weight: " + str(n0/n1))
    return math.floor(n0/n1)

"""
makePercentage: example use - for input probability p=0.12345, dp=2, 
returns 12.34 (p is rounded down)

Args:
    p: input probability (usually in range 0 <= p <= 1)
    dp: number of decimal places for percentage. Expected to be non-negative integer.

Returns:
    XX.XX (see method description)
"""
def makePercentage(p, dp=2):
    m = 10 ** dp
    return math.floor(p*100*m)/m

"""
readFromFile: returns bytes from file

Args:
    file: binary file

Returns:
    data: bytes
"""
def readFromFile(file, options='rb'):
    fd = open(file, options)
    data = fd.read()
    fd.close()
    return data 

def readFromFileEX(file, options='rb', start=0, length=0, readFromBack=False):
    if readFromBack:
        s=2
    else:
        s=0
    fd = open(file, options)
    fd.seek(start, s)
    data = fd.read(length)
    fd.close()
    return data 

"""
getCodeSectionFromFile: takes in a PE file (arg: file), and finds the address and length of the code section

Args:
    file: PE file
Returns:
    text_start: pointer (address) to start of section. -1 if section not found  / invalid input file.
    text_length: length of section. -1 if section not found / invalid input file.
    entry_offset: pointer (address) to entry point. -1 if section not found / invalid input file.
"""
def getCodeSectionFromFile(pe_file):
    sectionName = [b'.text', b'UPX0', b'CODE', b'RT_CODE', b'.itext', b'Exe']
    pe = pefile.PE(pe_file)
    entry_virtual = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        for sName in sectionName:
            if section.Name[0:len(sName)] == sName:
                text_start = section.PointerToRawData
                text_length = section.Misc_VirtualSize
                text_start_virtual = section.VirtualAddress
                entry_offset = entry_virtual-text_start_virtual + text_start
                return text_start, text_length, entry_offset
    return -1, -1, -1

"""
getArchitecture: takes in a PE file (arg: file), and finds the target architecture and mode

Args:
    file: PE file
Returns:
    ARCH, MODE: aliases defined in capstone library
"""
def getArchitecture(pe_file):
    pe = pefile.PE(pe_file)
    if pe.FILE_HEADER.Machine == 0x14c:
        return CS_ARCH_X86, CS_MODE_32
    elif pe.FILE_HEADER.Machine == 0x8664:
        return CS_ARCH_X86, CS_MODE_64
    elif pe.FILE_HEADER.Machine == 0x1c0:
        return CS_ARCH_ARM, CS_MODE_ARM
    elif pe.FILE_HEADER.Machine == 0x1c2 or pe.FILE_HEADER.Machine == 0x1c4:
        return CS_ARCH_ARM, CS_MODE_THUMB
    elif pe.FILE_HEADER.Machine == 0xAA64:
        return CS_ARCH_ARM64, CS_MODE_ARM
    else:
        print(pe_file + " has unrecognised bit mode " + hex(pe.FILE_HEADER.Machine))
    return CS_ARCH_X86, CS_MODE_32

"""
bytesToList: returns list of integers (range: 0-255) corresponding to an input byte list (arg: bytes)

Args:
    bytes: see method description
    startIndex: index of bytes[] to begin extracting integer list
    length/maxLen: number of bytes to extract from bytes[]
    offset: offset output integers by this value

Returns:
    result: resulting integer list. Maximum length of maxLen is guaranteed; no minimum length guarantees.
"""
def bytesToList(bytes, startIndex, maxLen, offset=1):
    result = [ i + offset for i in list(bytes[startIndex:startIndex+maxLen]) ]
    return result

"""
padList: e.g. if list=[1,2,3], outputLen=5 and padding='PAD',
result = [1,2,3,'PAD','PAD'] 

Args:
    list: input list to pad
    outputLen: length of output list
    padding: padding value

Returns:
    list: padded input list
"""
def padList(list, outputLen, padding):
    if outputLen-len(list) > 0:
        for i in range(outputLen-len(list)):
            list.append(padding)
    return list

"""
mapDictToList: e.g. if dict={'apple':2, 'cheese':3, 'pear':5, 'meat':1} and refList=['apple', 'pear', 'banana'],
result = [2, 5, 0, 4] (last element of result maps to "others" : items not in the refList)

Args:
    dict: dictionary to be mapped to a list
    refList: reference list

Returns:
    list: mapped list. Always one element longer than refList.
"""
def mapDictToList(dict, refList):
    l = [0] * (len(refList)+1)
    for k,v in dict.items():
        if k not in refList:
            l[len(refList)] += v
        else:
            l[refList.index(k)] = v
    return l

"""
printResultsAggregated: prints the confusion matrix, accuracy, precision and recall.

Args:
    predicted: list/array of one-hot predictions
    actual: list/array of one-hot actual labels
    threshold: prediction has range 0 <= prediction <= 1. Threshold divides this range into positive/negative.
"""
def printResultsAggregated(predicted, actual, threshold=0.5):
    TP, FP, FN, TN = (0,0,0,0) # FP: false alarm; FN: malware slipped through the cracks
    for i in range(len(actual)):
        p = predicted[i] > threshold
        t = p == actual[i]
        if t:
            if p:
                TP += 1
            else:
                TN += 1
        else:
            if p:
                FP += 1
            else:
                FN += 1
    print( "TP  \tFP  \tFN  \tTN"  )
    print( str(TP) + "\t" + str(FP) + "\t" + str(FN) + "\t" + str(TN) )
    if TP == 0:
        print( "No true positives. End of results." )
        return
    print( "Accuracy: " + str(makePercentage((TP+TN)/len(actual))) + "%" )
    print( "Precision: " + str(makePercentage((TP)/(TP+FP))) + "%" )
    print( "Recall: " + str(makePercentage((TP)/(TP+FN))) + "%" )
    print( "FP Rate: " + str(makePercentage((FP)/(FP+TN))) + "%" )

"""
getSQLFileFromDir: given a directory, returns the full path of the first .sql file inside

Args:
    directory: directory to search (search is non-recursive)
"""
def getSQLFileFromDir(directory):
    for file in os.listdir(directory):
        if isfile(join(directory, file)) and '.sql' in file:
            print("Found SQL dump: " + join(directory, file))
            return join(directory, file)
    return None

"""
Generic FileError exception.
To be raised when input file doesn't meet specifications.
"""

class FileError(Exception):
    def __init__(self, file, msg):
        self.file = file
        self.msg = msg










"""
Preprocessor class.
Handles preprocessing of input data (binary files).

options:
    b: bytes sequence from .text section
    o: _o_pcodes sequence derived from bytes from .text section
    h: bytes in PE _h_eader (more accurately, first 0x300 bytes)
    e: first 0x300 bytes in _e_ntry
    f: opcode frequency in .text section
    i: 2048-hashed import functions
"""
class Preprocessor:
    def __init__(self, xLength, refFileDict=None, segFile=None, copyDir=None, maxFileSize=1.5*(10**6), options='hef',
        DB_user="root", DB_pass="", DB_name="UAVDB2", DB_loaddata=True, DB_sqldir="./"):
        self.inputLength = {}
        self.refList = {}
        self.copyDir = copyDir
        i = 0
        for o in options:
            self.inputLength[o] = xLength[i]
            i += 1
        for o in 'fone':
            if o in options:
                fj = open(refFileDict[o], 'r')
                self.refList[o] = json.loads(fj.read())
                fj.close()
                if o == 'e':
                    self.opcodeDict = collections.defaultdict(int)
                    n = 1
                    for opcode in self.refList[o]:
                        self.opcodeDict[opcode] = n
                        n += 1
        if 's' in options:
            with open(segFile, "rb") as f:
                self.segList = pickle.load(f)
            self.inputLength['s'] = len(self.segList) + 1
        self.loadDB(DB_sqldir, DB_loaddata, DB_user, DB_pass, DB_name)
        self.maxFileSize = maxFileSize       # files above maxFileSize will be auto-excluded
        self.options = options       # see class description

    def __del__(self):
        self.cursor.close()
        self.cxn.close()

    """
    loadDB: connects to DB, and loads data from SQL dump if bLoadData is True

    Args:
        sql_dir: directory containing .sql dump file
        bLoadData: see method description
        DB_user, DB_pass: login credentials
        DB_name: name of database to use
    """
    def loadDB(self, sql_dir, bLoadData, DB_user, DB_pass, DB_name):
        if bLoadData:
            connect_db = None
        else:
            connect_db = DB_name
        self.cxn = pymysql.connect(user=DB_user, password=DB_pass, database=connect_db,
                          charset='utf8mb4',
                          cursorclass=pymysql.cursors.DictCursor)
        self.cursor = self.cxn.cursor()
        if not bLoadData:
            return
        sqlPath = getSQLFileFromDir(sql_dir)
        if sqlPath is None:
            raise FileError("", "SQL dump not found")
        self.cursor.execute("CREATE DATABASE IF NOT EXISTS " + DB_name)
        self.cursor.execute("USE " + DB_name)
        print("Reading from dump...")
        sqlFile = readFromFile(sqlPath, 'r')
        sqlCommands = sqlFile.split(';')
        for command in sqlCommands:
            try:
                if command.strip() != '':
                    self.cursor.execute(command)
            except IOError as e:
                print(str(e.errno) + ": " + str(e))
        print("Dump read successful.")
        return

    """
    getLabelFromDB: given input filename (arg: file), queries database pointed at by MySQLCursor (arg: cursor)
    for the IsVirus label

    Args:
        file: see method description
        cursor: see method description

    Returns:
        label: bool indicating whether file is a virus
    """
    def getLabelFromDB(self, file):
        query = "SELECT FileSize, IsVirus FROM Application WHERE FileHash=%s"
        self.cursor.execute(query, (file[:64],))
        result = self.cursor.fetchone()
        if result is None:
            raise FileError(file, "DB entry not found")
        if result['FileSize'] > self.maxFileSize:
            raise FileError(file, "File size too large")
        if result['IsVirus'] is None:
            raise FileError(file, "File label (isVirus classification) unknown")
        return result['IsVirus']

    """
    getHashedImportListFromFile: takes in a PE file (arg: file), retrieving DLL imports.
    Import function names go through a size-2048 hash.
    Returns a size-2048 list of binary values corresponding to whether the PE file has import(s) with that hash.
    i.e. if PE file imports function "malloc", which has a hash value of 1337 (decimal), then result[1337] = 1
         whereas if no import function has hash value 1338, then result[1338] = 0

    Args:
        file: PE file
    Returns:
        result: see method description
    """
    def getHashedImportListFromFile(self, file):
        result = [0]*self.inputLength['i']
        try:
            pe = pefile.PE(file)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for fxn in entry.imports:
                    if fxn.name is not None:
                        hashfull = hashlib.md5(fxn.name).hexdigest()
                        hashresult = int(hashfull[10:13],16) % self.inputLength['i']
                        result[hashresult] = 1
        except AttributeError:
            # print(file + " has no import tables.")
            return result
        return result

    """
    getOpcodeFreqList: constructs histogram of opcodes from bytes, in the form of a list (freq_list).
    This list has indices mapped to the reference list (i.e. opcode refList[n] has frequency freq_list[n]);
    The last element of freq_list counts the frequency of opcodes not in refList.

    Args:
        bytes: sequence/list of bytes to be counted
        startIndex: start index of bytes[] to be counted
        length: number of bytes to be counted

    Returns:
        freq_list: see method description
    """
    def getOpcodeFreqList(self, bytes, startIndex, length):
        freq_dict = collections.defaultdict(int)
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.skipdata = True
        for i in md.disasm(bytes[startIndex:startIndex+length], startIndex):
            freq_dict[i.mnemonic] += 1
        freq_list = mapDictToList(freq_dict, self.refList['f'])
        return freq_list

    def getSegCountList(self, file):
        freq_dict = collections.defaultdict(int)
        cmd = subprocess.run(["objdump", "-D", file], stdout=subprocess.PIPE)
        if cmd.returncode != 0:
            raise FileError(file, "objdump throws exception")
        asm = cmd.stdout.split(b'\nDisassembly of section ')
        bDiscardedFirstSection = False
        for section in asm:
            if not bDiscardedFirstSection:
                bDiscardedFirstSection = True
                continue
            name = section.split(b':')[0]
            while len(name) < 8:
                name += b'\x00'
            freq_dict[name] = section.count(b"\n") - 2
            # print(str(name) + ": length " + str(section.count(b"\n") - 2))
        freq_list = mapDictToList(freq_dict, self.segList)
        return freq_list   

    """
    getOpcodeList: constructs histogram of opcodes from bytes, in the form of a list (freq_list).
    This list has indices mapped to the reference list (i.e. opcode refList[n] has frequency freq_list[n]);
    The last element of freq_list counts the frequency of opcodes not in refList.

    Args:
        bytes: sequence/list of bytes to be counted
        startIndex: start index of bytes[] to be counted
        length: number of bytes to be counted

    Returns:
        freq_list: see method description
    """
    def getOpcodeList(self, bytes, mode, opcodeLength, startIndex=0):
        result = [0] * opcodeLength
        md = Cs(mode[0], mode[1])
        md.skipdata = True
        n = 0
        for i in md.disasm(bytes[startIndex:], 0):
            result[n] = self.opcodeDict[i.mnemonic]
            n += 1
            if n >= opcodeLength:
                break
        return result   

    """
    getNgramFreqListEX: generates a list wherein each element corresponds to an n-gram as given in the ngramList.
    Element=0 indicates the ngram is absent in the current file, element=1 indicates presence.

    Args:
        file: binary file path
        mode: 2-tuple, gives the architecture (e.g. x86) and mode of the file (e.g. 32-bit)
        ngramList: see method description
        codeStart: starting offset
        codeLength: length of code section
        maxLength: maximum number of bytes to read
    Returns:
        result: see method description
    """
    def getNgramFreqListEX(self, file, mode, ngramList, outputLength, codeStart, codeLength, maxLength=100000):
        freq_dict = collections.defaultdict(int)
        cmpFactor = math.ceil( len(ngramList) / outputLength )
        result = [0] * outputLength
        bytes = readFromFileEX(file, start=codeStart, length=min(maxLength,codeLength))
        md = Cs(mode[0], mode[1])
        md.skipdata = True
        opcodes = []
        for i in md.disasm(bytes, 0):
            opcodes.append(i.mnemonic)
            if len(opcodes) >= 2:
                ngram = tuple(opcodes[-2:])
                freq_dict[ngram] += 1
            if len(opcodes) >= 3:
                ngram = tuple(opcodes[-3:])
                freq_dict[ngram] += 1
            if len(opcodes) >= 4:
                ngram = tuple(opcodes[-4:])
                freq_dict[ngram] += 1
        i = 0
        # for opcode in ngramList:
        #     if freq_dict[tuple(opcode)] == 1:
        #         result[int(math.floor(i/cmpFactor))] += 1/cmpFactor
            # i += 1
        for opcode in ngramList:
            if freq_dict[tuple(opcode)] > 0:
                result[i] = freq_dict[tuple(opcode)]
                i += 1
        return result

    """
    OBSOLETE - processing time is too long
    getAsciiStringBytes: takes in a list of bytes (arg: bytes), producing a concatenation of all
    ASCII substrings satisfying minimum length (arg: minStrLen). Each ASCII character then maps to
    an integer >= 256. The returned list is the list of these integers, truncated/padded to the
    required output length (arg: outputLen).

    Args:
        bytes: see method description
        outputLen: see method description
        minStrLen: see method description
    Returns:
        result: see method description. Integer 351 is the padding character.
    def getAsciiStringBytes(self, bytes, outputLen, minStrLen=6):
        result = []
        tmp = []
        asciiRange = range(32, 127)
        for j in list(bytes[74:]): # 74: byte after "This program cannot be run in DOS mode" text
            if int(j.encode('hex'), 16) in asciiRange:
                # c-c-combo!
                tmp.append( int(j.encode('hex'), 16) + 256-32 ) # ASCII char 32 maps to int(256)
            else:
                # womp womp
                if len(tmp) >= minStrLen:
                    result.extend( tmp )
                    if len(result) >= outputLen:
                        tmp = []
                        break
                tmp = []
        if len(tmp) >= minStrLen:
            result.extend( tmp )
        if len(result) < outputLen:
            prepend = [256+127-32]*(outputLen-len(result))
            result.extend(prepend)
        return result[:outputLen]
    """


    """
    getDataFromFile: converts input binary file to tensorflow-friendly x-data

    Args:
        filefullpath: full path of binary 
        data: bytes of binary file
    Returns:
        [o]: list of opcodes from code section converted to integers
        [f]: normalised opcode histogram from code section (see method getOpcodeFreqList)
        [h]: first 0x300 bytes converted to integers
        [e]: first 0x300 bytes starting from entry address
        [i]: list of 2048 binary elements indicating presence of hashed import function
    """
    def getDataFromFile(self, filefullpath):
        tmp = {}
        data = readFromFileEX(filefullpath, start=0, length=768)
        if not b'MZ' == data[:2]:
            raise FileError(filefullpath, "Not a valid PE file")
        if not any(b'PE' == data[i:i+2] for i in range(len(data) - 1)):
            raise FileError(filefullpath, "Not a valid PE file")
        for o in self.options:
            if o == 'h':
                data = readFromFileEX(filefullpath, start=0, length=self.inputLength['h'])
                data = bytesToList(data, 0, self.inputLength['h'])
                tmp[o] = padList( data , self.inputLength['h'], 0 )
            elif o == 'b':
                head = readFromFileEX(filefullpath, start=0, length=self.inputLength['b']//2)
                head = bytesToList(head, 0, self.inputLength['b']//2)
                tail = readFromFileEX(filefullpath, start=-self.inputLength['b']//2, length=self.inputLength['b']//2, readFromBack=True)
                tail = bytesToList(tail, 0, self.inputLength['b']//2)
                head.extend(tail)
                tmp[o] = head
            elif o == 'e':
                text_start, text_len, entry_addr = getCodeSectionFromFile(filefullpath)
                if text_start == -1:
                    raise FileError(filefullpath, "Not a valid PE file")
                if entry_addr < -1: # virtual entry addr missing for some reason. Use start of code section instead
                    entry_addr = text_start
                entry_len = text_len - (entry_addr-text_start)
                if entry_len <= 500:
                    data = readFromFileEX(filefullpath, start=text_start, length=text_len)
                else:
                    data = readFromFileEX(filefullpath, start=entry_addr, length=entry_len)
                mode = getArchitecture(filefullpath)
                result = self.getOpcodeList(data, mode, self.inputLength['e'])
                tmp[o] = padList( list(result) , self.inputLength['e'], 0 )
            elif o in 'no':
                text_start, text_length, x = getCodeSectionFromFile(filefullpath)
                if text_start == -1:
                    raise FileError(filefullpath, "Not a valid PE file")
                mode = getArchitecture(filefullpath)
                freq = self.getNgramFreqListEX(filefullpath, mode, self.refList[o], self.inputLength[o], text_start, text_length)
                if sum(freq) == 0:
                    raise FileError("", "No opcodes detected in file")
                tmp[o] = freq
                # tmp[o] = [float(i)/max(freq) for i in freq]
            elif o == 'f':
                data = readFromFile(filefullpath)
                text_start, text_length, x = getCodeSectionFromFile(filefullpath)
                if text_start == -1:
                    raise FileError(filefullpath, "Not a valid PE file")
                freq = self.getOpcodeFreqList(data, text_start, text_length)
                if sum(freq_list) == 0:
                    raise FileError("", "No opcodes detected in file")
                tmp[o] = [float(i)/sum(freq) for i in freq] # normalise before returning as output
            # elif o == 'i':
            #     tmp[o] = self.getHashedImportListFromFile(filefullpath)
            elif o == 'i':
                data = readFromFile(filefullpath)
                # reshape data to 2d with zero padding at end
                # normalising it to [0,1] range
                # finally resizing it to 256x256 elements
                nBytes = len(data)
                nSide = int(math.ceil(math.sqrt(nBytes)))
                data = padList( list(data) , nSide*nSide, 0 )
                data = np.reshape(data, (nSide,nSide))
                tmp[o] = misc.imresize(data, (256, 256, 1))
            elif o == 's':
                tmp[o] = self.getSegCountList(filefullpath)
                # tmp[o] = [i/8. for i in freq] # normalise; entropy ranges from 0 to 8
        return tmp

    '''
    generateDataWithPartition: a subset of the input directory (arg: filedir) is automatically partitioned
    Specifically, the first n/2 benign and malicious files (arg n: partitionSize) will be partitioned

    Args:
        filedir: see method description
        partitionSize: see method description

    Returns:
        x: inputs, in dictionary format (indexed by character corresponding to option)
        y: labels
        xp: partitioned inputs, in dictionary format
        yp: partitioned labels
    '''
    def generateDataWithPartition(self, filedir, partitionSize=0, maxFiles=-1):
        y, yp = ([] for i in range(2))
        x, xp = ({} for i in range(2))
        n0 = 0
        n1 = 0
        for o in self.options:
            x[o] = []
            xp[o] = []
        for d in filedir:
            for root, subfolders, files in os.walk(d):
                # subfolders.sort()
                files.sort()
                for file in files:
                    exe_path = join( root, file )
                    try:
                        label = self.getLabelFromDB(file)
                        tmp = self.getDataFromFile(exe_path)
                        if __debug__ and True:
                            if (n0+n1) % 1000 == 0:
                                print("File #" + str(n0+n1))
                        isPartitioned = False
                        if y == 1:
                            n1 += 1
                            if n1 <= partitionSize/2:
                                isPartitioned = True
                        else:
                            n0 += 1
                            if n0 <= partitionSize/2:
                                isPartitioned = True
                        if isPartitioned:
                            for o in self.options:
                                xp[o].append( tmp[o] )
                            yp.append(label)
                        else:
                            for o in self.options:
                                x[o].append( tmp[o] )
                            y.append(label)
                        if maxFiles != -1 and (n0+n1) >= maxFiles:
                            break
                    except IOError as e:
                        print("Could not read file " + exe_path)
                    except CsError as e:
                        print("CsError: %s" %e)
                    except FileError as e:
                        print("Error in file " + e.file + ": " + e.msg)
                    except TypeError as e:
                        print("TypeError for file " + file + ": " + str(e))
                    except pefile.PEFormatError as e:
                        print(file + " is not a valid PE file.")
                if maxFiles != -1 and (n0+n1) >= maxFiles:
                    break
        print("Partition size: " + str(len(yp)))
        print("h size: " + str(len(x['h'])))
        print("Negative sample count: " + str(n0))
        print("Positive sample count: " + str(n1))
        return x, y, xp, yp

    '''
    dumpData: the input directory (arg: filedir) contains data files, which will be preprocessed and
    dumped to .pickle files in the dump directory (arg: dumpDir). Each pickle file has up to (arg: dumpSize) files
    and up to a total of (arg: maxFiles) files will be processed.

    Args:
        dumpID: identifier for dataset being used
        (other args): see method description
    '''

    def dumpData(self, fileDir, dumpDir, dumpID, dumpSize=20000, maxFiles=-1):
        y = []
        x = {}
        n0 = 0
        n1 = 0
        nDump = dumpSize
        skipAhead = True
        if isfile(getDumpFile(dumpDir, dumpID, self.options[0:1], 1)):
            return
        n0old = 0
        n1old = 0
        for o in self.options:
            x[o] = []
        for d in fileDir:
            for root, subfolders, files in os.walk(d):
                # subfolders.sort()
                files.sort(reverse=True)
                for file in files:
                    exe_path = join( root, file )
                    try:
                        ### HACKY BEGIN
                        # if skipAhead:
                        #     if file != "AC02588AD9DF13DD04FD0EDA92F9F23514FF797051694BE82F4D13E05B16D9C5_9801":
                        #         continue
                        #     else:
                        #         skipAhead = False
                        #         print("Continuing from last dumpload...")
                        #         (n0, n0old, n1, n1old, nDump) = (39082, 39082, 918, 918, 60000)
                        ### HACKY END
                        label = self.getLabelFromDB(file)
                        tmp = self.getDataFromFile(exe_path)
                        if __debug__ and True:
                            if (n0+n1) % 2000 == 0:
                                print(str(time.ctime()) + ": File #" + str(n0+n1))
                        if label == 1:
                            n1 += 1
                        else:
                            n0 += 1
                        for o in self.options:
                            x[o].append( tmp[o] )
                        y.append(label)
                        if (n0+n1) >= nDump:
                            nDump += dumpSize
                            for o in self.options:
                                dumpFile = getDumpFile(dumpDir, dumpID, o, str((n0+n1)//dumpSize))
                                with open(dumpFile, "wb") as f:
                                    pickle.dump((x[o], y), f)
                            y = []
                            x = {}
                            for o in self.options:
                                x[o] = []
                            print(time.ctime())
                            print("Dump #" + str((n0+n1)//dumpSize))
                            print("Negative sample count: " + str(n0-n0old))
                            print("Positive sample count: " + str(n1-n1old))
                            print("---------")
                            (n0old, n1old) = (n0, n1)
                        if maxFiles != -1 and (n0+n1) >= maxFiles:
                            break
                    # except IOError as e:
                    #     print("IOError with " + exe_path + ":" + str(e))
                    # except CsError as e:
                    #     print("CsError: %s" %e)
                    # except FileError as e:
                    #     print("Error in file " + e.file + ": " + e.msg)
                    # except TypeError as e:
                    #     print("TypeError for file " + file + ": " + str(e))
                    # except pefile.PEFormatError as e:
                    #     print(file + " is not a valid PE file.")
                    except (IOError, CsError, FileError, TypeError, pefile.PEFormatError) as e:
                        pass
                if maxFiles != -1 and (n0+n1) >= maxFiles:
                    break
        print("Total negative sample count: " + str(n0))
        print("Total positive sample count: " + str(n1))
        return