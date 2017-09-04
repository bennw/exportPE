import nnlib
import numpy as np
import math
import os
import pickle
import sys

# file params
fpOpcodeJson = "opcode.json"
fpSegPickle = "seg.pickle"
fpDataDir = [ "/home/ben/Documents/extractPE/data-nano" ] # path to folders/hard disk containing samples
fpDumpDir = "/home/ben/Documents/extractPE" # .pickle data files will be saved/loaded here
fpSQLDir = "/home/ben/Documents/bank"       # directory of .sql file
fpDataID = "Sep15"                          # identifies dataset being used
fpDBName = "Sep15"
fpOptions = 'he' # e.g. fpOptions='h' will use first 768 bytes from PE header
                   # fpOptions='e' will use first 768 bytes from code section entry point
                   # fpOptions='he' will use both of the above
                   # for full list of options, see nnlib.py
xLength = [768, 768] # expected input size of each option


print("Saving .pickle data with options: " + fpOptions)
pp = nnlib.Preprocessor(xLength, opcodeFile=fpOpcodeJson, segFile=fpSegPickle, options=fpOptions, 
    DB_name=fpDBName, DB_sqldir=fpSQLDir, DB_loaddata=False)
pp.dumpData(fpDataDir, fpDumpDir, fpDataID)

for o in fpOptions:
    n = 1
    print("Loading data file " + str(n) + " with option: " + o)
    with open(nnlib.getDumpFile(fpDumpDir, fpDataID, o, n), "rb") as f:
        (x, y) = pickle.load(f)