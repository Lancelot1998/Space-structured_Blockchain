import ctypes 
from ctypes import *   

import time

ll = ctypes.cdll.LoadLibrary
lib = ll("./lib.so")

input = bytes("DAG_structure_test.txt", "utf-8")
output = bytes("DAG_test.txt", "utf-8")

lib.test(500, input, output)

# lib.test(11, input, byteif len(result[i]) == 0:s("c.txt", "utf-8"))
#
# lib.test(11, input, bytes("d.txt", "utf-8"))

print('***finish***')

