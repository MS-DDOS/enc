import time as t
import sys
import aux
from another import C as D

def double_this(x):
    return 2*x

if __name__ == "__main__":
    if len(sys.argv) == 2:
        val = sys.argv[1]
    else:
        print "No command line param specified, using 10 as default value"
        val = 10
    print "entry.py - module level function - result:", double_this(val)
    print "entry.py - time.time() system module call - result:",t.time()
    b = aux.B()
    d = D(20.1)
    print "aux.py - class instance - result: ", b.triple_this(val)
    print "another.py - aliased class import - result: ", d.ceiling_self()
