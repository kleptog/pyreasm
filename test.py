import ctypes
import pyreasm

# Test involving only registers
state = pyreasm.ReAsm("xchg rax, rbx", rax=1, rbx=2).run()
print "rax=%d rbx=%d" % (state.rax, state.rbx)
assert state.rax == 2 and state.rbx == 1

# Testing involving a variable
class Test(ctypes.Structure):
    _fields_ = [('int_var', ctypes.c_long)]

state = pyreasm.ReAsm("xchg rax, int_var", Test, int_var=1, rax=2).run()
print "int_var=%d rax=%d" % (state.int_var, state.rax)
assert state.int_var == 2 and state.rax == 1

try:
    state = pyreasm.ReAsm("xor rax, rax\ncall rax").run()
except Exception, e:
    print e
