PyReAsm - A Python reassembler
==============================

There are a few tools for executing assembly code from Python:

   * CorePy
   * PyAsm

But these two projects focus on actually generating assembly code from
Python, presumably for performance.

This project is focus on debugging and safety. In CTFs you sometimes
something disassemble a piece of code and you need to run it seperately from
the rest.  This module allows you to run assembly code from within Python in
a totally safe environment. Hence: re-assember.

    >>> import ctypes
    >>> import pyreasm

    >>> state = pyreasm.ReAsm("xchg rax, rbx", rax=1, rbx=2).run()
    >>> print "rax=%d rbx=%d" % (state.rax, state.rbx)
    rax=2 rbx=1

Here the given assembly code is assembled into a seperated program and run
and the results transferred back.

You can also define variables which can also copied between the Python and
the assembly program.  For example:

    >>> class Test(ctypes.Structure):
    >>>     _fields_ = [('int_var', ctypes.c_long)]

    >>> state = pyreasm.ReAsm("xchg rax, int_var", Test, int_var=1, rax=2).run()
    >>> print "int_var=%d rax=%d" % (state.int_var, state.rax)
    int_var=2 rax=1

Since the code is run in a separate process, you don't have to worry about crashes.

    >>> try:
    >>>     state = pyreasm.ReAsm("xor rax, rax\ncall rax").run()
    >>> except Exception, e:
    >>>     print e
    Signal SIGSEGV

