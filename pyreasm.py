import re
from types import TypeType
from ctypes import Structure
import ctypes

from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.child import createChild
from ptrace.binding import ptrace_registers_t
from ptrace import syscall, debugger as ptrace_debugger

import subprocess

class ProgramState(object):
    def __init__(self, regs, data):
        self.regs = regs
        self.data = data

    def __getattr__(self, attr):
        if hasattr(self.regs, attr):
            return getattr(self.regs, attr)
        if hasattr(self.data, attr):
            return getattr(self.data, attr)
        raise AttributeError("%r has no attribute %r" % (self, attr))

    def dump(self):
        for reg, t in self.regs._fields_:
            print "%-3s %016x" % (reg, getattr(self.regs, reg))
        for field, t in self.data._fields_:
            print "%-8s %s" % (field, getattr(self.data, field))

class ReAsm(object):
    def __init__(self, *args, **kwargs):
        """ Initialise defaults based on arguments """
        self.code, self.data_type, self.data, self.regs = self._resolve_args(args, kwargs)

    def _resolve_args(self, args, kwargs):
        code = None
        data_type = None
        data = None
        regs = None

        for arg in args:
            if isinstance(arg, str):
                if code is not None:
                    raise ValueError("Multiple code arguments found")
                code = arg
            elif isinstance(arg, Structure):
                if data_type is not None:
                    raise ValueError("Multiple data type definitions found")
                data_type = type(arg)
                data = arg
            elif isinstance(arg, TypeType) and issubclass(arg, Structure):
                if data_type is not None:
                    raise ValueError("Multiple data type definitions found")
                data_type = arg
                data = arg()
            elif isinstance(arg, ptrace_registers_t):
                if regs is not None:
                    raise ValueError("Registers can only be supplied once")
                regs = arg
            else:
                raise ValueError("Unknown argument %r" % arg)

        for kw, val in kwargs.iteritems():
            if hasattr(ptrace_registers_t, kw):
                if regs is None:
                    regs = ptrace_registers_t()
                setattr(regs, kw, val)
            elif data is not None and hasattr(data, kw):
                setattr(data, kw, val)
            else:
                raise ValueError("Unknown keyword %r" % kw)

        return code, data_type, data, regs

    def _start_process(self, args, kwargs):
        code, data_type, data, regs = self._resolve_args(args, kwargs)
        if code is None:
            code = self.code
        if data_type is None:
            data_type = self.data_type
            data = self.data
        if regs is None:
            regs = self.regs

        if code is None:
            raise ValueError("No code to run")
        if regs is None:
            regs = ptrace_registers_t()

        prog = ReAsmProgram(code, data_type)
        return ReAsmProcess(prog, data, regs)

    def run(self, *args, **kwargs):
        return self._start_process(args, kwargs).run()

class ReAsmProgram(object):
    """ Represents a instance of code+data_type, which is compiled """

    SETUP = """
        .global _start
        .intel_syntax noprefix
    """

    SYSCALLS = {
        'SYSCALL_exit': [k for k,v in syscall.SYSCALL_NAMES.iteritems() if v == "exit"][0],
        'SYSCALL_pause': [k for k,v in syscall.SYSCALL_NAMES.iteritems() if v == "pause"][0],
        'SYSCALL_getpid': [k for k,v in syscall.SYSCALL_NAMES.iteritems() if v == "getpid"][0],
    }

    TRANSFER = """
    .align 16
    __transfer_area:
    .skip %d, 0
    """

    STARTUP = """
    .align 16
_start:
    movq rax, %(SYSCALL_pause)s
    syscall

    mov rax, [__transfer_area+%(REG_rax)s]
    mov rbx, [__transfer_area+%(REG_rbx)s]
    mov rcx, [__transfer_area+%(REG_rcx)s]
    mov rdx, [__transfer_area+%(REG_rdx)s]
    mov rsi, [__transfer_area+%(REG_rsi)s]
    mov rdi, [__transfer_area+%(REG_rdi)s]
#    mov rsp, [__transfer_area+%(REG_rsp)s]
#    mov rbp, [__transfer_area+%(REG_rbp)s]
    mov r8,  [__transfer_area+%(REG_r8)s]
    mov r9,  [__transfer_area+%(REG_r9)s]
    mov r10, [__transfer_area+%(REG_r10)s]
    mov r11, [__transfer_area+%(REG_r11)s]
    mov r12, [__transfer_area+%(REG_r12)s]
    mov r13, [__transfer_area+%(REG_r13)s]
    mov r14, [__transfer_area+%(REG_r14)s]
    mov r15, [__transfer_area+%(REG_r15)s]

    call main

    mov [__transfer_area+%(REG_rax)s], rax
    mov [__transfer_area+%(REG_rbx)s], rbx
    mov [__transfer_area+%(REG_rcx)s], rcx
    mov [__transfer_area+%(REG_rdx)s], rdx
    mov [__transfer_area+%(REG_rsi)s], rsi
    mov [__transfer_area+%(REG_rdi)s], rdi
    mov [__transfer_area+%(REG_rsp)s], rsp
    mov [__transfer_area+%(REG_rbp)s], rbp
    mov [__transfer_area+%(REG_r8)s], r8
    mov [__transfer_area+%(REG_r8)s], r9
    mov [__transfer_area+%(REG_r10)s], r10
    mov [__transfer_area+%(REG_r11)s], r11
    mov [__transfer_area+%(REG_r12)s], r12
    mov [__transfer_area+%(REG_r13)s], r13
    mov [__transfer_area+%(REG_r14)s], r14
    mov [__transfer_area+%(REG_r15)s], r15

# Wait for signal
    movq rax, %(SYSCALL_pause)s
    syscall

# Exit
    movq rax, %(SYSCALL_exit)s
    movq rdi, 0
    syscall
_loop1:
    jmp _loop1

    .align 16

# Mark the start of user code
_start_user_code:
main:

"""

    def __init__(self, code, data_type):
        self.code, self.data_type = code, data_type

        self.build(code, data_type)

    def _build_data(self, data_type):
        """ Create assembly for data segment """
        res = ".align 16\n__begin_data:\n"
        off = 0

        if data_type is not None:
            for name, _ in data_type._fields_:
                field = getattr(data_type, name)
                if field.offset > off:
                    res += "    .skip %s, 0\n" % (field.offset - off,)
                res += "%s:\n" % name
                off = field.offset
            if ctypes.sizeof(data_type) > off:
                res += "    .skip %s, 0\n" % (ctypes.sizeof(data_type)- off,)
        res += "__end_data:\n"

        return res

    def _clean_code(self, code):
        code = re.sub(r'(qword|dword|word|byte) \[', r'\1 ptr [', code)
        return code + "\n"

    def _verify_offsets(self, data_type):
        """ Verify bytes offsets in data segment and locate transfer area """
        self.data_start = None
        self.data_length = None
        self.transfer_start = None

        out = subprocess.check_output(["nm", "/tmp/test"])
        symbols = {}
        for line in out.splitlines():
            addr, _, name = line.split()
            symbols[name] = int(addr, 16)

        assert "__transfer_area" in symbols
        self.transfer_start = symbols['__transfer_area']
        self.transfer_length = ctypes.sizeof(ptrace_registers_t)

        if not data_type:
            return

        assert "__begin_data" in symbols
        assert "__end_data" in symbols

        for name, _ in data_type._fields_:
            assert getattr(data_type, name).offset == symbols[name] - symbols["__begin_data"]

        assert symbols['__end_data'] - symbols['__begin_data'] == ctypes.sizeof(data_type)

        self.data_start = symbols['__begin_data']
        self.data_length = symbols['__end_data'] - self.data_start

    def build(self, code, data_type):
        with open("/tmp/temp.s", "w") as f:
            f.write(self.SETUP)
            f.write(".data\n")
            f.write(self.TRANSFER % ctypes.sizeof(ptrace_registers_t))
            f.write(self._build_data(data_type))
            f.write(".text\n")
            args = dict( ("REG_%s" % name, getattr(ptrace_registers_t, name).offset) for name, type in ptrace_registers_t._fields_ )
            args.update(self.SYSCALLS)
            f.write(self.STARTUP % args)
            f.write(self._clean_code(code))
            f.write("\tretq\n")

        subprocess.check_call(["as", "--64", "-msyntax=intel", "/tmp/temp.s", "-o", "/tmp/test.o"])
        subprocess.check_call(["ld", "/tmp/test.o", "-o", "/tmp/test"])
        self._verify_offsets(data_type)

    def start(self):
        pid = createChild(["/tmp/test"], False)
        debugger = PtraceDebugger()
        debugger.addProcess(pid, True)
        debugger.enableSysgood()
        process = debugger[pid]
        process.syscall()
        e = process.waitEvent()
        assert isinstance(e, ptrace_debugger.ProcessSignal)

        return debugger, process

class ReAsmProcess(object):
    """ Represents a configured run """
    def __init__(self, prog, data, regs):
        self.prog = prog
        if data is None and self.prog.data_type is not None:
            data = self.prog.data_type()
        else:
            self.data = data
        self.regs = regs

    ### Pack/unpack transfer data/registers ###
    def _copy_data_to(self):
        """ Convert values of symbols to data block """
        if self.prog.data_type:
            buf = buffer(self.data)[:]
            self.process.writeBytes(self.prog.data_start, buf)

    def _copy_data_from(self):
        """ Convert data block to symbol values """
        if self.prog.data_type:
            buf = self.process.readBytes(self.prog.data_start, self.prog.data_length)
            self.data = self.prog.data_type.from_buffer_copy(buf)

    def _copy_regs_to(self):
        """ Copy regs values to program transfer area """
        buf = buffer(self.regs)[:]
        self.process.writeBytes(self.prog.transfer_start, buf)

    def _copy_regs_from(self):
        buf = self.process.readBytes(self.prog.transfer_start, self.prog.transfer_length)
        self.regs = ptrace_registers_t.from_buffer_copy(buf)

    def start(self):
        return self.prog.start()

    def run(self):
        debugger, process = self.start()
        self.process = process

        regs = process.getregs()
        assert regs.orig_rax == self.prog.SYSCALLS['SYSCALL_pause']
        process.setreg('orig_rax', self.prog.SYSCALLS['SYSCALL_getpid'])

        self._copy_data_to()
        self._copy_regs_to()

        try:
            while True:
                process.syscall()
                ev = process.waitEvent()
                if isinstance(ev, ptrace_debugger.ProcessSignal) and ev.signum != 5+128:
                    raise ev
                regs = process.getregs()
                if regs.orig_rax == 0x22:
                    if process.readBytes(process.getInstrPointer()-2, 2) == "\x0f\x05":  # SYSCALL
                        break
        finally:
            self._copy_data_from()
            self._copy_regs_from()

            state = ProgramState(self.regs, self.data)

            process.terminate()
        return state

    def trace(self):
        debugger, process = self._start_process()

        regs = process.getregs()
        assert regs.orig_rax == self.prog.SYSCALLS['SYSCALL_pause']
        process.setreg('orig_rax', self.prog.SYSCALLS['SYSCALL_getpid'])

        if data is None:
            data = self.data_type()
        data = self._pack_data(data)
        print repr(data)
        process.writeBytes(self.data_start, data)

        try:
            while True:
                process.singleStep()
                ev = process.waitEvent()
                if isinstance(ev, ptrace_debugger.ProcessSignal) and ev.signum != 5:
                    raise ev
                regs = process.getregs()
                print "rip %08X rax %08X rbx %08X rcx %08X rdx %08X rsp %08X rbp %08X" % (regs.rip, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsp, regs.rbp)
                if regs.rax == 0x22:
                    if process.readBytes(process.getInstrPointer(), 2) == "\x0f\x05":  # SYSCALL
                        break

                data = process.readBytes(self.data_start, self.data_length)
                state = ProgramState(regs, self._unpack_data(data))

                yield state
        finally:
            process.terminate()
