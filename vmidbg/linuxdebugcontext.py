import logging
import re

from libvmi import AccessContext, TranslateMechanism, X86Reg, Registers
from libvmi.event import RegEvent, RegAccess

from vmidbg.abstractdebugcontext import AbstractDebugContext
from vmidbg.gdbstub import GDBPacket, GDBSignal

from enum import Enum


class LinuxTaskState(Enum):
    RUNNING = 0
    INTERRUPTIBLE = 1
    UNINTERRUPTIBLE = 2
    STOPPED = 4
    TRACED = 8

    def __str__(self):
        return self.value


class LinuxTaskDescriptor:

    def __init__(self, desc_addr, vmi):
        self.vmi = vmi
        self.addr = desc_addr
        self.mm = self.vmi.read_addr_va(self.addr + self.vmi.get_offset('linux_mm'), 0)
        self.name = self.vmi.read_str_va(self.addr + self.vmi.get_offset('linux_name'), 0)
        self.id = self.vmi.read_32_va(self.addr + self.vmi.get_offset('linux_pid'), 0)
        self.stack = self.vmi.read_addr_va(self.addr + self.vmi.get_kernel_struct_offset('task_struct', 'stack'),0)
        self.pt_regs = self.stack + 16384 - 8 - self.vmi.get_kernel_struct_offset('pt_regs', 'ss')
        self.tgid = self.vmi.read_32_va(self.addr + self.vmi.get_kernel_struct_offset('task_struct','tgid'),0)

        # task_struct->mm->pgd (Page global directory)
        if self.mm:
            dtb_addr = self.vmi.read_addr_va(self.mm + self.vmi.get_offset('linux_pgd'), 0)
            # convert dtb into a machine address
            self.dtb = self.vmi.translate_kv2p(dtb_addr)
        else:
            # kernel thread
            self.dtb = 0

        task_addr = self.vmi.read_addr_va(self.addr + self.vmi.get_offset('linux_tasks'), 0)
        self.next_desc = task_addr - self.vmi.get_offset('linux_tasks')

    def is_alive(self):
        return True

    def get_state(self):
        return self.vmi.read_32_va(self.addr + self.vmi.get_kernel_struct_offset('task_struct','state'), 0)

    def is_running(self):
        return self.get_state() == LinuxTaskState.RUNNING

    def get_next_thread(self):
        thread_group_offset = self.vmi.get_kernel_struct_offset('task_struct','thread_group')
        return self.vmi.read_addr_va(self.addr + thread_group_offset, 0) - thread_group_offset

    def get_running_thread(self):
        return [thread for thread in self.list_threads() if thread.is_running()][0]

    def read_registers(self,vcpu=0):
        if self.is_running():
            return self.vmi.get_vcpuregs(vcpu)
        else:
            width = self.vmi.get_address_width()

            regs_gpr = {
                X86Reg.RAX : 'ax', X86Reg.RBX : 'bx', X86Reg.RCX : 'cx', X86Reg.RDX : 'dx',
                X86Reg.RSI : 'si', X86Reg.RDI : 'di', X86Reg.RBP : 'bp', X86Reg.RSP : 'sp',
            }

            regs_64 = {
                X86Reg.R8 : 'r8', X86Reg.R9 : 'r9', X86Reg.R10 : 'r10', X86Reg.R11 : 'r11',
                X86Reg.R12 : 'r12', X86Reg.R13 : 'r13', X86Reg.R14 : 'r14', X86Reg.R15 : 'r15'
            }

            regs_control = { X86Reg.RIP : 'ip', X86Reg.RFLAGS : 'flags'}

            if width == 4:
                regs = Registers()

                regs_gpr.update(regs_control)

                for register,alias in regs_gpr.items():
                    reg_offset = self.vmi.get_kernel_struct_offset('pt_regs', alias)
                    reg_value = self.vmi.read_addr_va(self.pt_regs + reg_offset , 0)
                    regs[register] = reg_value
                return regs
            else:
                regs = Registers()

                regs_gpr.update(regs_64)
                regs_gpr.update(regs_control)

                for register,alias in regs_gpr.items():
                    reg_offset = self.vmi.get_kernel_struct_offset('pt_regs', alias)
                    reg_value = self.vmi.read_addr_va(self.pt_regs + reg_offset , 0)
                    regs[register] = reg_value

                return regs

    def read_segments(self):
        segs = []
        _segments = ['fs', 'gs']

        for seg in _segments:
            offset = self.vmi.get_kernel_struct_offset('thread_struct', seg)
            segment = self.vmi.read_addr_va(self.pt_regs + offset)
            segs.append(segment)

        return segs

    def __str__(self):
        return "[{}] {} @{}".format(self.id, self.name, hex(self.addr))


class LinuxDebugContext(AbstractDebugContext):

    def __init__(self, vmi, process):
        super().__init__(vmi)
        self.log = logging.getLogger(__class__.__name__)
        self.target_name = process
        self.target_desc = None
        self.threads = None

        # misc: print kernel base address
        self.log.info('kernel base: @%s', hex(self.vmi.translate_ksym2v('start_kernel')))

    def attach(self):
        # 1 - pause to get a consistent memory access
        self.vmi.pause_vm()
        # 2 - find our target name in process list
        # process name might include regex chars
        pattern = re.escape(self.target_name)
        found = [desc for desc in self.list_processes() if re.match(pattern, desc.name)]
        if not found:
            logging.debug('%s not found in process list:', self.target_name)
            for desc in self.list_processes():
                logging.debug(desc)
            raise RuntimeError('Could not find process')
        if len(found) > 1:
            logging.warning('Found %s processes matching "%s", picking the first match ([%s])',
                            len(found), self.target_name, found[0].id)
        self.target_desc = found[0]
        # 3 - check if kernel thread (not supported)
        if self.target_desc.mm == 0:
            raise RuntimeError('intercepting kernel threads is not supported')

        # 4 - set breakpoint on the running thread
        ip = self.get_thread().read_registers()[X86Reg.RIP]
        self.bpm.continue_until(ip)

    def detach(self):
        self.vmi.resume_vm()

    def get_dtb(self):
        return self.target_desc.dtb

    def check_dtb(self, dtb):
        return None

    def dtb_to_desc(self, dtb):
        for desc in self.list_processes():
            if desc.dtb == dtb:
                return desc
        raise RuntimeError('Could not find task descriptor for DTB {}'.format(hex(dtb)))

    def get_access_context(self, address):
        return AccessContext(TranslateMechanism.PROCESS_PID,
                             addr=address, pid=self.target_desc.id)

    def get_thread(self, tid=-1):
        threads = list(self.target_desc.list_threads())

        if tid == -1:
            # Main thread
            return threads[-1]

        return [thread for thread in threads if thread.id == tid][0]


    def list_threads(self):
        return self.target_desc.list_threads()

    def list_processes(self):
        head_desc = self.vmi.translate_ksym2v('init_task')
        desc_addr = head_desc

        while True:
            desc = LinuxTaskDescriptor(desc_addr, self.vmi)
            yield desc
            # read next address
            desc_addr = desc.next_desc
            if desc_addr == head_desc:
                break

    def cb_on_swbreak(self, vmi, event):
        cb_data = event.data

        # check if it's our targeted process
        dtb = event.cffi_event.x86_regs.cr3

        if dtb != self.get_dtb():
            desc = self.dtb_to_desc(dtb)
            self.log.debug('wrong process: %s', desc.name)
            # need to singlestep
            return True
        else:
            self.log.debug('hit !')
            # pause
            self.vmi.pause_vm()
            cb_data['stop_listen'].set()
            thread = self.get_current_running_thread()
            if not thread:
                tid = -1
            else:
                tid = thread.id
            # report swbreak stop to client
            cb_data['stub'].send_packet_noack(GDBPacket(b'T%.2xswbreak:;thread:%x;' %
                                              (GDBSignal.TRAP.value, tid)))
            # don't singlestep
            return False
