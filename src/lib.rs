extern crate libc;
extern crate posix_ipc as ipc;
#[macro_use] extern crate bitflags;
extern crate num;
#[macro_use] extern crate enum_primitive;
extern crate nix;

use std::ptr;
use std::default::Default;
use std::mem;
use num::FromPrimitive;
use nix::errno::errno;

#[cfg(target_arch = "x86_64")]
pub type Address = u64;
#[cfg(not(target_arch = "x86_64"))]
pub type Address = u32;

#[cfg(target_arch = "x86_64")]
pub type Word = u64;
#[cfg(not(target_arch = "x86_64"))]
pub type Word = u32;

#[derive(Debug, Copy, Clone)]
pub enum Request {
  TraceMe = 0,
  PeekText = 1,
  PeekData = 2,
  PeekUser = 3,
  PokeText = 4,
  PokeData = 5,
  PokeUser = 6,
  Continue = 7,
  Kill = 8,
  SingleStep = 9,
  GetRegs = 12,
  SetRegs = 13,
  Attach = 16,
  Detatch = 17,
  SetOptions = 0x4200,
  Seize = 0x4206
}

enum_from_primitive! {
    #[derive(Clone, Copy, Debug)]
    pub enum Event {
      Fork = 1,
      VFork = 2,
      Clone = 3,
      Exec = 4,
      VForkDone = 5,
      Exit = 6,
      Seccomp = 7,
      Stop = 128
    }
}

impl Event {
    pub fn from_wait_status(st: i32) -> Option<Event> {
        let e: Option<Event> = FromPrimitive::from_i32(((st >> 8) & !5) >> 8);
        return e;
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Registers {
  pub r15: Word,
  pub r14: Word,
  pub r13: Word,
  pub r12: Word,
  pub rbp: Word,
  pub rbx: Word,
  pub r11: Word,
  pub r10: Word,
  pub r9: Word,
  pub r8: Word,
  pub rax: Word,
  pub rcx: Word,
  pub rdx: Word,
  pub rsi: Word,
  pub rdi: Word,
  pub orig_rax: Word,
  pub rip: Word,
  pub cs: Word,
  pub eflags: Word,
  pub rsp: Word,
  pub ss: Word,
  pub fs_base: Word,
  pub gs_base: Word,
  pub ds: Word,
  pub es: Word,
  pub fs: Word,
  pub gs: Word
}

bitflags! {
  flags Options: u32 {
    const SYSGOOD = 1,
    const TRACEFORK = 1 << 1,
    const TRACEVFORK = 1 << 2,
    const TRACECLONE = 1 << 3,
    const TRACEEXEC = 1 << 4,
    const TRACEVFORKDONE = 1 << 5,
    const TRACEEXIT = 1 << 6,
    const TRACESECCOMP = 1 << 7,
    const EXITKILL = 1 << 20
  }
}

pub fn setoptions(pid: libc::pid_t, opts: Options) -> Result<libc::c_long, usize> {
    ptrace(Request::SetOptions, pid, ptr::null_mut(), opts.bits as *mut
    libc::c_void)
}

pub fn getregs(pid: libc::pid_t) -> Result<Registers, usize> {
  let mut buf: Registers = Default::default();
  let buf_mut: *mut Registers = &mut buf;

  ptrace(Request::GetRegs, pid, ptr::null_mut(), buf_mut as *mut libc::c_void).map(|_| buf)
}

pub fn setregs(pid: libc::pid_t, regs: &Registers) -> Result<libc::c_long, usize> {
    unsafe {
        let buf: *mut libc::c_void = mem::transmute(regs);
        ptrace(Request::SetRegs, pid, ptr::null_mut(), buf)
    }
}

pub fn seize(pid: libc::pid_t) -> Result<libc::c_long, usize> {
        ptrace(Request::Seize, pid, ptr::null_mut(), ptr::null_mut())
}

pub fn attach(pid: libc::pid_t) -> Result<libc::c_long, usize> {
    ptrace(Request::Attach, pid, ptr::null_mut(), ptr::null_mut())
}

pub fn release(pid: libc::pid_t, signal: ipc::signals::Signal) -> Result<libc::c_long, usize> {
    ptrace(Request::Detatch, pid, ptr::null_mut(), (signal as u32) as *mut libc::c_void)
}

pub fn cont(pid: libc::pid_t, signal: ipc::signals::Signal) -> Result<libc::c_long, usize> {
    ptrace(Request::Continue, pid, ptr::null_mut(), (signal as u32) as *mut libc::c_void)
}

pub fn traceme() -> Result<libc::c_long, usize> {
    ptrace(Request::TraceMe, 0, ptr::null_mut(), ptr::null_mut())
}

fn ptrace(request: Request, pid: libc::pid_t,
       addr: *mut libc::c_void, data: *mut libc::c_void) -> Result<libc::c_long, usize> {
    extern {
      fn ptrace(request: libc::c_int, pid: libc::pid_t,
                addr: *mut libc::c_void, data: *mut libc::c_void) -> libc::c_long;
    }
unsafe {
  let v = ptrace(request as libc::c_int, pid, addr, data);

  if v == -1 && errno() != 0 {
    Result::Err(errno() as usize)
  } else {
    Ok(v)
  }
}
}

#[derive(Clone, Copy)]
pub struct Reader {
  pub pid: libc::pid_t
}

#[derive(Clone, Copy)]
pub struct Writer {
    pub pid: libc::pid_t
}

impl Writer {
    pub fn new(pid: libc::pid_t) -> Self {
        Writer {
            pid: pid
        }
    }

    pub fn poke_data(&self, address: Address, data: Word) -> Result<Word, usize> {
        ptrace(Request::PokeData, self.pid, address as *mut libc::c_void, data as *mut libc::c_void).map(|x| x as Word)
    }

    pub unsafe fn write_object<T: Sized>(&self, data: &T) -> Result<(), usize> {
        let mut buf = Vec::with_capacity(mem::size_of::<T>());
            let tptr: *const T = data;
            let p: *const u8 = mem::transmute(tptr);
            for i in 0..buf.capacity() {
                buf.push(*p.offset(i as isize));
            }

        Ok(())
    }

    pub fn write_data(&self, address: Address, buf: &Vec<u8>) -> Result<(), usize> {
        let word_size = mem::size_of::<Word>();
        //for write_addr in (0..buf.len()).map(|x| address + x as Address * word_size as Address) {
        for (i, word_vec) in buf.chunks(word_size).enumerate() { 
            let write_addr = address + word_size as Address * i as Address as Address;
            if word_vec.len() == word_size {
                try!(self.poke_data(write_addr, word_vec.iter().rev().fold(0 as Word, |w, &x| w << 8 | x as Word)));
            } else {
                let b: Word = try!(Reader::new(self.pid).peek_data(write_addr)) >> 8 * word_vec.len();
                let wb = word_vec.iter().rev().fold(b, |w, &x| w << 8 | x as Word);
                try!(self.poke_data(write_addr, wb));
            }
        }
        Ok(())
    }
}

impl Reader {
  pub fn new(pid: libc::pid_t) -> Reader {
    Reader { pid: pid }
  }

    pub fn peek_data(&self, address: Address) -> Result<Word, usize> {
            ptrace(Request::PeekData, self.pid, address as *mut libc::c_void, ptr::null_mut()).map(|x| x as Word)
    }

    pub fn read_string(&self, address: Address) -> Result<Vec<u8>, usize> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
	for read_addr in (0..).map(|x| address + x * mem::size_of::<Address>() as Address) {
            let d: Vec<u8> = try!(self.peek_data(read_addr))
                                 .bytes()
                                 .iter()
                                 .take_while(|x| **x != 0)
                                 .map(|x| *x).collect();
            buf.extend_from_slice(&d);
            if d.len() < mem::size_of::<Word>() { break; }
        }
        return Ok(buf);
    }
}

trait Bytes {
    fn bytes(self) -> Vec<u8>;
}

impl Bytes for Word {
    fn bytes(self) -> Vec<u8> {
        (0..mem::size_of::<Word>()).map(|x| ((self >> (x * 8)) & 0xff) as u8).collect()
    }
}
