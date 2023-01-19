use std::{
    env,
    ffi::OsString,
    io::{Error, Result},
    mem,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    ptr,
};

use strace::{Flags, Pid, Tracer};

mod bin_modes;

use bin_modes as mode;

fn e<T>(res: syscall::Result<T>) -> Result<T> {
    res.map_err(|err| Error::from_raw_os_error(err.errno))
}

pub const TRACE_FLAGS: Flags = Flags::from_bits_truncate(
    (Flags::STOP_ALL.bits() & !Flags::STOP_SINGLESTEP.bits()) | Flags::EVENT_ALL.bits(),
);

fn main() -> Result<()> {
    let opt = mode::parse_args();
    let cmd = match &opt.cmd {
        mode::Command::Cmdline(args) => args,
    };

    let mut file = None;
    for mut path in env::split_paths(&env::var_os("PATH").unwrap_or(OsString::new())) {
        path.push(&cmd[0]);
        if path.is_file() {
            file = Some(path);
            break;
        }
    }

    let path = match file {
        Some(inner) => inner,
        None => {
            eprintln!("Could not find that binary in $PATH");
            return Ok(());
        },
    };

    match unsafe { libc::fork() } {
        -1 => panic!("Failed to fork()"),
        0 => child(path, cmd.clone()),
        pid => parent(path, pid as usize, opt),
    }
}

fn child(path: PathBuf, cmd_args: Vec<String>) -> Result<()> {
    let mut path = path.into_os_string();
    path.push("\0");

    let mut args = Vec::new();
    for mut arg in cmd_args {
        arg.push('\0');
        let ptr = arg.as_ptr() as *const libc::c_char;
        mem::forget(arg);
        args.push(ptr);
    }
    args.push(ptr::null());

    // I'm ready to be traced!
    e(syscall::kill(e(syscall::getpid())?, syscall::SIGSTOP))?;

    let res = unsafe { libc::execv(path.as_bytes().as_ptr() as *const _, args.as_ptr()) };
    if res == -1 {
        panic!("Execv failed with error {}", Error::last_os_error());
    } else {
        unreachable!("fexec can't return Ok(_)")
    }
}

fn parent(path: PathBuf, pid: Pid, opt: mode::Opt) -> Result<()> {
    let mut status = 0;

    eprintln!("Executing {} (PID {})", path.display(), pid);

    // Wait until child is ready to be traced
    e(syscall::waitpid(pid, &mut status, syscall::WUNTRACED))?;

    let mut tracer = Tracer::attach(pid)?;

    // Won't actually restart the process, because it's stopped by ptrace
    e(syscall::kill(pid, syscall::SIGCONT))?;

    // There will first be a post-syscall for `kill`.
    tracer.next(Flags::STOP_POST_SYSCALL)?;

    match mode::inner_main(pid, tracer, opt) {
        Err(ref err) if err.raw_os_error() == Some(syscall::ESRCH) => {
            e(syscall::waitpid(pid, &mut status, syscall::WNOHANG))?;
            if syscall::wifexited(status) {
                println!(
                    "Process exited with status {}",
                    syscall::wexitstatus(status)
                );
            }
            if syscall::wifsignaled(status) {
                println!("Process signaled with status {}", syscall::wtermsig(status));
            }
            Ok(())
        },
        other => other,
    }
}
