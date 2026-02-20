//! Read a password from /dev/tty without echoing.
//!
//! The sole purpose of this file is to make the project totally dependency-free.
//! It replaces the `rpassword` crate by shelling out to `stty` to toggle echo,
//! which works on any Unix system without pulling in libc bindings or other crates.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn stty(flag: &str) -> io::Result<()> {
  let tty = File::open("/dev/tty")?;
  Command::new("stty").arg(flag).stdin(Stdio::from(tty)).status()?;
  Ok(())
}

pub fn read_password(prompt: &str) -> io::Result<Vec<u8>> {
  let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
  write!(tty, "{}", prompt)?;
  tty.flush()?;

  stty("-echo")?;
  let mut line = String::new();
  BufReader::new(File::open("/dev/tty")?).read_line(&mut line)?;
  stty("echo")?;

  writeln!(tty)?; // newline after hidden input
  let pass = line.trim_end_matches('\n').trim_end_matches('\r');
  Ok(pass.as_bytes().to_vec())
}
