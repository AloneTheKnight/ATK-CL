use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub fn read_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}

pub fn read_password() -> io::Result<Zeroizing<String>> {
    rpassword::prompt_password("Enter password: ").map(Zeroizing::new)
}

fn push_limited(text: &mut Zeroizing<Vec<u8>>, byte: u8, max_bytes: usize) -> io::Result<()> {
    if text.len() >= max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Input exceeds the maximum size of {max_bytes} bytes"),
        ));
    }

    text.push(byte);
    Ok(())
}

pub fn read_multiline(max_bytes: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    println!("Enter your text.");
    println!("Type :end on a separate line to finish.\n");

    let stdin = io::stdin();
    let mut input = stdin.lock();

    let mut text = Zeroizing::new(Vec::new());
    let mut line_start = 0usize;
    let mut byte = [0u8; 1];
    let mut pending_cr = false;

    print!("> ");
    io::stdout().flush()?;

    loop {
        match input.read(&mut byte)? {
            0 => {
                if pending_cr {
                    if &text[line_start..] == b":end" {
                        text.truncate(line_start);
                    } else {
                        push_limited(&mut text, b'\n', max_bytes)?;
                    }
                } else if &text[line_start..] == b":end" {
                    text.truncate(line_start);
                } else if text.len() > line_start {
                    push_limited(&mut text, b'\n', max_bytes)?;
                }

                break;
            }

            _ => {
                let current = byte[0];

                if pending_cr {
                    pending_cr = false;

                    if current == b'\n' {
                        if &text[line_start..] == b":end" {
                            text.truncate(line_start);
                            break;
                        }

                        push_limited(&mut text, b'\n', max_bytes)?;
                        line_start = text.len();

                        print!("> ");
                        io::stdout().flush()?;
                        continue;
                    }

                    push_limited(&mut text, b'\r', max_bytes)?;
                }

                match current {
                    b'\r' => {
                        pending_cr = true;
                    }

                    b'\n' => {
                        if &text[line_start..] == b":end" {
                            text.truncate(line_start);
                            break;
                        }

                        push_limited(&mut text, b'\n', max_bytes)?;
                        line_start = text.len();

                        print!("> ");
                        io::stdout().flush()?;
                    }

                    _ => {
                        push_limited(&mut text, current, max_bytes)?;
                    }
                }
            }
        }
    }

    Ok(text)
}

pub fn pause() {
    let mut input = String::new();

    println!();
    print!("Press Enter to continue...");

    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut input);
}
