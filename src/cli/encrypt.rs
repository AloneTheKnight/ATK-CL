use zeroize::Zeroizing;

use crate::core::crypto;
use crate::core::key::password::Password;
use crate::format::constants::MAX_PAYLOAD_SIZE;
use crate::io::{console, file};
use crate::utils::encoding;

pub fn run() {
    println!("\n============= ATK-CL ENCRYPTION =============");
    println!("[1] Enter text in console");
    println!("[2] Read from file");
    println!("[0] Back");

    let choice = match console::read_line("Select input method: ") {
        Ok(value) => value,
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    let (data, input_path): (Zeroizing<Vec<u8>>, Option<String>) = match choice.as_str() {
        "1" => match console::read_multiline(MAX_PAYLOAD_SIZE) {
            Ok(data) => (data, None),
            Err(error) => {
                println!("Input error: {error}");
                return;
            }
        },
        "2" => {
            let path = match console::read_line("Input file path: ") {
                Ok(path) if !path.trim().is_empty() => path,
                Ok(_) => {
                    println!("File path cannot be empty.");
                    return;
                }
                Err(error) => {
                    println!("Input error: {error}");
                    return;
                }
            };

            let data = match file::read_file_limited(&path, MAX_PAYLOAD_SIZE) {
                Ok(data) => data,
                Err(error) => {
                    println!("File error: {error}");
                    return;
                }
            };

            (data, Some(path))
        }
        "0" => return,
        _ => {
            println!("Invalid option.");
            return;
        }
    };

    println!("Input loaded successfully.");

    let password = match Password::read() {
        Ok(password) => password,
        Err(error) => {
            println!("Password error: {error}");
            return;
        }
    };

    println!("\n============= CONTAINER FORMAT =============");
    println!("[1] Standard container");
    println!("[2] Hidden container");
    println!("[0] Back");

    let format_choice = match console::read_line("Select container format: ") {
        Ok(value) => value,
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    let encoded = match format_choice.as_str() {
        "1" => {
            let container = match crypto::encrypt(&data, &password) {
                Ok(container) => container,
                Err(error) => {
                    println!("Encryption error: {error}");
                    return;
                }
            };

            match container.encode() {
                Ok(data) => data,
                Err(error) => {
                    println!("Container encoding error: {error}");
                    return;
                }
            }
        }
        "2" => {
            let container = match crypto::encrypt_hidden(&data, &password) {
                Ok(container) => container,
                Err(error) => {
                    println!("Encryption error: {error}");
                    return;
                }
            };

            match container.encode() {
                Ok(data) => data,
                Err(error) => {
                    println!("Hidden container encoding error: {error}");
                    return;
                }
            }
        }
        "0" => return,
        _ => {
            println!("Invalid option.");
            return;
        }
    };

    println!("\nEncryption completed successfully.");

    println!("\n============= OUTPUT =============");
    println!("[1] Display HEX");
    println!("[2] Display Base64");
    println!("[3] Save binary container");
    println!("[4] Save HEX text");
    println!("[5] Save Base64 text");
    println!("[0] Back");

    let output_choice = match console::read_line("Select output method: ") {
        Ok(value) => value,
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    match output_choice.as_str() {
        "1" => {
            println!("\n{}", encoding::to_hex(&encoded));
        }
        "2" => {
            println!("\n{}", encoding::to_base64(&encoded));
        }
        "3" => {
            crate::cli::save::save(&encoded, input_path.as_deref(), "Encrypted data");
        }
        "4" => {
            let text = encoding::to_hex(&encoded);
            crate::cli::save::save(text.as_bytes(), input_path.as_deref(), "Encrypted data");
        }
        "5" => {
            let text = encoding::to_base64(&encoded);
            crate::cli::save::save(text.as_bytes(), input_path.as_deref(), "Encrypted data");
        }
        "0" => (),
        _ => println!("Invalid option."),
    }
}
