use zeroize::{Zeroize, Zeroizing};

use crate::core::crypto;
use crate::core::key::password::Password;
use crate::format::constants::{
    FIXED_HEADER_SIZE, FORMAT_VERSION, MAGIC, MAX_ID_LENGTH, MAX_PAYLOAD_SIZE, NONCE_SIZE,
    SALT_SIZE, TAG_SIZE,
};
use crate::format::{Container, HiddenContainer};
use crate::io::{console, file};
use crate::utils::encoding;

const MAX_CONTAINER_SIZE: usize =
    FIXED_HEADER_SIZE + MAX_ID_LENGTH * 2 + SALT_SIZE + NONCE_SIZE + MAX_PAYLOAD_SIZE + TAG_SIZE;

const MAX_HIDDEN_CONTAINER_SIZE: usize = SALT_SIZE + NONCE_SIZE + MAX_PAYLOAD_SIZE + TAG_SIZE;

const MAX_INPUT_CONTAINER_SIZE: usize = if MAX_CONTAINER_SIZE > MAX_HIDDEN_CONTAINER_SIZE {
    MAX_CONTAINER_SIZE
} else {
    MAX_HIDDEN_CONTAINER_SIZE
};

const MAX_TEXT_CONTAINER_SIZE: usize = MAX_INPUT_CONTAINER_SIZE.saturating_mul(3);

enum DecodedContainer {
    Standard(Container),
    Hidden(HiddenContainer),
}

fn decode_utf8(mut data: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, ()> {
    let bytes = std::mem::take(&mut *data);

    match String::from_utf8(bytes) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(())
        }
    }
}

fn display_container_info(container: &DecodedContainer) {
    if let DecodedContainer::Standard(container) = container {
        println!("\n============= CONTAINER INFO =============");
        println!("Container type: Standard");
        println!("Format version: {}", FORMAT_VERSION);
        println!("Cipher: {}", container.cipher_id);
        println!("KDF: {}", container.kdf_id);
        println!("==========================================");
    }
}

pub fn run() {
    println!("\n============= ATK-CL DECRYPTION =============");
    println!("[1] Read binary container from file");
    println!("[2] Enter HEX in console");
    println!("[3] Enter Base64 in console");
    println!("[4] Read HEX from text file");
    println!("[5] Read Base64 from text file");
    println!("[0] Back");

    let choice = match console::read_line("Select input method: ") {
        Ok(value) => value,
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    let (encoded, input_path): (Zeroizing<Vec<u8>>, Option<String>) = match choice.as_str() {
        "1" => {
            let path = match read_input_path() {
                Some(path) => path,
                None => return,
            };

            let data = match file::read_file_limited(&path, MAX_INPUT_CONTAINER_SIZE) {
                Ok(data) => data,
                Err(error) => {
                    println!("File error: {error}");
                    return;
                }
            };

            (data, Some(path))
        }
        "2" => {
            println!("Paste HEX data. Enter :end on a new line when finished.");

            let raw = match console::read_multiline(MAX_TEXT_CONTAINER_SIZE) {
                Ok(data) => data,
                Err(error) => {
                    println!("Input error: {error}");
                    return;
                }
            };

            let text = match decode_utf8(raw) {
                Ok(text) => text,
                Err(()) => {
                    println!("Input is not valid UTF-8.");
                    return;
                }
            };

            let data = match encoding::from_hex_zeroizing(text.as_str()) {
                Ok(data) => data,
                Err(error) => {
                    println!("HEX decoding error: {error}");
                    return;
                }
            };

            (data, None)
        }
        "3" => {
            println!("Paste Base64 data. Enter :end on a new line when finished.");

            let raw = match console::read_multiline(MAX_TEXT_CONTAINER_SIZE) {
                Ok(data) => data,
                Err(error) => {
                    println!("Input error: {error}");
                    return;
                }
            };

            let text = match decode_utf8(raw) {
                Ok(text) => text,
                Err(()) => {
                    println!("Input is not valid UTF-8.");
                    return;
                }
            };

            let data = match encoding::from_base64_zeroizing(text.as_str()) {
                Ok(data) => data,
                Err(error) => {
                    println!("Base64 decoding error: {error}");
                    return;
                }
            };

            (data, None)
        }
        "4" | "5" => {
            let path = match read_input_path() {
                Some(path) => path,
                None => return,
            };

            let raw = match file::read_file_limited(&path, MAX_TEXT_CONTAINER_SIZE) {
                Ok(data) => data,
                Err(error) => {
                    println!("File error: {error}");
                    return;
                }
            };

            let text = match decode_utf8(raw) {
                Ok(text) => text,
                Err(()) => {
                    println!("Input file is not valid UTF-8.");
                    return;
                }
            };

            let data = if choice == "4" {
                match encoding::from_hex_zeroizing(text.as_str()) {
                    Ok(data) => data,
                    Err(error) => {
                        println!("HEX decoding error: {error}");
                        return;
                    }
                }
            } else {
                match encoding::from_base64_zeroizing(text.as_str()) {
                    Ok(data) => data,
                    Err(error) => {
                        println!("Base64 decoding error: {error}");
                        return;
                    }
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

    let container = if encoded.starts_with(MAGIC) {
        match Container::decode(&encoded) {
            Ok(container) => DecodedContainer::Standard(container),
            Err(error) => {
                println!("Invalid container: {error}");
                return;
            }
        }
    } else {
        match HiddenContainer::decode(&encoded) {
            Ok(container) => DecodedContainer::Hidden(container),
            Err(_) => {
                println!("Decryption failed.");
                return;
            }
        }
    };

    display_container_info(&container);

    let password = match Password::read() {
        Ok(password) => password,
        Err(error) => {
            println!("Password error: {error}");
            return;
        }
    };

    let plaintext = match &container {
        DecodedContainer::Standard(container) => {
            match crypto::decrypt_zeroizing(container, &password) {
                Ok(data) => data,
                Err(error) => {
                    println!("Decryption failed: {error}");
                    return;
                }
            }
        }
        DecodedContainer::Hidden(container) => {
            match crypto::decrypt_hidden_zeroizing(container, &password) {
                Ok(data) => data,
                Err(_) => {
                    println!("Decryption failed.");
                    return;
                }
            }
        }
    };

    println!("\nDecryption completed successfully.");

    println!("\n============= OUTPUT =============");
    println!("[1] Display plaintext");
    println!("[2] Display HEX and Base64");
    println!("[3] Save decrypted data to file");
    println!("[0] Back");

    let output_choice = match console::read_line("Select output method: ") {
        Ok(value) => value,
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    match output_choice.as_str() {
        "1" => match std::str::from_utf8(&plaintext) {
            Ok(text) => println!("\n{text}"),
            Err(_) => {
                println!("Data is not valid UTF-8.");
                println!("HEX/Base64 representation:");

                let formatted = encoding::format_both(&plaintext);
                println!("{}", formatted.as_str());
            }
        },
        "2" => {
            let formatted = encoding::format_both(&plaintext);
            println!("{}", formatted.as_str());
        }
        "3" => {
            crate::cli::save::save(&plaintext, input_path.as_deref(), "Decrypted data");
        }
        "0" => (),
        _ => println!("Invalid option."),
    }
}

fn read_input_path() -> Option<String> {
    match console::read_line("Input file path: ") {
        Ok(path) if !path.trim().is_empty() => Some(path),
        Ok(_) => {
            println!("File path cannot be empty.");
            None
        }
        Err(error) => {
            println!("Input error: {error}");
            None
        }
    }
}
