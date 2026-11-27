use crate::io::console;
use std::io::{self, Write};

use crate::core;

pub fn run() {
    loop {
        println!("\n========================================");
        println!("                 ATK-CL");
        println!("       Alone The Knight's Crypto Lib");
        println!("========================================");
        println!("Library version: {}", core::LIBRARY_VERSION);
        println!("Cipher: {}", core::cipher::constants::CIPHER_ID);
        println!("Status: Experimental");
        println!();
        println!("[1] Encrypt");
        println!("[2] Decrypt");
        println!("[3] Algorithm information");
        println!("[4] Research Lab");
        println!("[5] Key Management");
        println!("[0] Exit");
        println!("========================================");

        print!("Select option: ");

        if io::stdout().flush().is_err() {
            println!("Output error.");
            break;
        }

        let mut choice = String::new();

        if io::stdin().read_line(&mut choice).is_err() {
            println!("Input error.");
            continue;
        }

        match choice.trim() {
            "1" => {
                super::encrypt::run();
                console::pause();
            }
            "2" => {
                super::decrypt::run();
                console::pause();
            }
            "3" => {
                show_info();
                console::pause();
            }
            "4" => {
                super::research::run();
                console::pause();
            }
            "5" => {
                super::key_management::run();
                console::pause();
            }
            "0" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!("Invalid option.");
                console::pause();
            }
        }
    }
}

fn show_info() {
    println!("\n========== ATK-CL INFORMATION ==========");
    println!("Name: Alone The Knight's Crypto Lib");
    println!("Library version: {}", core::LIBRARY_VERSION);
    println!(
        "Format version: {}",
        crate::format::constants::FORMAT_VERSION
    );
    println!("Cipher: {}", core::cipher::constants::CIPHER_ID);
    println!("Status: Experimental / Not cryptographically validated");
    println!("========================================");
}
