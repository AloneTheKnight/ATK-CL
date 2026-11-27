use crate::core::key::manager::KeyManager;
use crate::io::console;
use crate::utils::encoding;

pub fn run() {
    loop {
        println!("\n========== KEY MANAGEMENT ==========");
        println!("[1] Generate key session");
        println!("[0] Back");

        let choice = match console::read_line("Select option: ") {
            Ok(value) => value,
            Err(error) => {
                println!("Input error: {error}");
                return;
            }
        };

        match choice.as_str() {
            "1" => create_session(),
            "0" => return,
            _ => println!("Invalid option."),
        }
    }
}

fn create_session() {
    println!("\n========== NEW KEY SESSION ==========");

    let manager = match KeyManager::create() {
        Ok(manager) => manager,
        Err(error) => {
            println!("Key session error: {error}");
            return;
        }
    };

    println!("\nKey session created successfully.");
    println!("Password: loaded (hidden)");
    println!("Salt size: {} bytes", manager.salt().as_bytes().len());

    println!(
        "Salt (HEX): {}",
        encoding::to_hex(manager.salt().as_bytes())
    );

    println!("\nKey derivation: NOT IMPLEMENTED");
    println!("Encryption: NOT PERFORMED");
    println!("Session will be discarded when you return.");

    drop(manager);

    let _ = console::read_line("\nPress Enter to continue...");
}
