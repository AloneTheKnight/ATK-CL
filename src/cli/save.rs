use std::path::Path;

use crate::io::{console, file};

pub fn save(data: &[u8], input_path: Option<&str>, description: &str) {
    let mut output_path = match console::read_line("Output file path: ") {
        Ok(path) if !path.trim().is_empty() => path,
        Ok(_) => {
            println!("Output path cannot be empty.");
            return;
        }
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    let mut overwrite = false;

    if Path::new(&output_path).exists() {
        println!("\nFile already exists.");
        println!("[1] Overwrite existing file");
        println!("[2] Save under a new name");
        println!("[0] Cancel");

        let choice = match console::read_line("Select action: ") {
            Ok(value) => value,
            Err(error) => {
                println!("Input error: {error}");
                return;
            }
        };

        match choice.trim() {
            "1" => overwrite = true,
            "2" => {
                output_path = match console::read_line("New output file path: ") {
                    Ok(path) if !path.trim().is_empty() => path,
                    Ok(_) => {
                        println!("Output path cannot be empty.");
                        return;
                    }
                    Err(error) => {
                        println!("Input error: {error}");
                        return;
                    }
                };
            }
            "0" => {
                println!("Operation cancelled.");
                return;
            }
            _ => {
                println!("Invalid option.");
                return;
            }
        }
    }

    if let Some(input_path) = input_path {
        match file::paths_refer_to_same_file(input_path, &output_path) {
            Ok(true) => {
                println!("Input and output paths must be different.");
                return;
            }
            Ok(false) => {}
            Err(error) => {
                println!("Path validation error: {error}");
                return;
            }
        }
    }

    let result = if overwrite {
        file::write_file_replace(&output_path, data)
    } else {
        file::write_file_new(&output_path, data)
    };

    match result {
        Ok(()) => println!("{description} saved: {output_path}"),
        Err(error) => println!("File error: {error}"),
    }
}
