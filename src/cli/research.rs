use crate::core::cipher::constants::NONCE_SIZE;
use crate::core::key::constants::KDF_ID;
use crate::core::key::derive::derive_key;
use crate::core::key::password::Password;
use crate::core::key::research::{
    avalanche, kdf_benchmark,
    report::{BitDifferenceReport, KdfBenchmarkReport},
    statistics,
};
use crate::core::key::salt::Salt;
use crate::io::console;
use std::hint::black_box;

const BENCHMARK_WARMUP: usize = 2;
const MAX_BENCHMARK_ITERATIONS: usize = 100;

pub fn run() {
    loop {
        println!("\n============= RESEARCH LAB =============");
        println!("[1] Bit difference analyzer");
        println!("[2] Cipher key sensitivity analysis");
        println!("[3] Statistical analysis");
        println!("[4] ATK-KDF-1 benchmark");
        println!("[5] Research information");
        println!("[0] Back");

        let choice = match console::read_line("Select option: ") {
            Ok(value) => value,
            Err(error) => {
                println!("Input error: {error}");
                return;
            }
        };

        match choice.trim() {
            "1" => bit_difference_menu(),
            "2" => avalanche_menu(),
            "3" => statistics_menu(),
            "4" => kdf_benchmark_menu(),
            "5" => show_information(),
            "0" => return,
            _ => println!("Invalid option."),
        }
    }
}

fn bit_difference_menu() {
    println!("\n========== BIT DIFFERENCE ==========");

    let left = match console::read_line("First HEX value: ") {
        Ok(value) => value,
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    let right = match console::read_line("Second HEX value: ") {
        Ok(value) => value,
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    let left = match crate::utils::encoding::from_hex(&left) {
        Ok(value) => value,
        Err(error) => {
            println!("Invalid first HEX value: {error}");
            return;
        }
    };

    let right = match crate::utils::encoding::from_hex(&right) {
        Ok(value) => value,
        Err(error) => {
            println!("Invalid second HEX value: {error}");
            return;
        }
    };

    match avalanche::count_changed_bits(&left, &right) {
        Some(changed) => {
            let total = avalanche::total_bits(&left);
            let ratio = avalanche::difference_ratio(&left, &right).unwrap_or(0.0);

            let percent = ratio * 100.0;

            println!("\nChanged bits: {changed}");
            println!("Total bits: {total}");
            println!("Difference: {percent:.4}%");

            let report = BitDifferenceReport {
                experiment: "Direct bit comparison".to_string(),
                input_length: left.len(),
                changed_bits: changed,
                total_bits: total,
                difference_percent: percent,
            };

            let save = console::read_line("\nSave report? [y/N]: ");

            if let Ok(answer) = save
                && answer.trim().eq_ignore_ascii_case("y")
            {
                save_bit_report(&report);
            }
        }
        None => println!("Input values have different lengths."),
    }
}

fn save_bit_report(report: &BitDifferenceReport) {
    let path = match console::read_line("Report file path: ") {
        Ok(path) if !path.trim().is_empty() => path,
        _ => {
            println!("Invalid path.");
            return;
        }
    };

    match report.save(path.trim()) {
        Ok(()) => println!("Report saved."),
        Err(error) => println!("Could not save report: {error}"),
    }
}

fn avalanche_menu() {
    println!("\n========== CIPHER KEY SENSITIVITY ==========");
    println!("This experiment flips one key bit and compares ciphertexts.");
    println!("It does not modify the cipher algorithm or its parameters.");

    let password = match Password::new(b"ATK-CL-RESEARCH-KEY-SENSITIVITY".to_vec()) {
        Ok(value) => value,
        Err(error) => {
            println!("Password setup failed: {error}");
            return;
        }
    };

    let salt = Salt::from_bytes([0xA5; 16]);

    let key = match derive_key(&password, &salt) {
        Ok(value) => value,
        Err(error) => {
            println!("Key derivation failed: {error}");
            return;
        }
    };

    let nonce = [0x5A; NONCE_SIZE];
    let input = b"ATK-CL research key sensitivity experiment";

    let changed = match avalanche::key_bit_flip_difference(key.as_bytes(), &nonce, input, 0, 0) {
        Ok(Some(value)) => value,
        Ok(None) => {
            println!("Invalid bit selection.");
            return;
        }
        Err(error) => {
            println!("Cipher operation failed: {error:?}");
            return;
        }
    };

    let total = input.len() * 8;
    let percent = if total == 0 {
        0.0
    } else {
        changed as f64 * 100.0 / total as f64
    };

    println!("\nChanged ciphertext bits: {changed}");
    println!("Total ciphertext bits: {total}");
    println!("Difference: {percent:.4}%");
    println!("Changed key bit: byte 0, bit 0");

    let report = BitDifferenceReport {
        experiment: "ATK-SC-1 key-bit sensitivity".to_string(),
        input_length: input.len(),
        changed_bits: changed,
        total_bits: total,
        difference_percent: percent,
    };

    let save = console::read_line("\nSave report? [y/N]: ");

    if let Ok(answer) = save
        && answer.trim().eq_ignore_ascii_case("y")
    {
        save_bit_report(&report);
    }

    println!("\nNOTE: One experiment is not a cryptographic security test.");
    println!("A meaningful study requires many controlled input samples.");
}

fn statistics_menu() {
    println!("\n========== STATISTICAL ANALYSIS ==========");
    println!("Enter comma-separated finite numbers.");
    println!("Example: 10, 20, 30, 40, 50");

    let input = match console::read_line("Values: ") {
        Ok(value) => value,
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    let values: Result<Vec<f64>, _> = input
        .split(',')
        .map(|part| part.trim().parse::<f64>())
        .collect();

    let values = match values {
        Ok(values) if !values.is_empty() => values,
        _ => {
            println!("Invalid or empty input.");
            return;
        }
    };

    if values.iter().any(|value| !value.is_finite()) {
        println!("NaN and infinite values are not accepted.");
        return;
    }

    println!("\nSamples: {}", values.len());
    println!("Mean: {:?}", statistics::mean(&values));
    println!("Median: {:?}", statistics::median(&values));
    println!("Minimum: {:?}", statistics::min(&values));
    println!("Maximum: {:?}", statistics::max(&values));
    println!("Variance: {:?}", statistics::variance(&values));
    println!(
        "Standard deviation: {:?}",
        statistics::standard_deviation(&values)
    );
}

fn kdf_benchmark_menu() {
    println!("\n========== ATK-KDF-1 BENCHMARK ==========");
    println!("This runs the actual derive_key() implementation.");
    println!("Warm-up iterations: {BENCHMARK_WARMUP}");
    println!("Allowed measured iterations: 1..={MAX_BENCHMARK_ITERATIONS}");

    let iterations = match console::read_line("Number of measured iterations: ") {
        Ok(value) => match value.trim().parse::<usize>() {
            Ok(number) if (1..=MAX_BENCHMARK_ITERATIONS).contains(&number) => number,
            _ => {
                println!("Enter a number from 1 to {MAX_BENCHMARK_ITERATIONS}.");
                return;
            }
        },
        Err(error) => {
            println!("Input error: {error}");
            return;
        }
    };

    let password = match Password::new(b"ATK-CL-RESEARCH-BENCHMARK".to_vec()) {
        Ok(value) => value,
        Err(error) => {
            println!("Password setup failed: {error}");
            return;
        }
    };

    let salt = Salt::from_bytes([0xA5; 16]);

    println!("\nRunning ATK-KDF-1 benchmark...");

    let result = kdf_benchmark::try_measure_with_warmup(BENCHMARK_WARMUP, iterations, || {
        let key = derive_key(&password, &salt).map_err(|error| format!("{error:?}"))?;

        black_box(key.as_bytes());

        Ok::<(), String>(())
    });

    let result = match result {
        Ok(Some(result)) => result,
        Ok(None) => {
            println!("Benchmark failed.");
            return;
        }
        Err(error) => {
            println!("KDF benchmark failed: {error}");
            return;
        }
    };

    println!("\n========== RESULTS ==========");
    println!("Algorithm: {}", KDF_ID);
    println!("Iterations: {}", result.iterations);
    println!("Average: {:?}", result.average);
    println!("Median: {:?}", result.median);
    println!("Minimum: {:?}", result.minimum);
    println!("Maximum: {:?}", result.maximum);
    println!("Standard deviation: {:.2} ns", result.standard_deviation_ns);
    println!("=============================");

    let report = KdfBenchmarkReport {
        algorithm: KDF_ID,
        warmup_iterations: BENCHMARK_WARMUP,
        result: &result,
    };

    let save = console::read_line("\nSave benchmark report? [y/N]: ");

    if let Ok(answer) = save
        && answer.trim().eq_ignore_ascii_case("y")
    {
        let path = match console::read_line("Output file path: ") {
            Ok(path) if !path.trim().is_empty() => path,
            _ => {
                println!("Invalid path.");
                return;
            }
        };

        match report.save(path.trim()) {
            Ok(()) => println!("Benchmark report saved."),
            Err(error) => println!("Could not save report: {error}"),
        }
    }

    println!("\nWARNING:");
    println!("Measurements depend on hardware and system load.");
    println!("They do not prove cryptographic security.");
}

fn show_information() {
    println!("\n========== RESEARCH INFORMATION ==========");
    println!("Project: ATK-CL");
    println!("Cipher: ATK-SC-1");
    println!("KDF: ATK-KDF-1");
    println!("Tools:");
    println!("- Direct bit difference analysis");
    println!("- Cipher key-bit sensitivity experiment");
    println!("- Statistical analysis");
    println!("- Real ATK-KDF-1 benchmark");
    println!();
    println!("Status: Experimental");
    println!("These tools do not prove cryptographic security.");
}
