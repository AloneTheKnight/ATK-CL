use std::cell::Cell;
use std::time::Duration;

use atk_cl::core::cipher::constants::{KEY_SIZE, NONCE_SIZE};
use atk_cl::core::key::research::{
    avalanche,
    kdf::{self, KdfResearchReport},
    kdf_benchmark,
    report::BitDifferenceReport,
    statistics,
};

#[test]
fn changed_bits_counts_identical_data() {
    assert_eq!(
        avalanche::count_changed_bits(&[0xAA, 0x55], &[0xAA, 0x55]),
        Some(0)
    );
}

#[test]
fn changed_bits_counts_all_different_bits() {
    assert_eq!(avalanche::count_changed_bits(&[0x00], &[0xFF]), Some(8));
}

#[test]
fn changed_bits_rejects_different_lengths() {
    assert_eq!(avalanche::count_changed_bits(&[1], &[1, 2]), None);
}

#[test]
fn difference_ratio_is_correct() {
    assert_eq!(avalanche::difference_ratio(&[0x00], &[0x0F]), Some(0.5));
}

#[test]
fn empty_difference_ratio_is_zero() {
    assert_eq!(avalanche::difference_ratio(&[], &[]), Some(0.0));
}

#[test]
fn key_bit_flip_produces_comparable_ciphertexts() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];
    let input = b"ATK-CL research test";

    let difference = avalanche::key_bit_flip_difference(&key, &nonce, input, 0, 0).unwrap();

    assert!(difference.is_some());
}

#[test]
fn key_bit_flip_rejects_invalid_bit_index() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    assert_eq!(
        avalanche::key_bit_flip_difference(&key, &nonce, b"test", 0, 8,).unwrap(),
        None
    );
}

#[test]
fn key_bit_flip_rejects_invalid_byte_index() {
    let key = [0x11; KEY_SIZE];
    let nonce = [0x22; NONCE_SIZE];

    assert_eq!(
        avalanche::key_bit_flip_difference(&key, &nonce, b"test", KEY_SIZE, 0,).unwrap(),
        None
    );
}

#[test]
fn statistics_mean_is_correct() {
    assert_eq!(statistics::mean(&[1.0, 2.0, 3.0]), Some(2.0));
}

#[test]
fn statistics_median_handles_odd_and_even_lengths() {
    assert_eq!(statistics::median(&[5.0, 1.0, 3.0]), Some(3.0));

    assert_eq!(statistics::median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
}

#[test]
fn statistics_minimum_and_maximum_are_correct() {
    assert_eq!(statistics::min(&[3.0, 1.0, 5.0]), Some(1.0));

    assert_eq!(statistics::max(&[3.0, 1.0, 5.0]), Some(5.0));
}

#[test]
fn statistics_variance_and_deviation_are_correct() {
    assert_eq!(statistics::variance(&[1.0, 2.0, 3.0]), Some(2.0 / 3.0));

    let deviation = statistics::standard_deviation(&[1.0, 2.0, 3.0]).unwrap();

    assert!((deviation - (2.0f64 / 3.0).sqrt()).abs() < 1e-12);
}

#[test]
fn statistics_rejects_empty_and_non_finite_values() {
    assert_eq!(statistics::mean(&[]), None);
    assert_eq!(statistics::median(&[]), None);
    assert_eq!(statistics::mean(&[1.0, f64::NAN]), None);
    assert_eq!(statistics::max(&[1.0, f64::INFINITY]), None);
}

#[test]
fn benchmark_calculates_result() {
    let times = [
        Duration::from_nanos(100),
        Duration::from_nanos(200),
        Duration::from_nanos(300),
    ];

    let result = kdf_benchmark::calculate_result(&times).unwrap();

    assert_eq!(result.iterations, 3);
    assert_eq!(result.average, Duration::from_nanos(200));
    assert_eq!(result.median, Duration::from_nanos(200));
    assert_eq!(result.minimum, Duration::from_nanos(100));
    assert_eq!(result.maximum, Duration::from_nanos(300));
}

#[test]
fn benchmark_rejects_empty_input() {
    assert!(kdf_benchmark::calculate_result(&[]).is_none());
}

#[test]
fn benchmark_performs_warmup_and_measurements() {
    let calls = Cell::new(0usize);

    let result = kdf_benchmark::measure_with_warmup(2, 3, || calls.set(calls.get() + 1));

    assert!(result.is_some());
    assert_eq!(calls.get(), 5);
    assert_eq!(result.unwrap().iterations, 3);
}

#[test]
fn benchmark_rejects_zero_iterations() {
    assert!(kdf_benchmark::measure(0, || {}).is_none());
}

#[test]
fn kdf_report_validation_works() {
    let valid = KdfResearchReport::new(16, 32, 1000);
    let invalid = KdfResearchReport::new(0, 32, 1000);

    assert!(valid.is_valid());
    assert!(!invalid.is_valid());
}

#[test]
fn kdf_report_average_and_median_work() {
    let reports = [
        KdfResearchReport::new(16, 32, 100),
        KdfResearchReport::new(16, 32, 200),
        KdfResearchReport::new(16, 32, 300),
    ];

    assert_eq!(kdf::average_execution_time(&reports), Some(200.0));

    assert_eq!(kdf::median_execution_time(&reports), Some(200.0));
}

#[test]
fn kdf_report_rejects_empty_reports() {
    assert_eq!(kdf::average_execution_time(&[]), None);
    assert_eq!(kdf::median_execution_time(&[]), None);
}

#[test]
fn bit_report_does_not_include_raw_input_values() {
    let report = BitDifferenceReport {
        experiment: "Test experiment".to_string(),
        input_length: 8,
        changed_bits: 4,
        total_bits: 64,
        difference_percent: 6.25,
    };

    let output = report.generate();

    assert!(output.contains("Test experiment"));
    assert!(output.contains("Changed bits: 4"));
    assert!(output.contains("No keys, passwords or raw input data are included."));
    assert!(!output.contains("secret-key-value"));
}
