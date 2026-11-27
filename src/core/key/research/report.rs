use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::key::research::kdf_benchmark::BenchmarkResult;
use crate::io::file;

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub struct BitDifferenceReport {
    pub experiment: String,
    pub input_length: usize,
    pub changed_bits: usize,
    pub total_bits: usize,
    pub difference_percent: f64,
}

impl BitDifferenceReport {
    pub fn generate(&self) -> String {
        format!(
            "========================================\n\
             ATK-CL RESEARCH REPORT\n\
             ========================================\n\
             Experiment: {}\n\
             Unix timestamp: {}\n\
             Input length: {} bytes\n\
             Changed bits: {}\n\
             Total bits: {}\n\
             Difference: {:.4}%\n\
             \n\
             NOTE:\n\
             This measurement does not prove cryptographic security.\n\
             No keys, passwords or raw input data are included.\n\
             ========================================\n",
            self.experiment,
            timestamp(),
            self.input_length,
            self.changed_bits,
            self.total_bits,
            self.difference_percent,
        )
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        file::write_file(path, self.generate().as_bytes())
    }
}

pub struct KdfBenchmarkReport<'a> {
    pub algorithm: &'a str,
    pub warmup_iterations: usize,
    pub result: &'a BenchmarkResult,
}

impl KdfBenchmarkReport<'_> {
    pub fn generate(&self) -> String {
        format!(
            "========================================\n\
             ATK-CL KDF BENCHMARK REPORT\n\
             ========================================\n\
             Algorithm: {}\n\
             Unix timestamp: {}\n\
             Warm-up iterations: {}\n\
             Measured iterations: {}\n\
             Average: {:?}\n\
             Median: {:?}\n\
             Minimum: {:?}\n\
             Maximum: {:?}\n\
             Standard deviation: {:.2} ns\n\
             \n\
             NOTE:\n\
             Results depend on hardware, operating system and system load.\n\
             Performance measurements do not prove cryptographic security.\n\
             ========================================\n",
            self.algorithm,
            timestamp(),
            self.warmup_iterations,
            self.result.iterations,
            self.result.average,
            self.result.median,
            self.result.minimum,
            self.result.maximum,
            self.result.standard_deviation_ns,
        )
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        file::write_file(path, self.generate().as_bytes())
    }
}
