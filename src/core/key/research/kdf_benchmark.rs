use std::time::{Duration, Instant};

use super::statistics;

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkResult {
    pub iterations: usize,
    pub average: Duration,
    pub median: Duration,
    pub minimum: Duration,
    pub maximum: Duration,
    pub standard_deviation_ns: f64,
}

pub fn calculate_result(times: &[Duration]) -> Option<BenchmarkResult> {
    if times.is_empty() || times.len() > u32::MAX as usize {
        return None;
    }

    let total = times
        .iter()
        .try_fold(Duration::ZERO, |sum, time| sum.checked_add(*time))?;

    let minimum = times.iter().copied().min()?;
    let maximum = times.iter().copied().max()?;
    let average = total / u32::try_from(times.len()).ok()?;

    let mut sorted = times.to_vec();
    sorted.sort_unstable();

    let middle = sorted.len() / 2;

    let median = if sorted.len() % 2 == 1 {
        sorted[middle]
    } else {
        let left = sorted[middle - 1].as_nanos();
        let right = sorted[middle].as_nanos();

        Duration::from_nanos(((left + right) / 2).min(u64::MAX as u128) as u64)
    };

    let values: Vec<f64> = times.iter().map(|time| time.as_nanos() as f64).collect();

    let standard_deviation_ns = statistics::standard_deviation(&values)?;

    Some(BenchmarkResult {
        iterations: times.len(),
        average,
        median,
        minimum,
        maximum,
        standard_deviation_ns,
    })
}

pub fn measure_with_warmup<F>(
    warmup_iterations: usize,
    iterations: usize,
    mut operation: F,
) -> Option<BenchmarkResult>
where
    F: FnMut(),
{
    if iterations == 0 || iterations > u32::MAX as usize {
        return None;
    }

    for _ in 0..warmup_iterations {
        operation();
    }

    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        operation();
        times.push(start.elapsed());
    }

    calculate_result(&times)
}

pub fn try_measure_with_warmup<F, E>(
    warmup_iterations: usize,
    iterations: usize,
    mut operation: F,
) -> Result<Option<BenchmarkResult>, E>
where
    F: FnMut() -> Result<(), E>,
{
    if iterations == 0 || iterations > u32::MAX as usize {
        return Ok(None);
    }

    for _ in 0..warmup_iterations {
        operation()?;
    }

    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        operation()?;
        times.push(start.elapsed());
    }

    Ok(calculate_result(&times))
}
pub fn measure<F>(iterations: usize, operation: F) -> Option<BenchmarkResult>
where
    F: FnMut(),
{
    measure_with_warmup(0, iterations, operation)
}
