fn valid_values(values: &[f64]) -> bool {
    !values.is_empty() && values.iter().all(|value| value.is_finite())
}

pub fn mean(values: &[f64]) -> Option<f64> {
    if !valid_values(values) {
        return None;
    }

    let mut result = 0.0;

    for (index, value) in values.iter().enumerate() {
        let count = (index + 1) as f64;
        result += (*value - result) / count;
    }

    result.is_finite().then_some(result)
}

pub fn min(values: &[f64]) -> Option<f64> {
    if !valid_values(values) {
        return None;
    }

    values.iter().copied().reduce(f64::min)
}

pub fn max(values: &[f64]) -> Option<f64> {
    if !valid_values(values) {
        return None;
    }

    values.iter().copied().reduce(f64::max)
}

pub fn median(values: &[f64]) -> Option<f64> {
    if !valid_values(values) {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);

    let middle = sorted.len() / 2;

    if sorted.len() % 2 == 1 {
        Some(sorted[middle])
    } else {
        let left = sorted[middle - 1];
        let right = sorted[middle];

        Some(left / 2.0 + right / 2.0)
    }
}

pub fn variance(values: &[f64]) -> Option<f64> {
    let average = mean(values)?;

    let result = values
        .iter()
        .map(|value| {
            let difference = *value - average;
            difference * difference
        })
        .sum::<f64>()
        / values.len() as f64;

    result.is_finite().then_some(result)
}

pub fn standard_deviation(values: &[f64]) -> Option<f64> {
    let variance = variance(values)?;
    let result = variance.sqrt();

    if result.is_finite() {
        Some(result)
    } else {
        None
    }
}
