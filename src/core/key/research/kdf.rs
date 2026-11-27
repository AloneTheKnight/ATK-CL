use super::statistics;

#[derive(Debug, Clone, PartialEq)]
pub struct KdfResearchReport {
    pub input_length: usize,
    pub output_length: usize,
    pub execution_time_ns: u128,
}

impl KdfResearchReport {
    pub fn new(input_length: usize, output_length: usize, execution_time_ns: u128) -> Self {
        Self {
            input_length,
            output_length,
            execution_time_ns,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.input_length > 0 && self.output_length > 0
    }
}

fn valid_reports(reports: &[KdfResearchReport]) -> bool {
    !reports.is_empty() && reports.iter().all(KdfResearchReport::is_valid)
}

pub fn average_execution_time(reports: &[KdfResearchReport]) -> Option<f64> {
    if !valid_reports(reports) {
        return None;
    }

    let values: Vec<f64> = reports
        .iter()
        .map(|report| report.execution_time_ns as f64)
        .collect();

    statistics::mean(&values)
}

pub fn median_execution_time(reports: &[KdfResearchReport]) -> Option<f64> {
    if !valid_reports(reports) {
        return None;
    }

    let values: Vec<f64> = reports
        .iter()
        .map(|report| report.execution_time_ns as f64)
        .collect();

    statistics::median(&values)
}
