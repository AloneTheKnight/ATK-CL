use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use tempfile::NamedTempFile;
use zeroize::Zeroizing;

pub fn read_file(path: &str) -> io::Result<Vec<u8>> {
    fs::read(path)
}

pub fn read_file_limited(path: &str, max_size: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let file = fs::File::open(path)?;
    let limit = u64::try_from(max_size).unwrap_or(u64::MAX);

    let mut reader = file.take(limit.saturating_add(1));
    let mut data = Zeroizing::new(Vec::new());

    reader.read_to_end(&mut data)?;

    if data.len() > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("File exceeds the maximum allowed size of {max_size} bytes"),
        ));
    }

    Ok(data)
}

pub fn paths_refer_to_same_file(input: &str, output: &str) -> io::Result<bool> {
    let input_path = fs::canonicalize(input)?;
    let output_path = Path::new(output);

    match fs::metadata(output_path) {
        Ok(_) => same_file::is_same_file(input, output),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let file_name = output_path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Invalid output file path")
            })?;

            let parent = output_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));

            let canonical_output = fs::canonicalize(parent)?.join(file_name);

            Ok(input_path == canonical_output)
        }
        Err(error) => Err(error),
    }
}

fn create_temp_file(path: &str, data: &[u8]) -> io::Result<NamedTempFile> {
    let output_path = Path::new(path);

    if output_path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid output file path",
        ));
    }

    let parent = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut temp_file = NamedTempFile::new_in(parent)?;
    temp_file.write_all(data)?;
    temp_file.as_file().sync_all()?;

    Ok(temp_file)
}

pub fn write_file_new(path: &str, data: &[u8]) -> io::Result<()> {
    create_temp_file(path, data)?
        .persist_noclobber(path)
        .map(|_| ())
        .map_err(|error| error.error)
}

pub fn write_file_replace(path: &str, data: &[u8]) -> io::Result<()> {
    create_temp_file(path, data)?
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
}

pub fn write_file(path: &str, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)
}
