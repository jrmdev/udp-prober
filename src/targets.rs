use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

const MAX_EXPANDED_TARGETS_PER_ENTRY: u128 = 1 << 24;

#[derive(Clone, Debug)]
pub enum TargetInput {
    Args(Vec<String>),
    File(PathBuf),
}

#[derive(Clone, Debug)]
pub struct Blocklist {
    ranges: Vec<IpRangeBounds>,
}

#[derive(Clone, Debug)]
enum IpRangeBounds {
    V4 { start: u32, end: u32 },
    V6 { start: u128, end: u128 },
}

#[derive(Clone, Debug)]
enum TargetRange {
    V4 {
        current: u32,
        end: u32,
        done: bool,
    },
    V6 {
        current: u128,
        end: u128,
        done: bool,
    },
}

impl Blocklist {
    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn parse(entries: &[String]) -> Result<Self> {
        let mut ranges = Vec::new();
        for entry in entries {
            ranges.extend(parse_range(entry)?);
        }
        Ok(Self { ranges })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.ranges.iter().any(|range| range.contains(ip))
    }
}

pub struct TargetStream {
    sources: VecDeque<SourceState>,
    current_range: Option<TargetRange>,
}

enum SourceState {
    ArgQueue(VecDeque<String>),
    FileLines(io::Lines<BufReader<File>>),
}

impl TargetStream {
    pub fn new(inputs: Vec<TargetInput>) -> Result<Self> {
        let mut sources = VecDeque::new();
        for input in inputs {
            match input {
                TargetInput::Args(args) => {
                    sources.push_back(SourceState::ArgQueue(args.into()));
                }
                TargetInput::File(path) => {
                    let file = File::open(&path)?;
                    sources.push_back(SourceState::FileLines(BufReader::new(file).lines()));
                }
            }
        }
        Ok(Self {
            sources,
            current_range: None,
        })
    }
}

impl Iterator for TargetStream {
    type Item = Result<IpAddr>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(range) = self.current_range.as_mut() {
                let Some(ip) = range.next_ip() else {
                    self.current_range = None;
                    continue;
                };
                return Some(Ok(ip));
            }

            let source = self.sources.front_mut()?;
            let raw_line = match source {
                SourceState::ArgQueue(queue) => match queue.pop_front() {
                    Some(item) => item,
                    None => {
                        self.sources.pop_front();
                        continue;
                    }
                },
                SourceState::FileLines(lines) => match lines.next() {
                    Some(Ok(line)) => line,
                    Some(Err(error)) => return Some(Err(error.into())),
                    None => {
                        self.sources.pop_front();
                        continue;
                    }
                },
            };

            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            match parse_target(trimmed) {
                Ok(TargetSpec::Single(ip)) => return Some(Ok(ip)),
                Ok(TargetSpec::Range(range)) => {
                    self.current_range = Some(range);
                    continue;
                }
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

enum TargetSpec {
    Single(IpAddr),
    Range(TargetRange),
}

impl IpRangeBounds {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { start, end }, IpAddr::V4(ip)) => {
                let value = u32::from(ip);
                value >= *start && value <= *end
            }
            (Self::V6 { start, end }, IpAddr::V6(ip)) => {
                let value = u128::from(ip);
                value >= *start && value <= *end
            }
            _ => false,
        }
    }

    fn target_count(&self) -> u128 {
        match self {
            Self::V4 { start, end } => u128::from(*end - *start) + 1,
            Self::V6 { start, end } => *end - *start + 1,
        }
    }

    fn into_target_range(self) -> Result<TargetRange> {
        if self.target_count() > MAX_EXPANDED_TARGETS_PER_ENTRY {
            bail!(
                "target entry expands to more than {} addresses",
                MAX_EXPANDED_TARGETS_PER_ENTRY
            );
        }

        Ok(match self {
            Self::V4 { start, end } => TargetRange::V4 {
                current: start,
                end,
                done: false,
            },
            Self::V6 { start, end } => TargetRange::V6 {
                current: start,
                end,
                done: false,
            },
        })
    }
}

impl TargetRange {
    fn next_ip(&mut self) -> Option<IpAddr> {
        match self {
            Self::V4 { current, end, done } => {
                if *done {
                    return None;
                }
                let ip = IpAddr::V4(Ipv4Addr::from(*current));
                if *current == *end {
                    *done = true;
                } else {
                    *current += 1;
                }
                Some(ip)
            }
            Self::V6 { current, end, done } => {
                if *done {
                    return None;
                }
                let ip = IpAddr::V6(Ipv6Addr::from(*current));
                if *current == *end {
                    *done = true;
                } else {
                    *current += 1;
                }
                Some(ip)
            }
        }
    }
}

fn parse_target(input: &str) -> Result<TargetSpec> {
    if let Some((start, end)) = input.split_once('-') {
        let range = parse_ip_range(start, end, input)?;
        return Ok(TargetSpec::Range(range.into_target_range()?));
    }

    if let Some((ip, mask_len)) = input.split_once('/') {
        let range = parse_cidr(ip, mask_len, input)?;
        return Ok(TargetSpec::Range(range.into_target_range()?));
    }

    Ok(TargetSpec::Single(parse_ip(input)?))
}

fn parse_range(input: &str) -> Result<Vec<IpRangeBounds>> {
    Ok(vec![parse_target_range(input)?])
}

fn parse_target_range(input: &str) -> Result<IpRangeBounds> {
    if let Some((start, end)) = input.split_once('-') {
        return parse_ip_range(start, end, input);
    }

    if let Some((ip, mask_len)) = input.split_once('/') {
        return parse_cidr(ip, mask_len, input);
    }

    let ip = parse_ip(input)?;
    Ok(match ip {
        IpAddr::V4(ip) => IpRangeBounds::V4 {
            start: u32::from(ip),
            end: u32::from(ip),
        },
        IpAddr::V6(ip) => IpRangeBounds::V6 {
            start: u128::from(ip),
            end: u128::from(ip),
        },
    })
}

fn parse_ip(input: &str) -> Result<IpAddr> {
    input
        .parse::<IpAddr>()
        .map_err(|_| anyhow::anyhow!("invalid IP target `{input}`"))
}

fn parse_ip_range(start: &str, end: &str, raw: &str) -> Result<IpRangeBounds> {
    match (parse_ip(start)?, parse_ip(end)?) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let start = u32::from(start);
            let end = u32::from(end);
            if end < start {
                bail!("invalid IP range `{raw}`");
            }
            Ok(IpRangeBounds::V4 { start, end })
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            let start = u128::from(start);
            let end = u128::from(end);
            if end < start {
                bail!("invalid IP range `{raw}`");
            }
            Ok(IpRangeBounds::V6 { start, end })
        }
        _ => bail!("mixed-family IP range `{raw}` is not supported"),
    }
}

fn parse_cidr(ip: &str, mask_len: &str, raw: &str) -> Result<IpRangeBounds> {
    let mask_len = mask_len.parse::<u32>()?;
    match parse_ip(ip)? {
        IpAddr::V4(ip) => {
            if mask_len > 32 {
                bail!("CIDR mask out of supported range in `{raw}`");
            }
            let ip_value = u32::from(ip);
            let mask = if mask_len == 0 {
                0
            } else {
                u32::MAX << (32 - mask_len)
            };
            let start = ip_value & mask;
            let end = start | (!mask);
            Ok(IpRangeBounds::V4 { start, end })
        }
        IpAddr::V6(ip) => {
            if mask_len > 128 {
                bail!("CIDR mask out of supported range in `{raw}`");
            }
            let ip_value = u128::from(ip);
            let mask = if mask_len == 0 {
                0
            } else {
                u128::MAX << (128 - mask_len)
            };
            let start = ip_value & mask;
            let end = start | (!mask);
            Ok(IpRangeBounds::V6 { start, end })
        }
    }
}

pub fn ensure_target_inputs(args: &[String], file: &Option<PathBuf>) -> Result<Vec<TargetInput>> {
    if args.is_empty() && file.is_none() {
        bail!("provide targets or --targets-file");
    }
    if !args.is_empty() && file.is_some() {
        bail!("use either positional targets or --targets-file, not both");
    }

    let mut inputs = Vec::new();
    if !args.is_empty() {
        inputs.push(TargetInput::Args(args.to_vec()));
    }
    if let Some(file) = file {
        if !Path::new(file).exists() {
            bail!("targets file `{}` does not exist", file.display());
        }
        inputs.push(TargetInput::File(file.clone()));
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::{Blocklist, TargetInput, TargetStream, ensure_target_inputs};

    #[test]
    fn target_stream_expands_args() {
        let stream = TargetStream::new(vec![TargetInput::Args(vec![
            "127.0.0.1".into(),
            "127.0.0.2-127.0.0.3".into(),
            "127.0.0.4/31".into(),
        ])])
        .unwrap();
        let values = stream.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(values.len(), 5);
    }

    #[test]
    fn target_stream_reads_files() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# comment").unwrap();
        writeln!(file, "127.0.0.1").unwrap();
        writeln!(file, "127.0.0.2-127.0.0.3").unwrap();
        writeln!(file, "::1").unwrap();
        let stream = TargetStream::new(vec![TargetInput::File(file.path().to_path_buf())]).unwrap();
        let values = stream.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(values.len(), 4);
    }

    #[test]
    fn blocklist_supports_ipv4_and_ipv6_entries() {
        let blocklist = Blocklist::parse(&[
            "127.0.0.1".into(),
            "10.0.0.0/30".into(),
            "2001:db8::/126".into(),
        ])
        .unwrap();
        assert!(blocklist.contains("127.0.0.1".parse().unwrap()));
        assert!(blocklist.contains("10.0.0.2".parse().unwrap()));
        assert!(blocklist.contains("2001:db8::2".parse().unwrap()));
        assert!(!blocklist.contains("10.0.0.10".parse().unwrap()));
        assert!(!blocklist.contains("2001:db8::10".parse().unwrap()));
    }

    #[test]
    fn target_stream_supports_mixed_ipv4_and_ipv6_args() {
        let stream = TargetStream::new(vec![TargetInput::Args(vec![
            "127.0.0.1".into(),
            "::1".into(),
            "2001:db8::1-2001:db8::2".into(),
        ])])
        .unwrap();
        let values = stream.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(values.len(), 4);
        assert_eq!(values[0].to_string(), "127.0.0.1");
        assert_eq!(values[1].to_string(), "::1");
        assert_eq!(values[2].to_string(), "2001:db8::1");
        assert_eq!(values[3].to_string(), "2001:db8::2");
    }

    #[test]
    fn target_inputs_validate_exclusive_modes() {
        assert!(ensure_target_inputs(&["127.0.0.1".into()], &None).is_ok());
        assert!(ensure_target_inputs(&[], &Some("missing.txt".into())).is_err());
    }
}
