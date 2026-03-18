use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use crossbeam_channel::unbounded;

use crate::catalog::{
    default_probe_count, find_probe_definition, probe_definitions, select_probes,
};
use crate::output::{OutputFormat, OutputMetadata, OutputWriter};
use crate::scan::{ScanConfig, run_scan};
use crate::targets::{Blocklist, ensure_target_inputs};

#[derive(Parser)]
#[command(
    name = "udp-prober",
    version,
    about = "UDP protocol-aware probe scanner"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan(ScanArgs),
    Probes(ProbesCommand),
}

#[derive(Args)]
struct ScanArgs {
    /// IPv4/IPv6 address, range, or CIDR target. Positional targets may mix families.
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,
    /// Read newline-delimited IPv4/IPv6 targets from a file. Entries may mix families.
    #[arg(long = "targets-file")]
    targets_file: Option<PathBuf>,
    /// Select one or more specific probes by canonical name.
    #[arg(long = "probe", value_name = "NAME")]
    probes: Vec<String>,
    /// Enable the full probe catalog instead of the default set.
    #[arg(long = "all-probes")]
    all_probes: bool,
    /// Only include probes with rarity at or below this value.
    #[arg(long = "rarity-max", default_value_t = 6)]
    rarity_max: u8,
    /// Cap aggregate send bandwidth. Supports k, M, and G suffixes.
    #[arg(long = "bandwidth", default_value = "250k")]
    bandwidth: String,
    /// Cap aggregate packet rate directly.
    #[arg(long = "pps")]
    packets_per_second: Option<String>,
    /// Pace retry packets globally per second.
    #[arg(long = "retry-pps", default_value_t = 2)]
    retry_packets_per_second: u32,
    /// Retry count after the first send.
    #[arg(long = "retries", default_value_t = 2)]
    retries: u32,
    /// Wait window for replies, such as 500ms or 1s.
    #[arg(long = "rtt", default_value = "1s")]
    rtt: String,
    /// Skip IPv4/IPv6 addresses, ranges, or CIDR blocks.
    #[arg(long = "blocklist", value_name = "TARGET")]
    blocklist: Vec<String>,
    /// Worker thread count.
    #[arg(long = "threads", default_value_t = 4)]
    threads: usize,
    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(Subcommand)]
enum ProbesSubcommand {
    List,
    Show { name: String },
}

#[derive(Args)]
struct ProbesCommand {
    #[command(subcommand)]
    command: ProbesSubcommand,
}

pub fn run() -> Result<()> {
    let command_line = capture_command_line();
    match Cli::parse().command {
        Commands::Scan(args) => run_scan_command(args, command_line),
        Commands::Probes(command) => run_probes_command(command),
    }
}

fn run_scan_command(args: ScanArgs, command_line: String) -> Result<()> {
    let selected_probes = select_probes(args.rarity_max, &args.probes, args.all_probes)?;
    let target_inputs = ensure_target_inputs(&args.targets, &args.targets_file)?;
    let blocklist = if args.blocklist.is_empty() {
        Blocklist::empty()
    } else {
        Blocklist::parse(&args.blocklist)?
    };
    let bandwidth_bits_per_second = parse_scaled_integer(&args.bandwidth)?;
    let packets_per_second = args
        .packets_per_second
        .as_deref()
        .map(parse_scaled_integer)
        .transpose()?;
    let rtt = parse_duration(&args.rtt)?;
    let threads = args.threads.max(1);

    let output_metadata = OutputMetadata {
        command_line,
        started_at: SystemTime::now(),
        selected_ports: selected_probes.iter().map(|probe| probe.port).collect(),
    };
    let config = ScanConfig {
        selected_probes,
        target_inputs,
        blocklist,
        bandwidth_bits_per_second,
        packets_per_second,
        retry_packets_per_second: args.retry_packets_per_second.max(1),
        retries: args.retries,
        rtt,
        threads,
    };

    let (events_tx, events_rx) = unbounded();
    let format = args.format;
    let handle = thread::spawn(move || run_scan(config, events_tx));
    let mut writer = OutputWriter::new(format, output_metadata);
    for event in &events_rx {
        writer.write_event(&event)?;
    }

    let summary = handle
        .join()
        .map_err(|_| anyhow::anyhow!("scan thread panicked"))??;
    writer.write_summary(&summary)?;
    Ok(())
}

fn run_probes_command(command: ProbesCommand) -> Result<()> {
    match command.command {
        ProbesSubcommand::List => {
            for definition in probe_definitions() {
                println!(
                    "{}\trarities<= {}\tports={}\tdefault={}",
                    definition.canonical,
                    definition.rarity,
                    join_ports(&definition.ports),
                    definition.default_enabled
                );
            }
            println!("defaults={}", default_probe_count(6));
        }
        ProbesSubcommand::Show { name } => {
            let definition = find_probe_definition(&name)?;
            println!("canonical: {}", definition.canonical);
            println!("display: {}", definition.display_name);
            if !definition.aliases.is_empty() {
                println!("aliases: {}", definition.aliases.join(", "));
            }
            println!("rarity: {}", definition.rarity);
            println!("ports: {}", join_ports(&definition.ports));
            println!("default: {}", definition.default_enabled);
            println!("payload bytes: {}", definition.payload.len());
            println!("payload hex: {}", definition.payload_hex);
            if let Some(note) = definition.safety_note {
                println!("safety note: {note}");
            }
        }
    }
    Ok(())
}

fn parse_scaled_integer(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("empty numeric value");
    }

    let (digits, multiplier) = match trimmed.chars().last().unwrap() {
        'k' | 'K' => (&trimmed[..trimmed.len() - 1], 1_000_u64),
        'm' | 'M' => (&trimmed[..trimmed.len() - 1], 1_000_000_u64),
        'g' | 'G' => (&trimmed[..trimmed.len() - 1], 1_000_000_000_u64),
        _ => (trimmed, 1_u64),
    };

    let value = digits
        .parse::<u64>()
        .with_context(|| format!("invalid numeric value `{input}`"))?;
    Ok(value * multiplier)
}

fn parse_duration(input: &str) -> Result<Duration> {
    let trimmed = input.trim();
    if let Some(value) = trimmed.strip_suffix("ms") {
        return Ok(Duration::from_millis(
            value
                .parse::<u64>()
                .with_context(|| format!("invalid duration `{input}`"))?,
        ));
    }
    if let Some(value) = trimmed.strip_suffix('s') {
        return Ok(Duration::from_secs_f64(
            value
                .parse::<f64>()
                .with_context(|| format!("invalid duration `{input}`"))?,
        ));
    }
    Ok(Duration::from_secs_f64(
        trimmed
            .parse::<f64>()
            .with_context(|| format!("invalid duration `{input}`"))?,
    ))
}

fn capture_command_line() -> String {
    std::env::args_os()
        .map(|arg| shell_quote_arg(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':'))
    {
        return arg.to_string();
    }

    let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{parse_duration, parse_scaled_integer};

    #[test]
    fn parse_scaled_values_supports_suffixes() {
        assert_eq!(parse_scaled_integer("250k").unwrap(), 250_000);
        assert_eq!(parse_scaled_integer("3M").unwrap(), 3_000_000);
        assert_eq!(parse_scaled_integer("7").unwrap(), 7);
    }

    #[test]
    fn parse_duration_supports_seconds_and_millis() {
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("0.5").unwrap(), Duration::from_millis(500));
    }
}
