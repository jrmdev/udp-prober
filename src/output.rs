use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const XML_OUTPUT_VERSION: &str = "1.05-udp-prober";

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum OutputFormat {
    Human,
    Jsonl,
    Xml,
}

#[derive(Clone, Debug)]
pub struct OutputMetadata {
    pub command_line: String,
    pub started_at: SystemTime,
    pub selected_ports: Vec<u16>,
}

#[derive(Clone, Debug)]
pub enum ScanEvent {
    Hit(HitEvent),
    Warning(WarningEvent),
}

#[derive(Clone, Debug)]
pub struct HitEvent {
    pub probe: String,
    pub display_name: String,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub reply_hex: String,
    pub rtt: Duration,
}

#[derive(Clone, Debug)]
pub struct WarningEvent {
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanSummary {
    pub targets_scanned: u64,
    pub probes_selected: usize,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub hits: u64,
    pub warnings: u64,
    pub unexpected_replies: u64,
    pub scan_duration_ms: u128,
}

#[derive(Default)]
struct XmlBuffer {
    hits: Vec<HitEvent>,
    warnings: Vec<String>,
}

pub struct OutputWriter {
    format: OutputFormat,
    metadata: OutputMetadata,
    stdout: io::Stdout,
    xml_buffer: XmlBuffer,
}

impl OutputWriter {
    pub fn new(format: OutputFormat, metadata: OutputMetadata) -> Self {
        Self {
            format,
            metadata,
            stdout: io::stdout(),
            xml_buffer: XmlBuffer::default(),
        }
    }

    pub fn write_event(&mut self, event: &ScanEvent) -> io::Result<()> {
        match self.format {
            OutputFormat::Human => match event {
                ScanEvent::Hit(hit) => writeln!(
                    self.stdout,
                    "hit probe={} target={}:{} reply-from={}:{} rtt_ms={} data={}",
                    hit.probe,
                    hit.target_ip,
                    hit.target_port,
                    hit.source_ip,
                    hit.source_port,
                    hit.rtt.as_millis(),
                    hit.reply_hex
                ),
                ScanEvent::Warning(warning) => writeln!(self.stdout, "warning {}", warning.message),
            },
            OutputFormat::Jsonl => {
                let value = match event {
                    ScanEvent::Hit(hit) => serde_json::json!({
                        "type": "hit",
                        "probe": hit.probe,
                        "display_name": hit.display_name,
                        "target_ip": hit.target_ip,
                        "target_port": hit.target_port,
                        "source_ip": hit.source_ip,
                        "source_port": hit.source_port,
                        "rtt_ms": hit.rtt.as_millis(),
                        "reply_hex": hit.reply_hex,
                    }),
                    ScanEvent::Warning(warning) => serde_json::json!({
                        "type": "warning",
                        "message": warning.message,
                    }),
                };
                writeln!(self.stdout, "{}", serde_json::to_string(&value).unwrap())
            }
            OutputFormat::Xml => {
                match event {
                    ScanEvent::Hit(hit) => self.xml_buffer.hits.push(hit.clone()),
                    ScanEvent::Warning(warning) => {
                        self.xml_buffer.warnings.push(warning.message.clone())
                    }
                }
                Ok(())
            }
        }
    }

    pub fn write_summary(&mut self, summary: &ScanSummary) -> io::Result<()> {
        match self.format {
            OutputFormat::Human => writeln!(
                self.stdout,
                "summary targets={} probes={} packets_sent={} bytes_sent={} hits={} warnings={} unexpected_replies={} duration_ms={}",
                summary.targets_scanned,
                summary.probes_selected,
                summary.packets_sent,
                summary.bytes_sent,
                summary.hits,
                summary.warnings,
                summary.unexpected_replies,
                summary.scan_duration_ms
            ),
            OutputFormat::Jsonl => writeln!(
                self.stdout,
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "type": "summary",
                    "targets_scanned": summary.targets_scanned,
                    "probes_selected": summary.probes_selected,
                    "packets_sent": summary.packets_sent,
                    "bytes_sent": summary.bytes_sent,
                    "hits": summary.hits,
                    "warnings": summary.warnings,
                    "unexpected_replies": summary.unexpected_replies,
                    "scan_duration_ms": summary.scan_duration_ms,
                }))
                .unwrap()
            ),
            OutputFormat::Xml => self.write_xml(summary),
        }
    }

    fn write_xml(&mut self, summary: &ScanSummary) -> io::Result<()> {
        let xml = render_xml_document(&self.metadata, &self.xml_buffer, summary);
        self.stdout.write_all(xml.as_bytes())
    }
}

fn render_xml_document(
    metadata: &OutputMetadata,
    xml_buffer: &XmlBuffer,
    summary: &ScanSummary,
) -> String {
    let mut xml = String::new();
    let finished_at = metadata
        .started_at
        .checked_add(Duration::from_millis(summary.scan_duration_ms as u64))
        .unwrap_or(metadata.started_at);
    let (start_epoch, start_str) = format_timestamp(metadata.started_at);
    let (finish_epoch, finish_str) = format_timestamp(finished_at);
    let ports = compress_ports(&metadata.selected_ports);
    let numservices = count_unique_ports(&metadata.selected_ports);
    let mut hosts = BTreeMap::<IpAddr, BTreeMap<u16, Vec<&HitEvent>>>::new();
    for hit in &xml_buffer.hits {
        hosts
            .entry(hit.target_ip)
            .or_default()
            .entry(hit.target_port)
            .or_default()
            .push(hit);
    }
    let hosts_up = hosts.len() as u64;
    let hosts_down = summary.targets_scanned.saturating_sub(hosts_up);
    let elapsed_seconds = summary.scan_duration_ms as f64 / 1000.0;
    let finished_summary = format!(
        "udp-prober done at {}; {} IP address{} ({} host{} up) scanned in {:.2} seconds",
        finish_str,
        summary.targets_scanned,
        suffix(summary.targets_scanned, "es"),
        hosts_up,
        suffix(hosts_up, "s"),
        elapsed_seconds
    );

    writeln!(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>").unwrap();
    writeln!(
        xml,
        "<nmaprun scanner=\"udp-prober\" args=\"{}\" start=\"{}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"{}\">",
        escape_xml_attr(&metadata.command_line),
        start_epoch,
        escape_xml_attr(&start_str),
        env!("CARGO_PKG_VERSION"),
        XML_OUTPUT_VERSION
    )
    .unwrap();
    writeln!(
        xml,
        "  <scaninfo type=\"udp\" protocol=\"udp\" numservices=\"{}\" services=\"{}\"/>",
        numservices,
        escape_xml_attr(&ports)
    )
    .unwrap();
    writeln!(xml, "  <verbose level=\"0\"/>").unwrap();
    writeln!(xml, "  <debugging level=\"0\"/>").unwrap();

    if !xml_buffer.warnings.is_empty() {
        let warning_text = xml_buffer
            .warnings
            .iter()
            .map(|warning| format!("warning {warning}"))
            .collect::<Vec<_>>()
            .join("\n");
        writeln!(
            xml,
            "  <output type=\"interactive\">{}</output>",
            escape_xml_text(&warning_text)
        )
        .unwrap();
    }

    for (host_ip, ports) in hosts {
        writeln!(
            xml,
            "  <host starttime=\"{}\" endtime=\"{}\">",
            start_epoch, finish_epoch
        )
        .unwrap();
        writeln!(
            xml,
            "    <status state=\"up\" reason=\"udp-response\" reason_ttl=\"0\"/>"
        )
        .unwrap();
        writeln!(
            xml,
            "    <address addr=\"{}\" addrtype=\"{}\"/>",
            host_ip,
            xml_addr_type(host_ip)
        )
        .unwrap();
        writeln!(xml, "    <ports>").unwrap();

        for (port, hits) in ports {
            writeln!(xml, "      <port protocol=\"udp\" portid=\"{}\">", port).unwrap();
            writeln!(
                xml,
                "        <state state=\"open\" reason=\"udp-response\" reason_ttl=\"0\"/>"
            )
            .unwrap();
            writeln!(
                xml,
                "        <service name=\"udp-response\" method=\"probed\" conf=\"3\"/>"
            )
            .unwrap();

            for hit in hits {
                let script_id = format!("udp-prober-{}", hit.probe);
                let script_output = format!(
                    "probe={} display_name={} source={}:{} rtt_ms={} reply_hex={}",
                    hit.probe,
                    hit.display_name,
                    hit.source_ip,
                    hit.source_port,
                    hit.rtt.as_millis(),
                    hit.reply_hex
                );
                writeln!(
                    xml,
                    "        <script id=\"{}\" output=\"{}\"/>",
                    escape_xml_attr(&script_id),
                    escape_xml_attr(&script_output)
                )
                .unwrap();
            }

            writeln!(xml, "      </port>").unwrap();
        }

        writeln!(xml, "    </ports>").unwrap();
        writeln!(xml, "  </host>").unwrap();
    }

    writeln!(xml, "  <runstats>").unwrap();
    writeln!(
        xml,
        "    <finished time=\"{}\" timestr=\"{}\" elapsed=\"{:.2}\" summary=\"{}\" exit=\"success\"/>",
        finish_epoch,
        escape_xml_attr(&finish_str),
        elapsed_seconds,
        escape_xml_attr(&finished_summary)
    )
    .unwrap();
    writeln!(
        xml,
        "    <hosts up=\"{}\" down=\"{}\" total=\"{}\"/>",
        hosts_up, hosts_down, summary.targets_scanned
    )
    .unwrap();
    writeln!(xml, "  </runstats>").unwrap();
    writeln!(xml, "</nmaprun>").unwrap();
    xml
}

fn count_unique_ports(ports: &[u16]) -> usize {
    ports.iter().copied().collect::<BTreeSet<_>>().len()
}

fn compress_ports(ports: &[u16]) -> String {
    let mut values = ports.iter().copied().collect::<BTreeSet<_>>().into_iter();
    let Some(mut start) = values.next() else {
        return String::new();
    };
    let mut end = start;
    let mut ranges = Vec::new();

    for value in values {
        if value == end.saturating_add(1) {
            end = value;
            continue;
        }
        ranges.push(render_range(start, end));
        start = value;
        end = value;
    }
    ranges.push(render_range(start, end));
    ranges.join(",")
}

fn render_range(start: u16, end: u16) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn format_timestamp(timestamp: SystemTime) -> (u64, String) {
    let unix = timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let formatted = OffsetDateTime::from_unix_timestamp(unix as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    (unix, formatted)
}

fn suffix(count: u64, plural: &'static str) -> &'static str {
    if count == 1 { "" } else { plural }
}

fn escape_xml_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn escape_xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_addr_type(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::{
        HitEvent, OutputMetadata, ScanSummary, XmlBuffer, compress_ports, count_unique_ports,
        render_xml_document,
    };

    #[test]
    fn compress_ports_merges_consecutive_values() {
        assert_eq!(compress_ports(&[53, 54, 55, 69, 111, 111]), "53-55,69,111");
    }

    #[test]
    fn count_unique_ports_deduplicates_values() {
        assert_eq!(count_unique_ports(&[53, 53, 69]), 2);
    }

    #[test]
    fn xml_rendering_escapes_warnings_and_args() {
        let xml = render_xml_document(
            &OutputMetadata {
                command_line: "udp-prober scan --format xml \"host<&>\"".to_string(),
                started_at: UNIX_EPOCH + Duration::from_secs(1),
                selected_ports: vec![53],
            },
            &XmlBuffer {
                hits: vec![HitEvent {
                    probe: "dns-version-bind-req".to_string(),
                    display_name: "DNS<Bind>".to_string(),
                    target_ip: "127.0.0.1".parse().unwrap(),
                    target_port: 53,
                    source_ip: "127.0.0.1".parse().unwrap(),
                    source_port: 53,
                    reply_hex: "aa55".to_string(),
                    rtt: Duration::from_millis(12),
                }],
                warnings: vec!["warn <this> & \"that\"".to_string()],
            },
            &ScanSummary {
                targets_scanned: 1,
                probes_selected: 1,
                packets_sent: 1,
                bytes_sent: 64,
                hits: 1,
                warnings: 1,
                unexpected_replies: 0,
                scan_duration_ms: 100,
            },
        );

        assert!(
            xml.contains("args=\"udp-prober scan --format xml &quot;host&lt;&amp;&gt;&quot;\"")
        );
        assert!(xml.contains(
            "<output type=\"interactive\">warning warn &lt;this&gt; &amp; \"that\"</output>"
        ));
        assert!(xml.contains("display_name=DNS&lt;Bind&gt;"));
    }

    #[test]
    fn xml_rendering_groups_multiple_probe_hits_under_one_port() {
        let xml = render_xml_document(
            &OutputMetadata {
                command_line: "udp-prober scan --format xml 127.0.0.1".to_string(),
                started_at: UNIX_EPOCH + Duration::from_secs(1),
                selected_ports: vec![1604, 1604, 5405],
            },
            &XmlBuffer {
                hits: vec![
                    HitEvent {
                        probe: "citrix".to_string(),
                        display_name: "citrix".to_string(),
                        target_ip: "127.0.0.1".parse().unwrap(),
                        target_port: 1604,
                        source_ip: "127.0.0.1".parse().unwrap(),
                        source_port: 1604,
                        reply_hex: "aa".to_string(),
                        rtt: Duration::from_millis(5),
                    },
                    HitEvent {
                        probe: "citrix-alt".to_string(),
                        display_name: "citrix-alt".to_string(),
                        target_ip: "127.0.0.1".parse().unwrap(),
                        target_port: 1604,
                        source_ip: "127.0.0.1".parse().unwrap(),
                        source_port: 1604,
                        reply_hex: "bb".to_string(),
                        rtt: Duration::from_millis(6),
                    },
                    HitEvent {
                        probe: "net-support".to_string(),
                        display_name: "net-support".to_string(),
                        target_ip: "127.0.0.1".parse().unwrap(),
                        target_port: 5405,
                        source_ip: "127.0.0.1".parse().unwrap(),
                        source_port: 5405,
                        reply_hex: "cc".to_string(),
                        rtt: Duration::from_millis(7),
                    },
                ],
                warnings: Vec::new(),
            },
            &ScanSummary {
                targets_scanned: 1,
                probes_selected: 3,
                packets_sent: 3,
                bytes_sent: 192,
                hits: 3,
                warnings: 0,
                unexpected_replies: 0,
                scan_duration_ms: 100,
            },
        );

        assert_eq!(
            xml.matches("<port protocol=\"udp\" portid=\"1604\">")
                .count(),
            1
        );
        assert!(xml.contains("id=\"udp-prober-citrix\""));
        assert!(xml.contains("id=\"udp-prober-citrix-alt\""));
        assert!(xml.contains("id=\"udp-prober-net-support\""));
    }

    #[test]
    fn xml_rendering_marks_ipv6_hosts_with_ipv6_addrtype() {
        let xml = render_xml_document(
            &OutputMetadata {
                command_line: "udp-prober scan ::1".to_string(),
                started_at: UNIX_EPOCH + Duration::from_secs(1),
                selected_ports: vec![53],
            },
            &XmlBuffer {
                hits: vec![HitEvent {
                    probe: "dns-version-bind-req".to_string(),
                    display_name: "dns".to_string(),
                    target_ip: "::1".parse().unwrap(),
                    target_port: 53,
                    source_ip: "::1".parse().unwrap(),
                    source_port: 53,
                    reply_hex: "aa55".to_string(),
                    rtt: Duration::from_millis(12),
                }],
                warnings: Vec::new(),
            },
            &ScanSummary {
                targets_scanned: 1,
                probes_selected: 1,
                packets_sent: 1,
                bytes_sent: 84,
                hits: 1,
                warnings: 0,
                unexpected_replies: 0,
                scan_duration_ms: 100,
            },
        );

        assert!(xml.contains("<address addr=\"::1\" addrtype=\"ipv6\"/>"));
    }
}
