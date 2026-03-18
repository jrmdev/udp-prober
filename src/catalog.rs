use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use anyhow::{Result, anyhow, bail};

#[derive(Clone, Debug)]
pub struct ProbeDef {
    pub canonical: String,
    pub display_name: &'static str,
    pub aliases: Vec<String>,
    pub ports: Vec<u16>,
    pub payload: Arc<[u8]>,
    pub payload_hex: &'static str,
    pub rarity: u8,
    pub default_enabled: bool,
    pub safety_note: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct SelectedProbe {
    pub canonical: String,
    pub display_name: &'static str,
    pub port: u16,
    pub payload: Arc<[u8]>,
    pub payload_len: usize,
}

struct ProbeTemplate {
    display_name: &'static str,
    canonical_override: Option<&'static str>,
    extra_aliases: &'static [&'static str],
    ports: &'static str,
    payload_hex: &'static str,
    rarity: u8,
    default_enabled: bool,
    safety_note: Option<&'static str>,
    include_legacy_alias: bool,
}

pub fn probe_definitions() -> &'static [ProbeDef] {
    static DEFINITIONS: OnceLock<Vec<ProbeDef>> = OnceLock::new();
    DEFINITIONS.get_or_init(build_definitions).as_slice()
}

pub fn default_probe_count(rarity_max: u8) -> usize {
    probe_definitions()
        .iter()
        .filter(|definition| definition.default_enabled && definition.rarity <= rarity_max)
        .flat_map(|definition| definition.ports.iter())
        .count()
}

pub fn select_probes(
    rarity_max: u8,
    explicit_names: &[String],
    all_probes: bool,
) -> Result<Vec<SelectedProbe>> {
    if !(1..=9).contains(&rarity_max) {
        bail!("rarity-max must be between 1 and 9");
    }

    let definitions = probe_definitions();
    let alias_map = build_alias_map(definitions)?;
    let mut selected = BTreeMap::<(String, u16), SelectedProbe>::new();
    let include_all = all_probes
        || explicit_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("all"));

    if include_all {
        for definition in definitions {
            if definition.rarity > rarity_max {
                continue;
            }
            for &port in &definition.ports {
                selected.insert(
                    (definition.canonical.clone(), port),
                    SelectedProbe {
                        canonical: definition.canonical.clone(),
                        display_name: definition.display_name,
                        port,
                        payload: definition.payload.clone(),
                        payload_len: definition.payload.len(),
                    },
                );
            }
        }
    }

    for explicit_name in explicit_names {
        if explicit_name.eq_ignore_ascii_case("all") {
            continue;
        }

        let normalized = explicit_name.trim().to_ascii_lowercase();
        let Some(&definition_index) = alias_map.get(&normalized) else {
            bail!("unknown probe name `{explicit_name}`");
        };

        let definition = &definitions[definition_index];
        for &port in &definition.ports {
            selected.insert(
                (definition.canonical.clone(), port),
                SelectedProbe {
                    canonical: definition.canonical.clone(),
                    display_name: definition.display_name,
                    port,
                    payload: definition.payload.clone(),
                    payload_len: definition.payload.len(),
                },
            );
        }
    }

    if !include_all && explicit_names.is_empty() {
        for definition in definitions {
            if !definition.default_enabled || definition.rarity > rarity_max {
                continue;
            }
            for &port in &definition.ports {
                selected.insert(
                    (definition.canonical.clone(), port),
                    SelectedProbe {
                        canonical: definition.canonical.clone(),
                        display_name: definition.display_name,
                        port,
                        payload: definition.payload.clone(),
                        payload_len: definition.payload.len(),
                    },
                );
            }
        }
    }

    Ok(selected.into_values().collect())
}

pub fn find_probe_definition(name: &str) -> Result<&'static ProbeDef> {
    let definitions = probe_definitions();
    let alias_map = build_alias_map(definitions)?;
    let normalized = name.trim().to_ascii_lowercase();
    let Some(&index) = alias_map.get(&normalized) else {
        bail!("unknown probe name `{name}`");
    };
    Ok(&definitions[index])
}

fn build_alias_map(definitions: &[ProbeDef]) -> Result<BTreeMap<String, usize>> {
    let mut alias_map = BTreeMap::new();
    for (index, definition) in definitions.iter().enumerate() {
        for alias in std::iter::once(definition.canonical.as_str()).chain(
            definition
                .aliases
                .iter()
                .map(String::as_str)
                .filter(|alias| !alias.is_empty()),
        ) {
            let normalized = alias.trim().to_ascii_lowercase();
            match alias_map.entry(normalized) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(index);
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    return Err(anyhow!(
                        "duplicate probe alias `{}` between `{}` and `{}`",
                        alias,
                        definitions[*entry.get()].canonical,
                        definition.canonical
                    ));
                }
            }
        }
    }
    Ok(alias_map)
}

fn build_definitions() -> Vec<ProbeDef> {
    templates()
        .into_iter()
        .map(|template| {
            let canonical = template
                .canonical_override
                .map(str::to_owned)
                .unwrap_or_else(|| canonicalize_name(template.display_name));

            let mut aliases = BTreeSet::new();
            if template.include_legacy_alias {
                aliases.insert(template.display_name.to_ascii_lowercase());
            }
            for alias in template.extra_aliases {
                aliases.insert(alias.to_ascii_lowercase());
            }
            aliases.remove(&canonical);

            ProbeDef {
                canonical,
                display_name: template.display_name,
                aliases: aliases.into_iter().collect(),
                ports: expand_port_list(template.ports),
                payload: Arc::from(
                    hex::decode(template.payload_hex)
                        .unwrap_or_else(|error| panic!("invalid hex payload: {error}")),
                ),
                payload_hex: template.payload_hex,
                rarity: template.rarity,
                default_enabled: template.default_enabled,
                safety_note: template.safety_note,
            }
        })
        .collect()
}

fn expand_port_list(ports: &str) -> Vec<u16> {
    let mut values = Vec::new();
    for part in ports.split(',').filter(|part| !part.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let start = start.parse::<u16>().unwrap();
            let end = end.parse::<u16>().unwrap();
            values.extend(start..=end);
        } else {
            values.push(part.parse::<u16>().unwrap());
        }
    }
    values
}

fn canonicalize_name(name: &str) -> String {
    let mut words = Vec::<String>::new();
    let mut current = String::new();
    let chars = name.chars().collect::<Vec<_>>();

    for (index, ch) in chars.iter().copied().enumerate() {
        if matches!(ch, '-' | '_' | ' ' | '/') {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current).to_ascii_lowercase());
            }
            continue;
        }

        if !current.is_empty() {
            let prev = current.chars().last().unwrap();
            let next = chars.get(index + 1).copied();
            let current_is_acronym = current
                .chars()
                .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit());
            let split_before = (prev.is_ascii_lowercase() && ch.is_ascii_uppercase())
                || (prev.is_ascii_digit() && ch.is_ascii_uppercase())
                || (prev.is_ascii_uppercase()
                    && ch.is_ascii_uppercase()
                    && next.is_some_and(|next| next.is_ascii_lowercase()))
                || (prev.is_ascii_uppercase()
                    && ch.is_ascii_lowercase()
                    && current_is_acronym
                    && current.len() > 1);
            if split_before {
                words.push(std::mem::take(&mut current).to_ascii_lowercase());
            }
        }

        current.push(ch);
    }

    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }

    words.join("-")
}

fn templates() -> Vec<ProbeTemplate> {
    vec![
        ProbeTemplate {
            display_name: "ike",
            canonical_override: None,
            extra_aliases: &[],
            ports: "500",
            payload_hex: "5b5e64c03e99b51100000000000000000110020000000000000001500000013400000001000000010000012801010008030000240101",
            rarity: 1,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "echo",
            canonical_override: None,
            extra_aliases: &[],
            ports: "7",
            payload_hex: "313233",
            rarity: 3,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "systat",
            canonical_override: None,
            extra_aliases: &[],
            ports: "11",
            payload_hex: "313233",
            rarity: 3,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "daytime",
            canonical_override: None,
            extra_aliases: &[],
            ports: "13",
            payload_hex: "313233",
            rarity: 3,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "chargen",
            canonical_override: None,
            extra_aliases: &[],
            ports: "19",
            payload_hex: "313233",
            rarity: 3,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "time",
            canonical_override: None,
            extra_aliases: &[],
            ports: "37",
            payload_hex: "313233",
            rarity: 3,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "net-support",
            canonical_override: None,
            extra_aliases: &[],
            ports: "5405",
            payload_hex: "01000000000000000000000000000000000080000000000000000000000000000000000000",
            rarity: 6,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "gtpv1",
            canonical_override: None,
            extra_aliases: &[],
            ports: "2123",
            payload_hex: "320100040000000050000000",
            rarity: 6,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "l2tp",
            canonical_override: None,
            extra_aliases: &[],
            ports: "1701",
            payload_hex: "c8020060000000000000000080080000000000018008000000020100800a0000000300000001800a00000004000000000008000000060500800900000007776655000f000000084d6963726f736f6674800800000009000180080000000a0008",
            rarity: 2,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "rpc",
            canonical_override: None,
            extra_aliases: &[],
            ports: "111",
            payload_hex: "039b65420000000000000002000f4243000000000000000000000000000000000000000000000000",
            rarity: 1,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "ntp",
            canonical_override: None,
            extra_aliases: &[],
            ports: "123",
            payload_hex: "cb0004fa000100000001000000000000000000000000000000000000000000000000000000000000bfbe7099cdb34000",
            rarity: 1,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "snmp-public",
            canonical_override: None,
            extra_aliases: &[],
            ports: "161",
            payload_hex: "3082002f02010004067075626c6963a082002002044c33a756020100020100308200103082000c06082b060102010105000500",
            rarity: 1,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "ms-sql",
            canonical_override: None,
            extra_aliases: &[],
            ports: "1434",
            payload_hex: "02",
            rarity: 2,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "ms-sql-slam",
            canonical_override: None,
            extra_aliases: &[],
            ports: "1434",
            payload_hex: "0a",
            rarity: 6,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "netop",
            canonical_override: None,
            extra_aliases: &[],
            ports: "6502",
            payload_hex: "d6818152000000f3874e01023200a8c000000113c1d904dd037d00000d005448435448435448435448435448432020202020202020202020202020202020023200a8c00000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            rarity: 6,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "tftp-legacy",
            canonical_override: Some("tftp-legacy"),
            extra_aliases: &["tftp-old"],
            ports: "69",
            payload_hex: "00012f6574632f706173737764006e6574617363696900",
            rarity: 1,
            default_enabled: false,
            safety_note: Some(
                "Legacy RRQ requests /etc/passwd and is kept only for compatibility.",
            ),
            include_legacy_alias: false,
        },
        ProbeTemplate {
            display_name: "tftp",
            canonical_override: Some("tftp"),
            extra_aliases: &["tftp-safe"],
            ports: "69",
            payload_hex: "00017237746674702e747874006f6374657400",
            rarity: 1,
            default_enabled: true,
            safety_note: Some("Safe RRQ for a synthetic filename."),
            include_legacy_alias: false,
        },
        ProbeTemplate {
            display_name: "db2",
            canonical_override: None,
            extra_aliases: &[],
            ports: "523",
            payload_hex: "444232474554414444520053514c3038303230",
            rarity: 6,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "citrix",
            canonical_override: None,
            extra_aliases: &[],
            ports: "1604",
            payload_hex: "1e00013002fda8e300000000000000000000000000000000000000000000",
            rarity: 3,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "RPCCheck",
            canonical_override: None,
            extra_aliases: &[],
            ports: "111",
            payload_hex: "72fe1d130000000000000002000186a00001977c0000000000000000000000000000000000000000",
            rarity: 1,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "DNSVersionBindReq",
            canonical_override: None,
            extra_aliases: &[],
            ports: "53",
            payload_hex: "0006010000010000000000000776657273696f6e0462696e640000100003",
            rarity: 1,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Help",
            canonical_override: None,
            extra_aliases: &[],
            ports: "42",
            payload_hex: "68656c700d0a0d0a",
            rarity: 3,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "NBTStat",
            canonical_override: Some("nbt-stat"),
            extra_aliases: &[],
            ports: "137",
            payload_hex: "80f00010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001",
            rarity: 4,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "SNMPv1public",
            canonical_override: Some("snmp-v1-public"),
            extra_aliases: &[],
            ports: "161",
            payload_hex: "3082002f02010004067075626c6963a082002002044c33a756020100020100308200103082000c06082b060102010105000500",
            rarity: 4,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "SNMPv3GetRequest",
            canonical_override: Some("snmp-v3-get-request"),
            extra_aliases: &[],
            ports: "161",
            payload_hex: "303a020103300f02024a69020300ffe30401040201030410300e0400020100020100040004000400301204000400a00c020237f00201000201003000",
            rarity: 4,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "DNS-SD",
            canonical_override: None,
            extra_aliases: &[],
            ports: "5353",
            payload_hex: "000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001",
            rarity: 4,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "DNSStatusRequest",
            canonical_override: None,
            extra_aliases: &[],
            ports: "53",
            payload_hex: "000010000000000000000000",
            rarity: 5,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "SIPOptions",
            canonical_override: None,
            extra_aliases: &[],
            ports: "5060",
            payload_hex: "4f5054494f4e53207369703a6e6d205349502f322e300d0a5669613a205349502f322e302f554450206e6d3b6272616e63683d666f6f3b72706f72740d0a46726f6d3a203c7369703a6e6d406e6d3e3b7461673d726f6f740d0a546f3a203c7369703a6e6d32406e6d323e0d0a43616c6c2d49443a2035303030300d0a435365713a203432204f5054494f4e530d0a4d61782d466f7277617264733a2037300d0a436f6e74656e742d4c656e6774683a20300d0a436f6e746163743a203c7369703a6e6d406e6d3e0d0a4163636570743a206170706c69636174696f6e2f7364700d0a0d0a",
            rarity: 5,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "NTPRequest",
            canonical_override: None,
            extra_aliases: &[],
            ports: "123",
            payload_hex: "e30004fa000100000001000000000000000000000000000000000000000000000000000000000000c54f234b71b152f3",
            rarity: 5,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "AFSVersionRequest",
            canonical_override: None,
            extra_aliases: &[],
            ports: "7001",
            payload_hex: "000003e7000000000000006500000000000000000d0500000000000000000000",
            rarity: 5,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Citrix",
            canonical_override: Some("citrix-alt"),
            extra_aliases: &[],
            ports: "1604",
            payload_hex: "1e00013002fda8e300000000000000000000000000000000000000000000",
            rarity: 5,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: false,
        },
        ProbeTemplate {
            display_name: "Kerberos",
            canonical_override: None,
            extra_aliases: &[],
            ports: "88",
            payload_hex: "6a816e30816ba103020105a20302010aa4815e305ca00703050050800010a2041b024e4da3173015a003020100a10e300c1b066b72627467741b024e4da511180f31393730303130313030303030305aa70602041f1eb9d9a8173015020112020111020110020117020101020103020102",
            rarity: 5,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "DTLSSessionReq",
            canonical_override: None,
            extra_aliases: &[],
            ports: "443",
            payload_hex: "16feff000000000000000000360100002a000000000000002afefd000000007c77401e8ac822a0a018ff9308caac0a642fc92264bc08a81689193000000002002f0100",
            rarity: 5,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Sqlping",
            canonical_override: None,
            extra_aliases: &[],
            ports: "1434",
            payload_hex: "02",
            rarity: 6,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "xdmcp",
            canonical_override: None,
            extra_aliases: &[],
            ports: "177",
            payload_hex: "00010002000100",
            rarity: 6,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "QUIC",
            canonical_override: None,
            extra_aliases: &[],
            ports: "3310",
            payload_hex: "0d89c19c1c2afffcf15139393900",
            rarity: 6,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "sybaseanywhere",
            canonical_override: None,
            extra_aliases: &[],
            ports: "2638",
            payload_hex: "1b00003d0000000012434f4e4e454354494f4e4c4553535f544453000000010000040005000500000102000003010104080000000000000000070204b1",
            rarity: 7,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "NetMotionMobility",
            canonical_override: None,
            extra_aliases: &[],
            ports: "5008",
            payload_hex: "00405000000000855db491280000000000017c9140000000aa39da423765cf010000000000000000000000000000000000000000000000000000000000000000",
            rarity: 7,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "LDAPSearchReqUDP",
            canonical_override: None,
            extra_aliases: &[],
            ports: "389",
            payload_hex: "30840000002d02010763840000002404000a01000a0100020100020164010100870b6f626a656374436c617373308400000000",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "ibm-db2-das-udp",
            canonical_override: None,
            extra_aliases: &[],
            ports: "523",
            payload_hex: "444232474554414444520053514c303830313000",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "SqueezeCenter",
            canonical_override: None,
            extra_aliases: &[],
            ports: "3483",
            payload_hex: "6549504144004e414d45004a534f4e00564552530055554944004a56494406123456781234",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Quake2_status",
            canonical_override: None,
            extra_aliases: &[],
            ports: "27910-27914",
            payload_hex: "ffffffff737461747573",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Quake3_getstatus",
            canonical_override: None,
            extra_aliases: &[],
            ports: "26000-26004,27960-27964,30720-30724,44400",
            payload_hex: "ffffffff676574737461747573",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "serialnumberd",
            canonical_override: None,
            extra_aliases: &[],
            ports: "626",
            payload_hex: "534e51554552593a203132372e302e302e313a4141414141413a78737672",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "vuze-dht",
            canonical_override: None,
            extra_aliases: &[],
            ports: "17555,49152-49156",
            payload_hex: "fff0970d2e60d16f000004000055abec32000000000032040a00c875f816005cb965000000004ed1f528",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "pc-anywhere",
            canonical_override: None,
            extra_aliases: &[],
            ports: "5632",
            payload_hex: "4e51",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "pc-duo",
            canonical_override: None,
            extra_aliases: &[],
            ports: "1505",
            payload_hex: "00808008ff00",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "pc-duo-gw",
            canonical_override: None,
            extra_aliases: &[],
            ports: "2303",
            payload_hex: "20908008ff00",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "memcached-stats",
            canonical_override: Some("memcached-stats"),
            extra_aliases: &["memcached-legacy"],
            ports: "11211",
            payload_hex: "000100000001000073746174730d0a",
            rarity: 8,
            default_enabled: false,
            safety_note: Some("Legacy memcached stats request is kept only for compatibility."),
            include_legacy_alias: false,
        },
        ProbeTemplate {
            display_name: "memcached",
            canonical_override: Some("memcached"),
            extra_aliases: &["memcached-version"],
            ports: "11211",
            payload_hex: "000100000001000076657273696f6e0d0a",
            rarity: 6,
            default_enabled: false,
            safety_note: Some("Safer memcached version request."),
            include_legacy_alias: false,
        },
        ProbeTemplate {
            display_name: "svrloc",
            canonical_override: None,
            extra_aliases: &[],
            ports: "427",
            payload_hex: "0201000036200000000000010002656e00000015736572766963653a736572766963652d6167656e74000764656661756c7400000000",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "ARD",
            canonical_override: None,
            extra_aliases: &[],
            ports: "3283",
            payload_hex: "0014000103",
            rarity: 8,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Quake1_server_info",
            canonical_override: None,
            extra_aliases: &[],
            ports: "26000-26004",
            payload_hex: "8000000c025155414b450003",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Quake3_master_getservers",
            canonical_override: None,
            extra_aliases: &[],
            ports: "27950,30710",
            payload_hex: "ffffffff6765747365727665727320363820656d7074792066756c6c",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "BackOrifice",
            canonical_override: None,
            extra_aliases: &[],
            ports: "19150",
            payload_hex: "ce63d1d216e713cf38a5a586b2754b99aa3258",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Murmur",
            canonical_override: None,
            extra_aliases: &[],
            ports: "64738",
            payload_hex: "000000006162636465666768",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "Ventrilo",
            canonical_override: None,
            extra_aliases: &[],
            ports: "3784",
            payload_hex: "01e7e57531a3170b21cfbf2b994edd19acde085f8b240a1119b6736fad2813d20ab91275",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "TeamSpeak2",
            canonical_override: None,
            extra_aliases: &[],
            ports: "8767",
            payload_hex: "f4be03000000000000000000010000003278ba85095465616d537065616b00000000000000000000000000000000000000000a57696e646f7773205850000000000000000000000000000000000000000200000020003c000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086e69636b6e616d65000000000000000000000000000000000000000000",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "TeamSpeak3",
            canonical_override: None,
            extra_aliases: &[],
            ports: "9987",
            payload_hex: "05ca7f169c11f98900000000029d748b45aa7befb99efead0819bacf41e016a2326cf3cff48e3c4483c88d51456f9095233e00972b1c71b24ec061f1d76fc57ef64852bf826aa23b65aa187a1738c38127c347fca735bafc0f9d9d72249dfc02176d6bb12d72c6e3171c95d9699957cedddf05dc039456043a14e5ad9a2b14303a23a325ade8e6398a852ac6dfe55d2da02f5d9cd72b24fbb09cc2ba89b41b17a2b6",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "FreelancerStatus",
            canonical_override: None,
            extra_aliases: &[],
            ports: "2302",
            payload_hex: "0002f1260126f090a6f026574eaca0ecf868e48d21",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "ASE",
            canonical_override: None,
            extra_aliases: &[],
            ports: "1258,2126,3123,12444,13200,23196,26000,27138,27244,27777,28138",
            payload_hex: "73",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "AndroMouse",
            canonical_override: None,
            extra_aliases: &[],
            ports: "8888",
            payload_hex: "414d534e494646",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "AirHID",
            canonical_override: None,
            extra_aliases: &[],
            ports: "13246",
            payload_hex: "66726f6d3a616972686964",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "OpenVPN",
            canonical_override: None,
            extra_aliases: &[],
            ports: "1194",
            payload_hex: "3864c17801b89bcb8f0000000000",
            rarity: 9,
            default_enabled: true,
            safety_note: Some("Unauthenticated packet-auth OpenVPN listeners may stay silent."),
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "ipmi-rmcp",
            canonical_override: None,
            extra_aliases: &[],
            ports: "623",
            payload_hex: "0600ff07000000000000000000092018c88100388e04b5",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "coap-request",
            canonical_override: None,
            extra_aliases: &[],
            ports: "5683",
            payload_hex: "400101cebb2e77656c6c2d6b6e6f776e04636f7265",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "UbiquitiDiscoveryv1",
            canonical_override: None,
            extra_aliases: &[],
            ports: "10001",
            payload_hex: "01000000",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "UbiquitiDiscoveryv2",
            canonical_override: None,
            extra_aliases: &[],
            ports: "10001",
            payload_hex: "02080000",
            rarity: 9,
            default_enabled: true,
            safety_note: None,
            include_legacy_alias: true,
        },
        ProbeTemplate {
            display_name: "stun-bind",
            canonical_override: Some("stun-bind"),
            extra_aliases: &["STUN_BIND"],
            ports: "3478",
            payload_hex: "000100002112a442000000000000000000000000",
            rarity: 6,
            default_enabled: true,
            safety_note: Some("Safe STUN binding request built from RFC 5389."),
            include_legacy_alias: false,
        },
        ProbeTemplate {
            display_name: "nat-pmp-addr",
            canonical_override: Some("nat-pmp-addr"),
            extra_aliases: &["NAT_PMP_ADDR"],
            ports: "5351",
            payload_hex: "0000",
            rarity: 6,
            default_enabled: true,
            safety_note: Some("NAT-PMP public address request."),
            include_legacy_alias: false,
        },
        ProbeTemplate {
            display_name: "nfs-null",
            canonical_override: Some("nfs-null"),
            extra_aliases: &["NFSPROC_NULL"],
            ports: "2049",
            payload_hex: "000000000000000000000002000186a3000000020000000000000000000000000000000000000000",
            rarity: 6,
            default_enabled: true,
            safety_note: Some("Safe ONC RPC NULL call for NFS service discovery."),
            include_legacy_alias: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_name, default_probe_count, find_probe_definition, select_probes};

    #[test]
    fn canonicalization_handles_mixed_probe_names() {
        assert_eq!(
            canonicalize_name("DNSVersionBindReq"),
            "dns-version-bind-req"
        );
        assert_eq!(canonicalize_name("NTPRequest"), "ntp-request");
        assert_eq!(
            canonicalize_name("UbiquitiDiscoveryv1"),
            "ubiquiti-discoveryv1"
        );
        assert_eq!(canonicalize_name("coap-request"), "coap-request");
    }

    #[test]
    fn default_counts_match_plan() {
        assert_eq!(default_probe_count(6), 38);
    }

    #[test]
    fn explicit_probe_selection_is_case_insensitive() {
        let probes = select_probes(
            6,
            &["NBTStat".to_string(), "dns-version-bind-req".to_string()],
            false,
        )
        .unwrap();
        assert_eq!(probes.len(), 2);
    }

    #[test]
    fn list_and_show_resolve_aliases() {
        let probe = find_probe_definition("NTPRequest").unwrap();
        assert_eq!(probe.canonical, "ntp-request");
    }

    #[test]
    fn openvpn_probe_targets_standard_udp_port() {
        let probe = find_probe_definition("openvpn").unwrap();
        assert_eq!(probe.canonical, "open-vpn");
        assert_eq!(probe.ports, vec![1194]);
        assert_eq!(
            probe.safety_note,
            Some("Unauthenticated packet-auth OpenVPN listeners may stay silent.")
        );
    }
}
