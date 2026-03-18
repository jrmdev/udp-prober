use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender, bounded};
use mio::event::Event;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::catalog::SelectedProbe;
use crate::output::{HitEvent, ScanEvent, ScanSummary, WarningEvent};
use crate::rate_limiter::SharedRateLimiter;
use crate::targets::{Blocklist, TargetInput, TargetStream};

const IPV4_PACKET_OVERHEAD_BYTES: usize = 42;
const IPV6_PACKET_OVERHEAD_BYTES: usize = 62;
const SOCKET_BUFFER_BYTES: usize = 1_000_000;
const MAX_INFLIGHT_STATES_PER_WORKER: usize = 16_384;
const SOCKET_RECV_BUFFER_BYTES: usize = 65_535;

#[derive(Clone)]
pub struct ScanConfig {
    pub selected_probes: Vec<SelectedProbe>,
    pub target_inputs: Vec<TargetInput>,
    pub blocklist: Blocklist,
    pub bandwidth_bits_per_second: u64,
    pub packets_per_second: Option<u64>,
    pub retry_packets_per_second: u32,
    pub retries: u32,
    pub rtt: Duration,
    pub threads: usize,
}

#[derive(Default)]
struct DispatcherStats {
    targets_scanned: u64,
}

#[derive(Default)]
struct WorkerStats {
    packets_sent: u64,
    bytes_sent: u64,
    hits: u64,
    warnings: u64,
    unexpected_replies: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ReplyKey {
    probe_index: usize,
    target_ip: IpAddr,
    source_port: u16,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ScheduleKind {
    Send,
    Expire,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScheduledAction {
    when: Instant,
    state_id: u64,
    generation: u64,
    kind: ScheduleKind,
}

#[derive(Debug)]
struct ProbeState {
    target_ip: IpAddr,
    probe_index: usize,
    attempts_sent: u32,
    generation: u64,
    last_sent_at: Option<Instant>,
    reserved_send_at: Option<Instant>,
}

struct ProbeSockets {
    ipv4: UdpSocket,
    ipv6: UdpSocket,
}

#[derive(Clone, Copy)]
enum SocketFamily {
    V4,
    V6,
}

struct WorkerContext {
    worker_id: usize,
    config: Arc<ScanConfig>,
    rate_limiter: Arc<SharedRateLimiter>,
    events: Sender<ScanEvent>,
    targets: Receiver<IpAddr>,
    sockets: Vec<ProbeSockets>,
    states: HashMap<u64, ProbeState>,
    reply_index: HashMap<ReplyKey, u64>,
    schedule: BinaryHeap<Reverse<ScheduledAction>>,
    next_state_id: u64,
    input_closed: bool,
    stats: WorkerStats,
}

pub fn run_scan(config: ScanConfig, events: Sender<ScanEvent>) -> Result<ScanSummary> {
    if config.selected_probes.is_empty() {
        anyhow::bail!("no probes selected");
    }

    let start = Instant::now();
    let threads = config.threads.max(1);
    let target_channel_capacity =
        (MAX_INFLIGHT_STATES_PER_WORKER / config.selected_probes.len().max(1)).max(1);

    let config = Arc::new(config);
    let rate_limiter = Arc::new(SharedRateLimiter::new(
        config.bandwidth_bits_per_second,
        config.packets_per_second,
    ));

    let mut worker_channels = Vec::with_capacity(threads);
    let mut worker_handles = Vec::with_capacity(threads);

    for worker_id in 0..threads {
        let (tx, rx) = bounded::<IpAddr>(target_channel_capacity);
        worker_channels.push(tx);

        let worker_config = Arc::clone(&config);
        let worker_limiter = Arc::clone(&rate_limiter);
        let worker_events = events.clone();
        worker_handles.push(thread::spawn(move || {
            run_worker(worker_id, worker_config, worker_limiter, worker_events, rx)
        }));
    }
    drop(events);

    let dispatcher_inputs = config.target_inputs.clone();
    let dispatcher_blocklist = config.blocklist.clone();
    let dispatcher_handle = thread::spawn(move || {
        run_dispatcher(dispatcher_inputs, dispatcher_blocklist, worker_channels)
    });

    let dispatcher_stats = dispatcher_handle
        .join()
        .map_err(|_| anyhow::anyhow!("dispatcher thread panicked"))??;

    let mut summary = ScanSummary {
        targets_scanned: dispatcher_stats.targets_scanned,
        probes_selected: config.selected_probes.len(),
        ..ScanSummary::default()
    };

    for handle in worker_handles {
        let stats = handle
            .join()
            .map_err(|_| anyhow::anyhow!("worker thread panicked"))??;
        summary.packets_sent += stats.packets_sent;
        summary.bytes_sent += stats.bytes_sent;
        summary.hits += stats.hits;
        summary.warnings += stats.warnings;
        summary.unexpected_replies += stats.unexpected_replies;
    }
    summary.scan_duration_ms = start.elapsed().as_millis();

    Ok(summary)
}

fn run_dispatcher(
    inputs: Vec<TargetInput>,
    blocklist: Blocklist,
    workers: Vec<Sender<IpAddr>>,
) -> Result<DispatcherStats> {
    let mut stream = TargetStream::new(inputs)?;
    let mut index = 0usize;
    let mut stats = DispatcherStats::default();
    let worker_count = workers.len().max(1);

    for target in &mut stream {
        let target = target?;
        if blocklist.contains(target) {
            continue;
        }
        workers[index % worker_count]
            .send(target)
            .context("failed to send target to worker")?;
        stats.targets_scanned += 1;
        index += 1;
    }

    Ok(stats)
}

fn run_worker(
    worker_id: usize,
    config: Arc<ScanConfig>,
    rate_limiter: Arc<SharedRateLimiter>,
    events: Sender<ScanEvent>,
    targets: Receiver<IpAddr>,
) -> Result<WorkerStats> {
    let mut poll = Poll::new().context("failed to create poll instance")?;
    let mut sockets = Vec::with_capacity(config.selected_probes.len());
    for (probe_index, _) in config.selected_probes.iter().enumerate() {
        let mut ipv4_socket = new_udp_socket(SocketFamily::V4)?;
        poll.registry()
            .register(
                &mut ipv4_socket,
                token_for(probe_index, SocketFamily::V4),
                Interest::READABLE,
            )
            .context("failed to register IPv4 UDP socket with poll")?;
        let mut ipv6_socket = new_udp_socket(SocketFamily::V6)?;
        poll.registry()
            .register(
                &mut ipv6_socket,
                token_for(probe_index, SocketFamily::V6),
                Interest::READABLE,
            )
            .context("failed to register UDP socket with poll")?;
        sockets.push(ProbeSockets {
            ipv4: ipv4_socket,
            ipv6: ipv6_socket,
        });
    }

    let mut context = WorkerContext {
        worker_id,
        config,
        rate_limiter,
        events,
        targets,
        sockets,
        states: HashMap::new(),
        reply_index: HashMap::new(),
        schedule: BinaryHeap::new(),
        next_state_id: 0,
        input_closed: false,
        stats: WorkerStats::default(),
    };

    let mut events = Events::with_capacity(1024);
    loop {
        let worker_is_idle = context.states.is_empty();
        fill_targets(&mut context, worker_is_idle)?;

        if context.input_closed && context.states.is_empty() {
            break;
        }

        let timeout = next_poll_timeout(&context);
        poll.poll(&mut events, timeout)?;

        for event in &events {
            handle_socket_event(&mut context, event)?;
        }
        process_due_actions(&mut context)?;
    }

    Ok(context.stats)
}

fn new_udp_socket(family: SocketFamily) -> Result<UdpSocket> {
    let domain = match family {
        SocketFamily::V4 => Domain::IPV4,
        SocketFamily::V6 => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_send_buffer_size(SOCKET_BUFFER_BYTES)?;
    socket.set_recv_buffer_size(SOCKET_BUFFER_BYTES)?;
    match family {
        SocketFamily::V4 => {
            socket.set_broadcast(true)?;
            socket.bind(&SockAddr::from(SocketAddr::from((
                Ipv4Addr::UNSPECIFIED,
                0,
            ))))?;
        }
        SocketFamily::V6 => {
            socket.set_only_v6(true)?;
            socket.bind(&SockAddr::from(SocketAddr::from((
                Ipv6Addr::UNSPECIFIED,
                0,
            ))))?;
        }
    }
    Ok(UdpSocket::from_std(socket.into()))
}

fn fill_targets(context: &mut WorkerContext, block_when_empty: bool) -> Result<()> {
    let states_per_target = context.config.selected_probes.len().max(1);
    let mut first_attempt = true;

    while context.states.len() + states_per_target <= MAX_INFLIGHT_STATES_PER_WORKER {
        let received = if block_when_empty && first_attempt {
            match context.targets.recv_timeout(Duration::from_millis(20)) {
                Ok(target) => Some(target),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => None,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    context.input_closed = true;
                    None
                }
            }
        } else {
            match context.targets.try_recv() {
                Ok(target) => Some(target),
                Err(crossbeam_channel::TryRecvError::Empty) => None,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    context.input_closed = true;
                    None
                }
            }
        };

        first_attempt = false;

        let Some(target) = received else {
            break;
        };

        for probe_index in 0..context.config.selected_probes.len() {
            let state_id = context.next_state_id;
            context.next_state_id += 1;
            context.states.insert(
                state_id,
                ProbeState {
                    target_ip: target,
                    probe_index,
                    attempts_sent: 0,
                    generation: 0,
                    last_sent_at: None,
                    reserved_send_at: None,
                },
            );
            context.schedule.push(Reverse(ScheduledAction {
                when: Instant::now(),
                state_id,
                generation: 0,
                kind: ScheduleKind::Send,
            }));
        }
    }

    Ok(())
}

fn next_poll_timeout(context: &WorkerContext) -> Option<Duration> {
    let now = Instant::now();
    let next_schedule = context.schedule.peek().map(|item| item.0.when);
    match (
        next_schedule,
        context.input_closed,
        context.states.is_empty(),
    ) {
        (Some(when), _, _) if when <= now => Some(Duration::ZERO),
        (Some(when), _, _) => Some((when - now).min(Duration::from_millis(50))),
        (None, false, true) => Some(Duration::from_millis(50)),
        (None, _, _) => Some(Duration::from_millis(20)),
    }
}

fn handle_socket_event(context: &mut WorkerContext, event: &Event) -> Result<()> {
    let (probe_index, family) = probe_index_from_token(event.token());
    let socket = socket_for_family(&mut context.sockets[probe_index], family);
    let mut buffer = [0_u8; SOCKET_RECV_BUFFER_BYTES];

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((bytes_read, source @ SocketAddr::V4(_)))
            | Ok((bytes_read, source @ SocketAddr::V6(_))) => {
                let key = ReplyKey {
                    probe_index,
                    target_ip: source.ip(),
                    source_port: source.port(),
                };
                let Some(state_id) = context.reply_index.remove(&key) else {
                    context.stats.unexpected_replies += 1;
                    continue;
                };
                let Some(state) = context.states.remove(&state_id) else {
                    context.stats.unexpected_replies += 1;
                    continue;
                };
                context.stats.hits += 1;
                let probe = &context.config.selected_probes[state.probe_index];
                let rtt = state
                    .last_sent_at
                    .map(|last_sent_at| last_sent_at.elapsed())
                    .unwrap_or_default();
                let event = ScanEvent::Hit(HitEvent {
                    probe: probe.canonical.clone(),
                    display_name: probe.display_name.to_string(),
                    target_ip: state.target_ip,
                    target_port: probe.port,
                    source_ip: source.ip(),
                    source_port: source.port(),
                    reply_hex: hex::encode(&buffer[..bytes_read]),
                    rtt,
                });
                let _ = context.events.send(event);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => {
                emit_warning(
                    context,
                    format!(
                        "worker {} recv error on probe socket {}: {}",
                        context.worker_id, probe_index, error
                    ),
                );
                return Ok(());
            }
        }
    }
}

fn process_due_actions(context: &mut WorkerContext) -> Result<()> {
    let now = Instant::now();
    while context
        .schedule
        .peek()
        .is_some_and(|entry| entry.0.when <= now)
    {
        let Reverse(action) = context.schedule.pop().unwrap();
        let Some(state) = context.states.get(&action.state_id) else {
            continue;
        };
        if action.generation != state.generation {
            continue;
        }

        match action.kind {
            ScheduleKind::Send => send_probe(context, action.state_id)?,
            ScheduleKind::Expire => expire_state(context, action.state_id),
        }
    }
    Ok(())
}

fn send_probe(context: &mut WorkerContext, state_id: u64) -> Result<()> {
    let (probe_index, target_ip, generation) = match context.states.get(&state_id) {
        Some(state) => (state.probe_index, state.target_ip, state.generation),
        None => return Ok(()),
    };
    let probe = &context.config.selected_probes[probe_index];
    let probe_port = probe.port;
    let probe_name = probe.canonical.clone();
    let payload = probe.payload.clone();
    let payload_len = probe.payload_len;
    let packet_overhead = packet_overhead_bytes(target_ip);
    let now = Instant::now();
    let scheduled_at = match context
        .states
        .get(&state_id)
        .and_then(|state| state.reserved_send_at)
    {
        Some(scheduled_at) => scheduled_at,
        None => {
            let scheduled_at = context.rate_limiter.reserve(payload_len + packet_overhead);
            if let Some(state) = context.states.get_mut(&state_id) {
                state.reserved_send_at = Some(scheduled_at);
            }
            scheduled_at
        }
    };
    if scheduled_at > now {
        schedule_state(
            context,
            state_id,
            generation + 1,
            scheduled_at,
            ScheduleKind::Send,
        );
        if let Some(state) = context.states.get_mut(&state_id) {
            state.generation += 1;
        }
        return Ok(());
    }

    let socket = socket_for_target(&mut context.sockets[probe_index], target_ip);
    let target_addr = SocketAddr::new(target_ip, probe_port);
    match socket.send_to(&payload, target_addr) {
        Ok(bytes_sent) => {
            let sent_at = Instant::now();
            if let Some(state) = context.states.get_mut(&state_id) {
                state.attempts_sent += 1;
                state.last_sent_at = Some(sent_at);
                state.generation += 1;
                state.reserved_send_at = None;
            }
            context.reply_index.insert(
                ReplyKey {
                    probe_index,
                    target_ip,
                    source_port: probe_port,
                },
                state_id,
            );
            context.stats.packets_sent += 1;
            context.stats.bytes_sent += (bytes_sent + packet_overhead) as u64;

            let max_attempts = context.config.retries + 1;
            let attempts_sent = context
                .states
                .get(&state_id)
                .map(|state| state.attempts_sent)
                .unwrap_or(max_attempts);
            let generation = context
                .states
                .get(&state_id)
                .map(|state| state.generation)
                .unwrap_or(generation + 1);

            if attempts_sent < max_attempts {
                let retry_interval =
                    Duration::from_secs_f64(1.0 / context.config.retry_packets_per_second as f64);
                schedule_state(
                    context,
                    state_id,
                    generation,
                    sent_at + retry_interval,
                    ScheduleKind::Send,
                );
            } else {
                schedule_state(
                    context,
                    state_id,
                    generation,
                    sent_at + context.config.rtt,
                    ScheduleKind::Expire,
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            let next_generation = if let Some(state) = context.states.get_mut(&state_id) {
                state.generation += 1;
                state.reserved_send_at = Some(Instant::now() + Duration::from_millis(5));
                Some(state.generation)
            } else {
                None
            };
            if let Some(next_generation) = next_generation {
                schedule_state(
                    context,
                    state_id,
                    next_generation,
                    Instant::now() + Duration::from_millis(5),
                    ScheduleKind::Send,
                );
            }
        }
        Err(error) => {
            expire_state(context, state_id);
            emit_warning(
                context,
                format!(
                    "send error for {} via {}: {}",
                    target_addr, probe_name, error
                ),
            );
        }
    }
    Ok(())
}

fn expire_state(context: &mut WorkerContext, state_id: u64) {
    if let Some(state) = context.states.remove(&state_id) {
        let probe = &context.config.selected_probes[state.probe_index];
        context.reply_index.remove(&ReplyKey {
            probe_index: state.probe_index,
            target_ip: state.target_ip,
            source_port: probe.port,
        });
    }
}

fn schedule_state(
    context: &mut WorkerContext,
    state_id: u64,
    generation: u64,
    when: Instant,
    kind: ScheduleKind,
) {
    context.schedule.push(Reverse(ScheduledAction {
        when,
        state_id,
        generation,
        kind,
    }));
}

fn emit_warning(context: &mut WorkerContext, message: String) {
    context.stats.warnings += 1;
    let _ = context
        .events
        .send(ScanEvent::Warning(WarningEvent { message }));
}

fn token_for(probe_index: usize, family: SocketFamily) -> Token {
    Token((probe_index * 2) + socket_family_index(family))
}

fn probe_index_from_token(token: Token) -> (usize, SocketFamily) {
    let raw = token.0;
    let family = if raw % 2 == 0 {
        SocketFamily::V4
    } else {
        SocketFamily::V6
    };
    (raw / 2, family)
}

fn socket_family_index(family: SocketFamily) -> usize {
    match family {
        SocketFamily::V4 => 0,
        SocketFamily::V6 => 1,
    }
}

fn socket_for_family(sockets: &mut ProbeSockets, family: SocketFamily) -> &mut UdpSocket {
    match family {
        SocketFamily::V4 => &mut sockets.ipv4,
        SocketFamily::V6 => &mut sockets.ipv6,
    }
}

fn socket_for_target(sockets: &mut ProbeSockets, target_ip: IpAddr) -> &mut UdpSocket {
    match target_ip {
        IpAddr::V4(_) => &mut sockets.ipv4,
        IpAddr::V6(_) => &mut sockets.ipv6,
    }
}

fn packet_overhead_bytes(target_ip: IpAddr) -> usize {
    match target_ip {
        IpAddr::V4(_) => IPV4_PACKET_OVERHEAD_BYTES,
        IpAddr::V6(_) => IPV6_PACKET_OVERHEAD_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use crossbeam_channel::{TryRecvError, bounded, unbounded};

    use super::{ScanConfig, run_scan};
    use crate::catalog::SelectedProbe;
    use crate::output::ScanEvent;
    use crate::targets::{Blocklist, TargetInput};

    enum ResponseMode {
        Always(Vec<u8>),
        After(usize, Vec<u8>),
    }

    struct TestServer {
        port: u16,
        wake_addr: SocketAddr,
        received_at: Arc<Mutex<Vec<Instant>>>,
        shutdown_tx: crossbeam_channel::Sender<()>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn start(mode: ResponseMode) -> Self {
            Self::start_on(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), mode).unwrap()
        }

        fn start_v6(mode: ResponseMode) -> io::Result<Self> {
            Self::start_on(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)), mode)
        }

        fn start_on(bind_addr: SocketAddr, mode: ResponseMode) -> io::Result<Self> {
            let socket = StdUdpSocket::bind(bind_addr)?;
            socket
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let port = socket.local_addr().unwrap().port();
            let wake_addr = match bind_addr {
                SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            };
            let received_at = Arc::new(Mutex::new(Vec::new()));
            let received_clone = Arc::clone(&received_at);
            let (shutdown_tx, shutdown_rx) = bounded::<()>(1);

            let handle = thread::spawn(move || {
                let mut packets_seen = 0usize;
                loop {
                    if shutdown_rx.try_recv().is_ok() {
                        break;
                    }

                    let mut buffer = [0_u8; 2048];
                    match socket.recv_from(&mut buffer) {
                        Ok((_size, source)) => {
                            packets_seen += 1;
                            received_clone.lock().unwrap().push(Instant::now());
                            let reply = match &mode {
                                ResponseMode::Always(payload) => Some(payload.as_slice()),
                                ResponseMode::After(after, payload) => {
                                    (packets_seen >= *after).then_some(payload.as_slice())
                                }
                            };
                            if let Some(reply) = reply {
                                let _ = socket.send_to(reply, source);
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
            });

            Ok(Self {
                port,
                wake_addr,
                received_at,
                shutdown_tx,
                handle: Some(handle),
            })
        }

        fn received_count(&self) -> usize {
            self.received_at.lock().unwrap().len()
        }

        fn received_times(&self) -> Vec<Instant> {
            self.received_at.lock().unwrap().clone()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            let _ = self.shutdown_tx.send(());
            let _ = match self.wake_addr {
                SocketAddr::V4(_) => StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .and_then(|socket| socket.send_to(&[0], self.wake_addr)),
                SocketAddr::V6(_) => StdUdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
                    .and_then(|socket| socket.send_to(&[0], self.wake_addr)),
            };
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn probe(name: &str, port: u16, payload: &[u8]) -> SelectedProbe {
        SelectedProbe {
            canonical: name.to_string(),
            display_name: Box::leak(name.to_string().into_boxed_str()),
            port,
            payload: Arc::<[u8]>::from(payload.to_vec()),
            payload_len: payload.len(),
        }
    }

    fn run_test_scan(
        probes: Vec<SelectedProbe>,
        targets: Vec<String>,
        retries: u32,
        retry_packets_per_second: u32,
        packets_per_second: Option<u64>,
        threads: usize,
        rtt: Duration,
    ) -> (crate::output::ScanSummary, Vec<ScanEvent>) {
        let (events_tx, events_rx) = unbounded();
        let summary = run_scan(
            ScanConfig {
                selected_probes: probes,
                target_inputs: vec![TargetInput::Args(targets)],
                blocklist: Blocklist::empty(),
                bandwidth_bits_per_second: 5_000_000,
                packets_per_second,
                retry_packets_per_second,
                retries,
                rtt,
                threads,
            },
            events_tx,
        )
        .unwrap();

        let mut events = Vec::new();
        loop {
            match events_rx.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }

        (summary, events)
    }

    #[test]
    fn scan_reports_hits_and_negative_case() {
        let server_a = TestServer::start(ResponseMode::Always(b"alpha".to_vec()));
        let server_b = TestServer::start(ResponseMode::Always(b"bravo".to_vec()));
        let unused_socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let unused_port = unused_socket.local_addr().unwrap().port();
        drop(unused_socket);

        let (summary, events) = run_test_scan(
            vec![
                probe("probe-a", server_a.port, &[0x01]),
                probe("probe-b", server_b.port, &[0x02]),
                probe("probe-c", unused_port, &[0x03]),
            ],
            vec!["127.0.0.1".into()],
            0,
            20,
            None,
            2,
            Duration::from_millis(150),
        );

        let hit_names = events
            .into_iter()
            .filter_map(|event| match event {
                ScanEvent::Hit(hit) => Some(hit.probe),
                ScanEvent::Warning(_) => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(summary.targets_scanned, 1);
        assert_eq!(summary.packets_sent, 3);
        assert_eq!(summary.hits, 2);
        assert!(hit_names.contains(&"probe-a".to_string()));
        assert!(hit_names.contains(&"probe-b".to_string()));
    }

    #[test]
    fn scan_retries_until_response_arrives() {
        let server = TestServer::start(ResponseMode::After(2, b"ok".to_vec()));

        let (summary, events) = run_test_scan(
            vec![probe("retry-probe", server.port, &[0x41, 0x42])],
            vec!["127.0.0.1".into()],
            2,
            20,
            None,
            1,
            Duration::from_millis(200),
        );

        assert_eq!(summary.hits, 1);
        assert!(summary.packets_sent >= 2);
        assert!(server.received_count() >= 2);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ScanEvent::Hit(hit) if hit.probe == "retry-probe"))
        );
    }

    #[test]
    fn scan_respects_global_packet_rate_across_threads() {
        let server = TestServer::start(ResponseMode::Always(b"rate".to_vec()));
        let targets = vec![
            "127.0.0.1".to_string(),
            "127.0.0.2".to_string(),
            "127.0.0.3".to_string(),
            "127.0.0.4".to_string(),
            "127.0.0.5".to_string(),
            "127.0.0.6".to_string(),
        ];

        let (summary, _events) = run_test_scan(
            vec![probe("rate-probe", server.port, &[0x55])],
            targets,
            0,
            50,
            Some(5),
            4,
            Duration::from_millis(100),
        );

        let times = server.received_times();
        assert_eq!(summary.packets_sent, 6);
        assert_eq!(times.len(), 6);
        let elapsed = times.last().unwrap().duration_since(times[0]);
        assert!(
            elapsed >= Duration::from_millis(700),
            "expected packet pacing, observed {:?}",
            elapsed
        );
    }

    #[test]
    fn scan_supports_mixed_ipv4_and_ipv6_targets() {
        let server_v4 = TestServer::start(ResponseMode::Always(b"v4".to_vec()));
        let Ok(server_v6) = TestServer::start_v6(ResponseMode::Always(b"v6".to_vec())) else {
            return;
        };

        let (summary, events) = run_test_scan(
            vec![
                probe("probe-v4", server_v4.port, &[0x11]),
                probe("probe-v6", server_v6.port, &[0x22]),
            ],
            vec!["127.0.0.1".into(), "::1".into()],
            0,
            20,
            None,
            2,
            Duration::from_millis(150),
        );

        let hit_targets = events
            .into_iter()
            .filter_map(|event| match event {
                ScanEvent::Hit(hit) => Some(hit.target_ip),
                ScanEvent::Warning(_) => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(summary.targets_scanned, 2);
        assert!(summary.hits >= 2);
        assert!(
            hit_targets
                .iter()
                .any(|ip| *ip == "127.0.0.1".parse::<IpAddr>().unwrap())
        );
        assert!(
            hit_targets
                .iter()
                .any(|ip| *ip == "::1".parse::<IpAddr>().unwrap())
        );
    }
}
