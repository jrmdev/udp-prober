fn main() {
    if let Err(error) = udp_prober::run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
