mod catalog;
mod cli;
mod output;
mod rate_limiter;
mod scan;
mod targets;

pub fn run() -> anyhow::Result<()> {
    cli::run()
}
