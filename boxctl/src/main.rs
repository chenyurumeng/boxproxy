mod atomic_file;
mod cli;
mod config;
mod control;
mod core_config;
mod db;
mod exec;
mod logger;
mod monitor;
mod platform;
mod resource;
mod rules;
mod service;

use cli::{
    parse_args, print_version, CnipCommand, Command, ConfigCommand, ModeCommand, ResourceCommand,
    ServiceCommand, WifiCommand,
};
use config::{BoxPaths, Config};
use exec::Runner;
use std::env;
use std::process;

type Result<T> = std::result::Result<T, String>;

fn main() {
    if let Err(err) = run() {
        logger::console_error(err);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    if env::args()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V")
    {
        print_version();
        process::exit(0);
    }

    let cli = parse_args(env::args().skip(1).collect())?;
    let paths = BoxPaths::new(cli.home, cli.overrides.db_path.clone())?;
    let config = Config::load(paths, cli.overrides)?;
    let runner = Runner::new(cli.dry_run, cli.verbose);

    match cli.command {
        Command::Up => control::up(&config, &runner),
        Command::Boot => control::boot(&config, &runner),
        Command::Down => control::down(&config, &runner),
        Command::Restart => control::restart(&config, &runner),
        Command::Status => control::status(&config, &runner),
        Command::Service(ServiceCommand::Start) => {
            control::with_operation_lock(&config, || service::start(&config, &runner))
        }
        Command::Service(ServiceCommand::Stop) => {
            control::with_operation_lock(&config, || service::stop(&config, &runner))
        }
        Command::Service(ServiceCommand::Restart) => control::with_operation_lock(&config, || {
            service::stop(&config, &runner)?;
            service::start(&config, &runner)
        }),
        Command::Service(ServiceCommand::Status) => service::status(&config, &runner),
        Command::Mode(ModeCommand::Apply) => {
            control::with_operation_lock(&config, || rules::apply(&config, &runner))
        }
        Command::Mode(ModeCommand::Clear) => {
            control::with_operation_lock(&config, || rules::clear(&config, &runner))
        }
        Command::Mode(ModeCommand::Renew) => {
            control::with_operation_lock(&config, || rules::renew(&config, &runner))
        }
        Command::Config(ConfigCommand::Sync) => {
            control::with_operation_lock(&config, || core_config::sync(&config))
        }
        Command::Resource(ResourceCommand::Apply) => {
            control::with_operation_lock(&config, || resource::apply_current(&config, &runner))
        }
        Command::Cnip(CnipCommand::Reload) => {
            control::with_operation_lock(&config, || rules::reload_cn_ipset(&config, &runner))
        }
        Command::Monitor => monitor::run(&config, &runner),
        Command::MonitorStop => monitor::stop(&config, &runner),
        Command::Wifi(WifiCommand::Apply) => monitor::apply_wifi_policy(&config, &runner),
    }
}
