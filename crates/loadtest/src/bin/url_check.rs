#![forbid(unsafe_code)]

use aegaeon_loadtest::{url_validation::validate_report_urls, LoadTestConfig};
use std::{ffi::OsString, io::Read};

fn validate_stdin_config() -> bool {
    // A configuration is small; bound malformed input without echoing it.
    const MAX_CONFIG_BYTES: u64 = 65_536;
    let mut raw = Vec::new();
    std::io::stdin()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut raw)
        .is_ok()
        && raw.len() as u64 <= MAX_CONFIG_BYTES
        && serde_json::from_slice::<LoadTestConfig>(&raw)
            .is_ok_and(|config| config.validate().is_ok())
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Option<(String, Option<String>)> {
    let mut args = args.into_iter();
    let mut target = None;
    let mut issuer = None;
    while let Some(argument) = args.next() {
        let argument = argument.into_string().ok()?;
        let (name, value) = match argument.split_once('=') {
            Some((name, value)) => (name.to_owned(), value.to_owned()),
            None => (argument, args.next()?.into_string().ok()?),
        };
        match name.as_str() {
            "--url" if target.is_none() => target = Some(value),
            "--discovery-expected-issuer" if issuer.is_none() => issuer = Some(value),
            _ => return None,
        }
    }
    Some((target?, issuer))
}

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let config_mode = arguments.first().is_some_and(|arg| arg == "--config-stdin");
    let valid = if config_mode {
        arguments.len() == 1 && validate_stdin_config()
    } else {
        parse_args(arguments).is_some_and(|(target, issuer)| {
            validate_report_urls(&target, issuer.as_deref()).is_ok()
        })
    };
    if !valid {
        if config_mode {
            eprintln!("[perf] configuration validation failed");
        } else {
            eprintln!("[perf] URL validation failed");
        }
        std::process::exit(2);
    }
}
