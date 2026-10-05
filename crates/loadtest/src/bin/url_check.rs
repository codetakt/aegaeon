#![forbid(unsafe_code)]

use aegaeon_loadtest::url_validation::validate_report_urls;
use std::ffi::OsString;

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
    let valid = parse_args(std::env::args_os().skip(1))
        .is_some_and(|(target, issuer)| validate_report_urls(&target, issuer.as_deref()).is_ok());
    if !valid {
        eprintln!("[perf] URL validation failed");
        std::process::exit(2);
    }
}
