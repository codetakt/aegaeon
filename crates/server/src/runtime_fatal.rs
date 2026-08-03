#![forbid(unsafe_code)]

pub const RUNTIME_AUTHORITY_UNAVAILABLE_EXIT_CODE: i32 = 78;

pub fn terminate_runtime() -> ! {
    std::process::exit(RUNTIME_AUTHORITY_UNAVAILABLE_EXIT_CODE);
}
