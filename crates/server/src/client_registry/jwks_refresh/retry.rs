pub(super) fn sleep_before_retry(attempt: &mut u32, retries: u32) -> bool {
    if *attempt >= retries {
        return false;
    }
    *attempt += 1;
    std::thread::sleep(std::time::Duration::from_millis(100 * (1 << *attempt)));
    true
}
