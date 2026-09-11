// Package regressions for verification-library MIR, not application proofs.
#[kani::proof]
#[kani::unwind(2)]
fn arithmetic_control() {
    let value: u8 = kani::any();
    assert!(u16::from(value) + 1 > u16::from(value));
}

#[kani::proof]
#[kani::unwind(2)]
fn sized_control() {
    let value = [1u8];
    assert!(std::mem::size_of_val(&value) == 1);
}

#[kani::proof]
#[kani::unwind(2)]
fn slice_size() {
    let value = [1u8];
    assert!(std::mem::size_of_val(&value[..]) == 1);
}

#[kani::proof]
#[kani::unwind(2)]
fn slice_alignment() {
    let value = [1u8];
    assert!(std::mem::align_of_val(&value[..]) == 1);
}

#[kani::proof]
#[kani::unwind(2)]
fn string_clone() {
    let value = String::from("x");
    assert!(value.clone() == value);
}

#[kani::proof]
#[kani::unwind(2)]
fn vec_clone() {
    let value = vec![String::from("x")];
    assert!(value.clone() == value);
}

#[kani::proof]
#[kani::unwind(2)]
fn wrong_size() {
    let value = [1u8];
    assert!(std::mem::size_of_val(&value) == 2);
}
