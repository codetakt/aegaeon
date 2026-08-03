#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Sample {
    value: u64,
}

fn roundtrip(sample: &Sample) -> Sample {
    let json = serde_json::to_string(sample).expect("serialize");
    serde_json::from_str(&json).expect("deserialize")
}

fn main() {
    let sample = Sample { value: 7 };
    let back = roundtrip(&sample);
    assert_eq!(sample, back);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_smoke() {
        let sample = Sample { value: 7 };
        let back = roundtrip(&sample);
        assert_eq!(sample, back);
    }
}
