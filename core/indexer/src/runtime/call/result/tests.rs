use std::fmt::Write;

use super::Output;

#[test]
fn failed_output_charge_is_independent_of_write_boundaries() {
    for limit in 0..9 {
        for pieces in [
            vec!["éabcdefg"],
            vec!["é", "ab", "cdefg"],
            vec!["é", "a", "b", "c", "d", "e", "f", "g"],
        ] {
            let mut output = Output::new(limit);
            for piece in pieces {
                if output.write_str(piece).is_err() {
                    break;
                }
            }
            assert!(output.exhausted);
            assert_eq!(output.charged_bytes, limit);
            assert!(output.value.len() as u64 <= limit);
        }
    }
}
