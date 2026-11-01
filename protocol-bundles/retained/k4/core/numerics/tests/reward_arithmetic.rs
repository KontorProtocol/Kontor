use numerics::{Error, Integer, Sign, mul_add_div_rem_integer, string_to_integer, u64_to_integer};

const MAX_WIRE: Integer = Integer {
    r0: u64::MAX,
    r1: u64::MAX,
    r2: u64::MAX,
    r3: u64::MAX,
    sign: Sign::Plus,
};

fn decimal_whole_limit() -> Integer {
    string_to_integer("115792089237316195423570985008687907853269984665640564039457").unwrap()
}

#[test]
fn allocation_floors_and_preserves_the_exact_remainder() {
    for a in 0..12 {
        for b in 0..12 {
            for carry in 0..12 {
                for divisor in 1..12 {
                    let numerator = a * b + carry;
                    assert_eq!(
                        mul_add_div_rem_integer(
                            u64_to_integer(a),
                            u64_to_integer(b),
                            u64_to_integer(carry),
                            u64_to_integer(divisor),
                        )
                        .unwrap(),
                        (
                            u64_to_integer(numerator / divisor),
                            u64_to_integer(numerator % divisor),
                        ),
                    );
                }
            }
        }
    }
}

#[test]
fn wide_intermediate_succeeds_when_final_allocation_fits() {
    let max = decimal_whole_limit();
    let one = u64_to_integer(1);
    assert_eq!(
        mul_add_div_rem_integer(MAX_WIRE, MAX_WIRE, one, MAX_WIRE).unwrap(),
        (MAX_WIRE, one),
    );
    assert_eq!(
        mul_add_div_rem_integer(max, max, one, max).unwrap(),
        (max, one),
    );
    let (quotient, remainder) = mul_add_div_rem_integer(max, MAX_WIRE, max, MAX_WIRE).unwrap();
    assert_eq!((quotient, remainder), (max, max));
    assert_eq!(
        mul_add_div_rem_integer(max, one, max, u64_to_integer(2)).unwrap(),
        (max, Integer::default()),
    );
}

#[test]
fn full_width_remainder_can_be_carried_without_truncation() {
    let zero = Integer::default();
    let below_max = Integer {
        r0: u64::MAX - 1,
        ..MAX_WIRE
    };
    let (quotient, remainder) = mul_add_div_rem_integer(zero, zero, below_max, MAX_WIRE).unwrap();
    assert_eq!((quotient, remainder), (zero, below_max));
    assert_eq!(
        mul_add_div_rem_integer(u64_to_integer(1), u64_to_integer(1), remainder, MAX_WIRE).unwrap(),
        (u64_to_integer(1), zero),
    );
}

#[test]
fn final_allocation_overflow_is_an_error() {
    let max = MAX_WIRE;
    for (a, b, carry, divisor) in [
        (
            max,
            u64_to_integer(2),
            Integer::default(),
            u64_to_integer(1),
        ),
        (max, max, max, max),
    ] {
        assert!(matches!(
            mul_add_div_rem_integer(a, b, carry, divisor),
            Err(Error::Overflow(_)),
        ));
    }
}

#[test]
fn rejects_negative_inputs_and_zero_divisors() {
    let one = u64_to_integer(1);
    let negative = Integer {
        sign: Sign::Minus,
        ..one
    };
    for index in 0..4 {
        let mut args = [one; 4];
        args[index] = negative;
        assert!(matches!(
            mul_add_div_rem_integer(args[0], args[1], args[2], args[3]),
            Err(Error::Validation(_)),
        ));
    }
    for sign in [Sign::Plus, Sign::Minus] {
        let zero = Integer {
            sign,
            ..Integer::default()
        };
        assert!(matches!(
            mul_add_div_rem_integer(one, one, one, zero),
            Err(Error::DivByZero(_)),
        ));
        assert_eq!(
            mul_add_div_rem_integer(zero, one, zero, one).unwrap(),
            (Integer::default(), Integer::default()),
        );
    }
}

#[test]
fn retained_remainders_make_accrual_frequency_irrelevant() {
    let scale = 1_000_000_000_000_000_000u128;
    let divisor = 1007u128;
    let weight = 7u128;
    let mut carry = Integer::default();
    let mut paid = 0u128;
    let mut funded = 0u128;
    for block in 0..1000u128 {
        let amount = scale + block;
        let (allocation, remainder) = mul_add_div_rem_integer(
            string_to_integer(&amount.to_string()).unwrap(),
            u64_to_integer(weight as u64),
            carry,
            u64_to_integer(divisor as u64),
        )
        .unwrap();
        paid += u128::from(allocation.r0) + (u128::from(allocation.r1) << 64);
        funded += amount;
        carry = remainder;
        assert_eq!(paid, funded * weight / divisor);
        assert_eq!(u128::from(carry.r0), funded * weight % divisor);
        assert!(paid <= funded);
    }
    assert_eq!(
        mul_add_div_rem_integer(
            string_to_integer(&funded.to_string()).unwrap(),
            u64_to_integer(weight as u64),
            Integer::default(),
            u64_to_integer(divisor as u64),
        )
        .unwrap(),
        (string_to_integer(&paid.to_string()).unwrap(), carry),
    );
}
