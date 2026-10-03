//! Integer monetary amounts.
//!
//! **Protocol invariant:** all monetary values are integers in the smallest
//! unit, called a *grain*.  One OBS is `10^12` grains.  Floating point is never
//! used for balances, fees, rewards, issuance or supply accounting.
//!
//! ```text
//! 1 OBS   = 1_000_000_000_000 grains
//! MAX_SUPPLY = 21_000_000 OBS = 21_000_000_000_000_000_000_000 grains
//! ```
//!
//! `u128` is used for arithmetic so that intermediate sums (for example
//! `supply + reward`) cannot overflow before the protocol invariant check.

use core::fmt;

/// Number of grains in one OBS.
pub const GRAINS_PER_OBS: u128 = 1_000_000_000_000;

/// Number of decimal places used when displaying amounts.
pub const OBS_DECIMALS: u32 = 12;

/// Maximum supply: 21,000,000 OBS (hard protocol invariant).
pub const MAX_SUPPLY_OBS: u128 = 21_000_000;

/// Maximum supply in grains.
pub const MAX_SUPPLY: Amount = Amount(MAX_SUPPLY_OBS * GRAINS_PER_OBS);

/// Genesis allocation: 100,000 OBS.
pub const GENESIS_ALLOCATION_OBS: u128 = 100_000;

/// Genesis allocation in grains.
pub const GENESIS_ALLOCATION: Amount = Amount(GENESIS_ALLOCATION_OBS * GRAINS_PER_OBS);

/// Validator bond: 50 OBS.
pub const VALIDATOR_BOND: Amount = Amount(50 * GRAINS_PER_OBS);

/// An integer amount of OBS in grains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(pub u128);

impl Amount {
    /// Zero.
    pub const ZERO: Amount = Amount(0);

    /// Constructs an amount from a whole number of OBS.
    pub const fn from_obs(obs: u128) -> Amount {
        Amount(obs * GRAINS_PER_OBS)
    }

    /// Constructs an amount from grains.
    pub const fn from_grains(grains: u128) -> Amount {
        Amount(grains)
    }

    /// The raw grain count.
    pub const fn grains(self) -> u128 {
        self.0
    }

    /// Checked addition.
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }

    /// Multiplies by an integer factor with overflow checks.
    pub fn checked_mul(self, factor: u128) -> Option<Amount> {
        self.0.checked_mul(factor).map(Amount)
    }

    /// Divides by an integer, truncating towards zero (deterministic).
    pub fn div_floor(self, divisor: u128) -> Option<Amount> {
        if divisor == 0 {
            None
        } else {
            Some(Amount(self.0 / divisor))
        }
    }

    /// Is this amount zero?
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Computes `self * numerator / denominator` with exact integer arithmetic,
    /// truncating the result towards zero.
    ///
    /// Returns `None` when `denominator` is zero or when the intermediate
    /// product overflows `u128`.
    pub fn mul_div_floor(self, numerator: u128, denominator: u128) -> Option<Amount> {
        if denominator == 0 {
            return None;
        }
        self.0
            .checked_mul(numerator)
            .map(|product| Amount(product / denominator))
    }

    /// Computes `self * numerator / denominator` with exact integer
    /// arithmetic, rounding the result **up** (ceiling division).
    ///
    /// Returns `None` when `denominator` is zero or when the intermediate
    /// product overflows `u128`.  Used for fee calculations, where the protocol
    /// rounds in the network's favour so that no transfer can be free.
    pub fn mul_div_ceil(self, numerator: u128, denominator: u128) -> Option<Amount> {
        if denominator == 0 {
            return None;
        }
        let product = self.0.checked_mul(numerator)?;
        let quotient = product / denominator;
        let round_up = u128::from(product % denominator != 0);
        // The round-up cannot overflow: a non-zero remainder means
        // `product >= quotient + 1`, so the rounded quotient never exceeds the
        // product, which fits.  Checked anyway — this function sits on the
        // monetary path, where "cannot overflow" is a thing to enforce rather
        // than to argue.
        quotient.checked_add(round_up).map(Amount)
    }

    /// Parses a decimal string such as `1.25` or `0.000000000001`.
    ///
    /// Rejects empty strings, more than 12 decimal places, signs, whitespace,
    /// underscores and anything else that is not a plain decimal number.
    pub fn parse(s: &str) -> Result<Amount, MoneyError> {
        if s.is_empty() {
            return Err(MoneyError::Empty);
        }
        let (whole_str, frac_str) = match s.split_once('.') {
            Some((w, f)) => (w, f),
            None => (s, ""),
        };
        if whole_str.is_empty() && frac_str.is_empty() {
            return Err(MoneyError::Malformed);
        }
        if frac_str.len() > OBS_DECIMALS as usize {
            return Err(MoneyError::TooManyDecimals);
        }
        for c in whole_str.bytes() {
            if !c.is_ascii_digit() {
                return Err(MoneyError::Malformed);
            }
        }
        for c in frac_str.bytes() {
            if !c.is_ascii_digit() {
                return Err(MoneyError::Malformed);
            }
        }
        let whole: u128 = if whole_str.is_empty() {
            0
        } else {
            whole_str.parse().map_err(|_| MoneyError::Overflow)?
        };
        let mut frac: u128 = if frac_str.is_empty() {
            0
        } else {
            frac_str.parse().map_err(|_| MoneyError::Overflow)?
        };
        for _ in frac_str.len()..OBS_DECIMALS as usize {
            frac *= 10;
        }
        let total = whole
            .checked_mul(GRAINS_PER_OBS)
            .and_then(|v| v.checked_add(frac))
            .ok_or(MoneyError::Overflow)?;
        Ok(Amount(total))
    }

    /// Formats the amount as a decimal OBS string with trailing zeros removed.
    pub fn to_decimal_string(self) -> String {
        let whole = self.0 / GRAINS_PER_OBS;
        let frac = self.0 % GRAINS_PER_OBS;
        if frac == 0 {
            return whole.to_string();
        }
        let mut frac_str = format!("{:012}", frac);
        while frac_str.ends_with('0') {
            frac_str.pop();
        }
        format!("{}.{}", whole, frac_str)
    }

    /// Formats the amount with exactly 12 decimal places (deterministic wire
    /// representation used by the Explorer and API).
    pub fn to_fixed_string(self) -> String {
        format!(
            "{}.{:012}",
            self.0 / GRAINS_PER_OBS,
            self.0 % GRAINS_PER_OBS
        )
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} OBS", self.to_decimal_string())
    }
}

/// Errors produced while parsing amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoneyError {
    /// The input was empty.
    Empty,
    /// The input was not a plain decimal number.
    Malformed,
    /// More than 12 decimal places were supplied.
    TooManyDecimals,
    /// The value does not fit in `u128` grains.
    Overflow,
}

impl fmt::Display for MoneyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MoneyError::Empty => write!(f, "amount is empty"),
            MoneyError::Malformed => write!(f, "amount is not a plain decimal number"),
            MoneyError::TooManyDecimals => write!(f, "amount has more than 12 decimal places"),
            MoneyError::Overflow => write!(f, "amount is too large"),
        }
    }
}

impl std::error::Error for MoneyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceil_division_rounds_up() {
        assert_eq!(Amount(1).mul_div_ceil(1, 3).unwrap(), Amount(1));
        assert_eq!(Amount(10).mul_div_ceil(1, 4).unwrap(), Amount(3));
        assert_eq!(Amount(10).mul_div_floor(1, 4).unwrap(), Amount(2));
        assert!(Amount(1).mul_div_ceil(1, 0).is_none());
        // The largest amount survives both the multiplication and the round-up
        // without wrapping.
        assert_eq!(Amount(u128::MAX).mul_div_ceil(1, 1).unwrap(), Amount(u128::MAX));
        assert!(
            Amount(u128::MAX).mul_div_ceil(2, 3).is_none(),
            "the product must be checked, not wrapped"
        );
        // Right at the edge of the product limit, the round-up still lands.
        let half = u128::MAX / 2;
        assert_eq!(
            Amount(half).mul_div_ceil(2, 3).unwrap(),
            Amount((half * 2) / 3 + 1)
        );
    }

    #[test]
    fn parse_and_format_roundtrip() {
        for s in [
            "0",
            "1",
            "1.5",
            "100000",
            "0.000000000001",
            "20999999.999999999999",
        ] {
            let a = Amount::parse(s).unwrap();
            assert_eq!(Amount::parse(&a.to_decimal_string()).unwrap(), a);
        }
    }

    #[test]
    fn known_values() {
        assert_eq!(Amount::parse("1").unwrap(), Amount::from_obs(1));
        assert_eq!(
            Amount::parse("0.000000000001").unwrap(),
            Amount::from_grains(1)
        );
        assert_eq!(MAX_SUPPLY.0, 21_000_000 * GRAINS_PER_OBS);
        assert_eq!(GENESIS_ALLOCATION.to_decimal_string(), "100000");
        assert_eq!(VALIDATOR_BOND.to_decimal_string(), "50");
    }

    #[test]
    fn invalid_amounts_are_rejected() {
        assert!(Amount::parse("").is_err());
        assert!(Amount::parse("1.2.3").is_err());
        assert!(Amount::parse("-1").is_err());
        assert!(Amount::parse("1e5").is_err());
        assert!(Amount::parse(" 1").is_err());
        assert!(Amount::parse("1.0000000000001").is_err());
        assert!(Amount::parse("340282366920938463463374607431768211456").is_err());
    }

    #[test]
    fn arithmetic_is_checked() {
        let a = Amount::parse("10").unwrap();
        let b = Amount::parse("3").unwrap();
        assert_eq!(a.checked_sub(b).unwrap().to_decimal_string(), "7");
        assert!(b.checked_sub(a).is_none());
        assert_eq!(a.mul_div_floor(2, 3).unwrap().to_decimal_string(), "6.666666666666");
        // Overflow of the u128 grain space is detected, not wrapped.
        let huge = Amount(u128::MAX);
        assert!(huge.checked_add(Amount(1)).is_none());
        assert!(Amount(u128::MAX / 2).checked_mul(4).is_none());
        assert_eq!(a.div_floor(0), None);
    }

    #[test]
    fn fixed_format_is_deterministic() {
        assert_eq!(Amount::from_obs(1).to_fixed_string(), "1.000000000000");
        assert_eq!(Amount::from_grains(1).to_fixed_string(), "0.000000000001");
    }
}
