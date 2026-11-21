//! Parsing of the `retention` argument of `set_webhook_outbox_limits`.
//!
//! The CLI takes a whole number of seconds. Only this MCP argument also
//! accepts a duration such as `36h`, `30d` or `90m`.

/// Parses seconds, or a whole number plus one of `s`, `m`, `h`, `d`.
///
/// The range check is separate: this only rejects a string that is not a
/// duration. `"default"` is not a duration.
///
/// # Errors
///
/// Returns an error when `value` is empty, signed, fractional, a compound
/// duration, or an unknown unit, and when the number does not fit in `i64`.
pub fn parse_retention(value: &str) -> Result<i64, String> {
    let text = value.trim();
    if text.is_empty() || text.starts_with('+') || text.starts_with('-') {
        return Err(retention_syntax());
    }
    if text.bytes().all(|byte| byte.is_ascii_digit()) {
        return text.parse::<i64>().map_err(|_| retention_too_large());
    }
    let mut chars = text.chars();
    let Some(unit) = chars.next_back() else {
        return Err(retention_syntax());
    };
    let digits = chars.as_str();
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(retention_syntax());
    }
    let count: i64 = digits.parse().map_err(|_| retention_too_large())?;
    let factor = match unit.to_ascii_lowercase() {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return Err(retention_syntax()),
    };
    count.checked_mul(factor).ok_or_else(retention_too_large)
}

fn retention_syntax() -> String {
    "retention must be a whole number of seconds or a duration like 36h, 30d or 90m".to_owned()
}

fn retention_too_large() -> String {
    "retention is too large".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seconds_and_single_units() {
        assert_eq!(parse_retention("3600").ok(), Some(3_600));
        assert_eq!(parse_retention("36h").ok(), Some(129_600));
        assert_eq!(parse_retention("30d").ok(), Some(2_592_000));
        assert_eq!(parse_retention("90m").ok(), Some(5_400));
        assert_eq!(parse_retention("1h").ok(), Some(3_600));
        assert_eq!(parse_retention("2s").ok(), Some(2));
        assert_eq!(parse_retention("36H").ok(), Some(129_600));
        assert_eq!(parse_retention("  90m  ").ok(), Some(5_400));
        assert_eq!(parse_retention("036h").ok(), Some(129_600));
        assert_eq!(parse_retention("0d").ok(), Some(0));
    }

    #[test]
    fn rejects_anything_that_is_not_one_duration() {
        for bad in [
            "30 days", "1.5h", "1w", "", "36 h", "-1", "+36h", "36h30m", "1d2h", "h", "default",
            "36hours",
        ] {
            let err = match parse_retention(bad) {
                Ok(secs) => panic!("accepted {bad} as {secs}"),
                Err(err) => err,
            };
            assert!(
                err.contains("36h") || err.contains("too large"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn rejects_a_duration_that_overflows() {
        let err = match parse_retention("999999999999999999d") {
            Ok(secs) => panic!("accepted an overflowing duration as {secs}"),
            Err(err) => err,
        };
        assert!(err.contains("too large"), "{err}");
    }
}
