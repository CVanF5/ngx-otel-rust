// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! nginx log level → OTel SeverityNumber mapping.
//!
//! nginx levels are defined in `nginx/src/core/ngx_log.h:16-24` as integer
//! constants.  They are *inverted* from OTel — lower nginx level = more
//! severe.
//!
//! | nginx | name   | OTel SeverityNumber |
//! |-------|--------|---------------------|
//! | 1     | emerg  | Fatal4  (24)        |
//! | 2     | alert  | Fatal2  (22)        |
//! | 3     | crit   | Fatal   (21)        |
//! | 4     | error  | Error   (17)        |
//! | 5     | warn   | Warn    (13)        |
//! | 6     | notice | Info2   (10)        |
//! | 7     | info   | Info    (9)         |
//! | 8     | debug  | Debug   (5)         |

use crate::data_model::SeverityNumber;

/// Map a nginx log level to an OTel `(SeverityNumber, severity_text)` pair.
///
/// Returns `(SeverityNumber::Unspecified, "")` for any value outside `1..=8`.
#[inline]
pub fn nginx_to_otel(ngx_level: u32) -> (SeverityNumber, &'static str) {
    match ngx_level {
        1 => (SeverityNumber::Fatal4, "emerg"),
        2 => (SeverityNumber::Fatal2, "alert"),
        3 => (SeverityNumber::Fatal, "crit"),
        4 => (SeverityNumber::Error, "error"),
        5 => (SeverityNumber::Warn, "warn"),
        6 => (SeverityNumber::Info2, "notice"),
        7 => (SeverityNumber::Info, "info"),
        8 => (SeverityNumber::Debug, "debug"),
        _ => (SeverityNumber::Unspecified, ""),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_model::SeverityNumber;

    /// Assert the full 8-level nginx → OTel severity mapping.
    #[test]
    fn nginx_to_otel_table_matches_spec() {
        // (nginx_level, expected_severity_number, expected_severity_text)
        let table: &[(u32, SeverityNumber, &str)] = &[
            (1, SeverityNumber::Fatal4, "emerg"),
            (2, SeverityNumber::Fatal2, "alert"),
            (3, SeverityNumber::Fatal, "crit"),
            (4, SeverityNumber::Error, "error"),
            (5, SeverityNumber::Warn, "warn"),
            (6, SeverityNumber::Info2, "notice"),
            (7, SeverityNumber::Info, "info"),
            (8, SeverityNumber::Debug, "debug"),
        ];

        for &(level, expected_sev, expected_text) in table {
            let (sev, text) = nginx_to_otel(level);
            assert_eq!(
                sev, expected_sev,
                "nginx level {level}: expected severity {expected_sev:?}, got {sev:?}"
            );
            assert_eq!(
                text, expected_text,
                "nginx level {level}: expected text '{expected_text}', got '{text}'"
            );
        }

        // Out-of-range values map to Unspecified.
        assert_eq!(nginx_to_otel(0), (SeverityNumber::Unspecified, ""));
        assert_eq!(nginx_to_otel(9), (SeverityNumber::Unspecified, ""));
        assert_eq!(nginx_to_otel(255), (SeverityNumber::Unspecified, ""));
    }

    /// Verify the numeric values of key severity levels match the OTel proto spec.
    #[test]
    fn severity_number_values_match_proto() {
        assert_eq!(SeverityNumber::Info as i32, 9);
        assert_eq!(SeverityNumber::Error as i32, 17);
        assert_eq!(SeverityNumber::Fatal as i32, 21);
        assert_eq!(SeverityNumber::Fatal4 as i32, 24);
        assert_eq!(SeverityNumber::Debug as i32, 5);
        assert_eq!(SeverityNumber::Warn as i32, 13);
        assert_eq!(SeverityNumber::Unspecified as i32, 0);
    }
}
