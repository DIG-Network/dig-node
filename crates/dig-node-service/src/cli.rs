//! The CLI's machine-readable surface: the differentiated exit-code table and the
//! `--json` output envelopes.
//!
//! Beside the human-prose output (the default), every subcommand can emit ONE
//! structured JSON object to stdout under `--json` (human prose then goes to
//! stderr), and every failure maps to a DISTINCT, documented exit code rather than
//! a single generic `1`. So a script/agent driving `dig-node` can branch on
//! the exit code AND parse the result without scraping prose.
//!
//! The exit-code table (also documented in the README and emitted by
//! `--help-json`-style introspection):
//!
//! | Exit | Code (UPPER_SNAKE)  | Meaning                                          |
//! |------|---------------------|--------------------------------------------------|
//! | 0    | OK                  | Success.                                         |
//! | 1    | NOT_SERVING         | `status`: the node is not responding.            |
//! | 2    | USAGE               | Bad arguments / usage error.                     |
//! | 3    | PERMISSION_DENIED   | `install`/`uninstall` need elevation (Windows).  |
//! | 4    | SERVICE_FAILED      | A service operation failed (register/start/stop).|
//! | 5    | BIND_FAILED         | `run`: could not bind the loopback address.      |
//! | 6    | IO_ERROR            | Other I/O error.                                 |
//! | 7    | NODE_UNREACHABLE    | The node did not answer; nothing was measured.    |

use serde_json::{json, Value};

use crate::meta;

/// A documented, stable exit code for the CLI. Each maps a failure CLASS to a
/// distinct process exit code AND a stable UPPER_SNAKE symbolic name, so callers
/// can branch on either. Backed by this enum rather than scattered `exit(1)`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// 0 — success.
    Ok,
    /// 1 — `status` ran fine but the node is not serving (scriptable "is it up?").
    NotServing,
    /// 2 — usage / bad argument error.
    Usage,
    /// 3 — the operation needs elevation (Windows service install/uninstall).
    PermissionDenied,
    /// 4 — a service-manager operation (register/start/stop/uninstall) failed.
    ServiceFailed,
    /// 5 — `run` could not bind the configured loopback address.
    BindFailed,
    /// 6 — any other I/O error.
    IoError,
    /// 7 — the node did not answer, so the operation was never measured (dig-node#407).
    ///
    /// Deliberately NOT `IO_ERROR`: that code says an I/O operation was attempted and failed,
    /// which is a claim about the requested operation. An unreachable node is a failure to
    /// MEASURE, not a measured failure, and the two must not share an encoding -- the restart
    /// window an update opens is exactly when the difference matters, and a caller that cannot
    /// tell them apart learns to ignore both.
    NodeUnreachable,
}

impl ExitCode {
    /// The numeric process exit code.
    pub const fn code(self) -> u8 {
        match self {
            ExitCode::Ok => 0,
            ExitCode::NotServing => 1,
            ExitCode::Usage => 2,
            ExitCode::PermissionDenied => 3,
            ExitCode::ServiceFailed => 4,
            ExitCode::BindFailed => 5,
            ExitCode::IoError => 6,
            ExitCode::NodeUnreachable => 7,
        }
    }

    /// The stable UPPER_SNAKE symbolic name.
    pub const fn name(self) -> &'static str {
        match self {
            ExitCode::Ok => "OK",
            ExitCode::NotServing => "NOT_SERVING",
            ExitCode::Usage => "USAGE",
            ExitCode::PermissionDenied => "PERMISSION_DENIED",
            ExitCode::ServiceFailed => "SERVICE_FAILED",
            ExitCode::BindFailed => "BIND_FAILED",
            ExitCode::IoError => "IO_ERROR",
            ExitCode::NodeUnreachable => "NODE_UNREACHABLE",
        }
    }

    /// A one-line description for the catalogue / `--help`.
    pub const fn description(self) -> &'static str {
        match self {
            ExitCode::Ok => "Success.",
            ExitCode::NotServing => "status: the node is not responding.",
            ExitCode::Usage => "Bad arguments / usage error.",
            ExitCode::PermissionDenied => {
                "install/uninstall need an elevated (Administrator) console (Windows)."
            }
            ExitCode::ServiceFailed => {
                "A service operation failed (register/start/stop/uninstall)."
            }
            ExitCode::BindFailed => "run: could not bind the loopback address.",
            ExitCode::IoError => "Other I/O error.",
            ExitCode::NodeUnreachable => {
                "The node did not answer; the operation was not measured (it may be restarting)."
            }
        }
    }

    /// Map a [`std::io::Error`] from a service/serve operation to the closest exit
    /// code, so the typed failure class survives to the process exit status.
    pub fn from_io_error(e: &std::io::Error) -> ExitCode {
        use std::io::ErrorKind::*;
        match e.kind() {
            PermissionDenied => ExitCode::PermissionDenied,
            AddrInUse | AddrNotAvailable => ExitCode::BindFailed,
            // A bad argument surfaced as `InvalidInput` (e.g. `dig-node open` rejecting a
            // non-DIG/malformed link) is a USAGE error, not a generic I/O failure.
            InvalidInput => ExitCode::Usage,
            // The node did not answer. Nothing was measured about the requested operation, so
            // this must not be reported as an I/O failure OF that operation (#407).
            ConnectionRefused => ExitCode::NodeUnreachable,
            _ => ExitCode::IoError,
        }
    }

    /// Every code, for the catalogue.
    pub fn all() -> &'static [ExitCode] {
        &[
            ExitCode::Ok,
            ExitCode::NotServing,
            ExitCode::Usage,
            ExitCode::PermissionDenied,
            ExitCode::ServiceFailed,
            ExitCode::BindFailed,
            ExitCode::IoError,
            ExitCode::NodeUnreachable,
        ]
    }
}

/// The structured outcome of a CLI subcommand: a human-prose `summary` (printed to
/// stderr in the default mode) and a machine `result` object (folded into the
/// `--json` success envelope). Service functions return this instead of printing
/// directly, so main.rs renders ONE consistent surface for both audiences.
#[derive(Debug)]
pub struct Outcome {
    /// Human-readable, possibly multi-line, summary lines.
    pub summary: String,
    /// Machine-readable result fields (an object), folded into the JSON envelope.
    pub result: Value,
}

impl Outcome {
    /// Build an outcome from a summary string and a JSON result object.
    pub fn new(summary: impl Into<String>, result: Value) -> Self {
        Outcome {
            summary: summary.into(),
            result,
        }
    }
}

/// The `--json` success envelope: `{ ok: true, action, ...result }` plus the
/// service build fingerprint, so one parse yields both the outcome and the
/// node identity. `action` is the subcommand name; `result` is folded in at the
/// top level.
pub fn success_envelope(action: &str, result: Value) -> Value {
    let mut obj = json!({
        "ok": true,
        "action": action,
        "service": meta::SERVICE_NAME,
        "version": meta::VERSION,
    });
    if let Value::Object(fields) = result {
        if let Value::Object(map) = &mut obj {
            for (k, v) in fields {
                map.insert(k, v);
            }
        }
    }
    obj
}

/// The `--json` error envelope: `{ ok:false, error:{ code, exit_code, message, hint } }`.
/// `code` is the stable symbolic name; `exit_code` is the numeric process code.
pub fn error_envelope(action: &str, exit: ExitCode, message: &str, hint: Option<&str>) -> Value {
    json!({
        "ok": false,
        "action": action,
        "error": {
            "code": exit.name(),
            "exit_code": exit.code(),
            "message": message,
            "hint": hint,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #407 -- an unreachable node must not be reported as an I/O failure OF the request.
    ///
    /// The two arms are asserted TOGETHER because the property is a distinction, not an outcome:
    /// a "fix" that renamed code 6, or that mapped every failure to the new code, satisfies
    /// either arm alone. `Other` is the genuine-I/O-failure control and must stay `IO_ERROR`.
    #[test]
    fn an_unreachable_node_is_distinguished_from_a_measured_io_failure() {
        let unreachable =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "node not answering");
        let measured = std::io::Error::other("the disk gave up mid-write");

        assert_eq!(
            ExitCode::from_io_error(&unreachable),
            ExitCode::NodeUnreachable
        );
        assert_eq!(ExitCode::from_io_error(&measured), ExitCode::IoError);
        assert_ne!(
            ExitCode::from_io_error(&unreachable).code(),
            ExitCode::from_io_error(&measured).code(),
            "a failure to measure and a measured failure must not share an exit code"
        );
    }

    /// The catalogue is the machine-readable contract (§6.2), and a code missing from it is
    /// invisible to every consumer that enumerates rather than guesses.
    #[test]
    fn the_new_code_is_in_the_catalogue_with_a_stable_name_and_number() {
        assert!(ExitCode::all().contains(&ExitCode::NodeUnreachable));
        assert_eq!(ExitCode::NodeUnreachable.code(), 7);
        assert_eq!(ExitCode::NodeUnreachable.name(), "NODE_UNREACHABLE");
        // Every code's number is distinct -- an added arm that reused 6 would read as success
        // against the two assertions above if either were relaxed.
        let mut codes: Vec<u8> = ExitCode::all().iter().map(|c| c.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "two exit codes share a number");
    }

    #[test]
    fn exit_codes_are_unique_and_upper_snake() {
        let mut codes = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for e in ExitCode::all() {
            assert!(codes.insert(e.code()), "duplicate exit code {}", e.code());
            assert!(names.insert(e.name()), "duplicate name {}", e.name());
            assert!(
                e.name().chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "{} is not UPPER_SNAKE",
                e.name()
            );
        }
    }

    #[test]
    fn ok_is_zero_and_not_serving_is_one() {
        assert_eq!(ExitCode::Ok.code(), 0);
        assert_eq!(ExitCode::NotServing.code(), 1);
    }

    #[test]
    fn io_error_kinds_map_to_exit_classes() {
        let perm = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "x");
        assert_eq!(ExitCode::from_io_error(&perm), ExitCode::PermissionDenied);
        let bind = std::io::Error::new(std::io::ErrorKind::AddrInUse, "x");
        assert_eq!(ExitCode::from_io_error(&bind), ExitCode::BindFailed);
        let other = std::io::Error::other("x");
        assert_eq!(ExitCode::from_io_error(&other), ExitCode::IoError);
        let usage = std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad link");
        assert_eq!(ExitCode::from_io_error(&usage), ExitCode::Usage);
    }

    #[test]
    fn success_envelope_folds_result_fields_and_marks_ok() {
        let env = success_envelope(
            "status",
            json!({ "serving": true, "addr": "127.0.0.1:9778" }),
        );
        assert_eq!(env["ok"], json!(true));
        assert_eq!(env["action"], json!("status"));
        assert_eq!(env["serving"], json!(true));
        assert_eq!(env["addr"], json!("127.0.0.1:9778"));
        assert_eq!(env["service"], json!("dig-node"));
    }

    #[test]
    fn error_envelope_carries_symbolic_and_numeric_code() {
        let env = error_envelope(
            "install",
            ExitCode::PermissionDenied,
            "needs admin",
            Some("elevate"),
        );
        assert_eq!(env["ok"], json!(false));
        assert_eq!(env["error"]["code"], json!("PERMISSION_DENIED"));
        assert_eq!(env["error"]["exit_code"], json!(3));
        assert_eq!(env["error"]["message"], json!("needs admin"));
        assert_eq!(env["error"]["hint"], json!("elevate"));
    }
}
