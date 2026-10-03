//! Command-line parsing for the network's services.
//!
//! The services are started by an operator, not by a framework, so this is a
//! deliberately small parser: `--name value`, `--name=value`, `--flag`, and
//! repeated `--peer`.  It is here rather than in each binary because three
//! services parsing arguments three slightly different ways is how an operator
//! ends up with a port that means something different in each of them.
//!
//! Two rules the callers rely on:
//!
//! * an unknown option is an *error*, never ignored — a mistyped `--prot` would
//!   otherwise silently start the service on the default port;
//! * a value that must parse (`--port`, a hex seed, a path) is parsed here, so a
//!   bad value stops the service before it opens a socket or a database.

use std::path::PathBuf;

/// A parsed argument list.
#[derive(Debug, Clone)]
pub struct Args {
    program: String,
    options: Vec<(String, Option<String>)>,
    positional: Vec<String>,
}

/// Why an argument list could not be understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// An option was not recognised.
    Unknown(String),
    /// An option that needs a value had none.
    MissingValue(String),
    /// An option's value could not be parsed.
    BadValue {
        /// The option.
        name: String,
        /// What was expected.
        expected: &'static str,
    },
}

impl core::fmt::Display for ArgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ArgError::Unknown(name) => write!(f, "unknown option {}", name),
            ArgError::MissingValue(name) => write!(f, "{} needs a value", name),
            ArgError::BadValue { name, expected } => {
                write!(f, "{} expects {}", name, expected)
            }
        }
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parses `argv`, refusing any option not named in `known`.
    ///
    /// `known` is a list of `"name"` for options that take a value and
    /// `"name!"` for flags that do not.  `--help` and `--version` are always
    /// known.
    pub fn parse(program: &str, argv: &[String], known: &[&str]) -> Result<Args, ArgError> {
        let known: Vec<(String, bool)> = known
            .iter()
            .map(|entry| match entry.strip_suffix('!') {
                Some(name) => (name.trim_start_matches('-').to_string(), true),
                None => (entry.trim_start_matches('-').to_string(), false),
            })
            .collect();
        let mut options: Vec<(String, Option<String>)> = Vec::new();
        let mut positional = Vec::new();
        let mut index = 0;
        while index < argv.len() {
            let token = &argv[index];
            if token == "--" {
                positional.extend(argv[index + 1..].iter().cloned());
                break;
            }
            if let Some(rest) = token.strip_prefix("--") {
                let (name, inline) = match rest.split_once('=') {
                    Some((name, value)) => (name.to_string(), Some(value.to_string())),
                    None => (rest.to_string(), None),
                };
                let Some((_, is_flag)) = known.iter().find(|(known, _)| *known == name) else {
                    return Err(ArgError::Unknown(format!("--{}", name)));
                };
                if *is_flag {
                    options.push((name, None));
                } else {
                    let value = match inline {
                        Some(value) => value,
                        None => {
                            index += 1;
                            argv.get(index)
                                .cloned()
                                .ok_or_else(|| ArgError::MissingValue(format!("--{}", name)))?
                        }
                    };
                    options.push((name, Some(value)));
                }
            } else {
                positional.push(token.clone());
            }
            index += 1;
        }
        Ok(Args {
            program: program.to_string(),
            options,
            positional,
        })
    }

    /// The program name, for usage output.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Everything after `--`.
    pub fn positional(&self) -> &[String] {
        &self.positional
    }

    /// True when a flag was given.
    pub fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(option, _)| option == name)
    }

    /// The first value given for an option.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .rev()
            .find(|(option, _)| option == name)
            .and_then(|(_, value)| value.as_deref())
    }

    /// Every value given for a repeatable option, in order.
    pub fn all(&self, name: &str) -> Vec<String> {
        self.options
            .iter()
            .filter(|(option, _)| option == name)
            .filter_map(|(_, value)| value.clone())
            .collect()
    }

    /// A value with a default.
    pub fn or(&self, name: &str, default: &str) -> String {
        self.get(name).unwrap_or(default).to_string()
    }

    /// A required value.
    pub fn require(&self, name: &str) -> Result<&str, ArgError> {
        self.get(name)
            .ok_or_else(|| ArgError::MissingValue(format!("--{}", name)))
    }

    /// A port number.
    pub fn port(&self, name: &str, default: u16) -> Result<u16, ArgError> {
        match self.get(name) {
            None => Ok(default),
            Some(value) => value.parse::<u16>().map_err(|_| ArgError::BadValue {
                name: format!("--{}", name),
                expected: "a port number from 1 to 65535",
            }),
        }
    }

    /// A whole number.
    pub fn number(&self, name: &str, default: u64) -> Result<u64, ArgError> {
        match self.get(name) {
            None => Ok(default),
            Some(value) => value.parse::<u64>().map_err(|_| ArgError::BadValue {
                name: format!("--{}", name),
                expected: "a non-negative whole number",
            }),
        }
    }

    /// A path.
    pub fn path(&self, name: &str, default: Option<&str>) -> Result<PathBuf, ArgError> {
        match self.get(name) {
            Some(value) => Ok(PathBuf::from(value)),
            None => default
                .map(PathBuf::from)
                .ok_or_else(|| ArgError::MissingValue(format!("--{}", name))),
        }
    }

    /// 32 bytes of hex, for a seed or a public key.
    pub fn hex32(&self, name: &str) -> Result<Option<[u8; 32]>, ArgError> {
        let Some(value) = self.get(name) else {
            return Ok(None);
        };
        let bytes = obs_crypto::encoding::hex_decode(value).ok_or_else(|| ArgError::BadValue {
            name: format!("--{}", name),
            expected: "32 bytes of hex",
        })?;
        if bytes.len() != 32 {
            return Err(ArgError::BadValue {
                name: format!("--{}", name),
                expected: "32 bytes of hex",
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn values_flags_and_defaults_are_read_as_written() {
        let args = Args::parse(
            "obs-node",
            &argv(&["--port", "7201", "--fsync", "--peer", "a:1", "--peer", "b:2"]),
            &["port", "fsync!", "peer"],
        )
        .unwrap();
        assert_eq!(args.port("port", 7200).unwrap(), 7201);
        assert!(args.flag("fsync"));
        assert_eq!(args.all("peer"), vec!["a:1".to_string(), "b:2".to_string()]);
        assert_eq!(args.port("other", 9).unwrap(), 9);
        // `--name=value` also works.
        let args = Args::parse("x", &argv(&["--port=1"]), &["port"]).unwrap();
        assert_eq!(args.get("port"), Some("1"));
    }

    #[test]
    fn an_unknown_option_is_an_error_rather_than_something_to_ignore() {
        // A mistyped option must stop the service, not be silently dropped.
        match Args::parse("obs-node", &argv(&["--prot", "7201"]), &["port"]) {
            Err(ArgError::Unknown(name)) => assert_eq!(name, "--prot"),
            other => panic!("expected an unknown-option error, got {:?}", other.map(|_| ())),
        }
        match Args::parse("obs-node", &argv(&["--port"]), &["port"]) {
            Err(ArgError::MissingValue(name)) => assert_eq!(name, "--port"),
            other => panic!("expected a missing-value error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn a_bad_value_stops_the_service_before_it_opens_a_socket() {
        let args = Args::parse("obs-node", &argv(&["--port", "seventy"]), &["port"]).unwrap();
        assert!(matches!(args.port("port", 1), Err(ArgError::BadValue { .. })));
        let args = Args::parse("obs-node", &argv(&["--mine-seed", "abc"]), &["mine-seed"]).unwrap();
        assert!(matches!(args.hex32("mine-seed"), Err(ArgError::BadValue { .. })));
        let args = Args::parse(
            "obs-node",
            &argv(&["--mine-seed", &"0".repeat(64)]),
            &["mine-seed"],
        )
        .unwrap();
        assert_eq!(args.hex32("mine-seed").unwrap(), Some([0u8; 32]));
        assert_eq!(args.hex32("node-seed").unwrap(), None);
    }

    #[test]
    fn positional_arguments_survive_the_double_dash() {
        let args = Args::parse("obs-node", &argv(&["--fsync", "--", "-not-an-option"]), &["fsync!"]).unwrap();
        assert!(args.flag("fsync"));
        assert_eq!(args.positional(), &["-not-an-option".to_string()]);
    }
}
