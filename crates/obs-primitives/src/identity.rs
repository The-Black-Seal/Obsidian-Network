//! Gmail identity canonicalisation.
//!
//! Obsidian binds exactly one mining account to one Gmail identity.  Gmail
//! itself treats several spellings as the same mailbox, so the server has to
//! agree with Gmail before it can promise that rule.  This module is the single
//! definition of "the same Gmail identity", and it is deliberately small and
//! pure so that it can be audited and tested on its own.
//!
//! The canonical form is:
//!
//! 1. Surrounding whitespace is ignored.
//! 2. The address must contain exactly one `@`.
//! 3. The local part is localised to lower case.
//! 4. Everything from the first `+` in the local part is removed (Gmail
//!    sub-addressing delivers those to the same mailbox).
//! 5. Dots in the local part are removed (Gmail ignores them).
//! 6. The domain is localised to lower case, and `googlemail.com` is mapped to
//!    `gmail.com` (Google operates both names for the same mailbox).
//! 7. The result must be `<local>@gmail.com` with a non-empty local part.
//!
//! The canonical string is then committed to with
//! [`obs_chain::chain::gmail_commitment`](obs_chain), and only the commitment
//! ever reaches the chain: the address itself is never stored on-chain, never
//! logged by the protocol and never returned by an API.

use core::fmt;

/// Why an address is not a usable Gmail identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmailError {
    /// The input was empty (or only whitespace).
    Empty,
    /// There was no `@`.
    MissingAt,
    /// There was more than one `@`.
    MultipleAt,
    /// The local part was empty, or became empty after normalisation.
    EmptyLocalPart,
    /// The domain was empty.
    EmptyDomain,
    /// The address is not a Gmail address.
    NotGmail,
    /// The address contained a character that is not allowed.
    InvalidCharacter(char),
}

impl fmt::Display for GmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GmailError::Empty => write!(f, "the email address is empty"),
            GmailError::MissingAt => write!(f, "the email address has no '@'"),
            GmailError::MultipleAt => write!(f, "the email address has more than one '@'"),
            GmailError::EmptyLocalPart => write!(f, "the email address has no local part"),
            GmailError::EmptyDomain => write!(f, "the email address has no domain"),
            GmailError::NotGmail => write!(f, "only Gmail addresses are accepted"),
            GmailError::InvalidCharacter(c) => {
                write!(f, "the email address contains an invalid character {:?}", c)
            }
        }
    }
}

impl std::error::Error for GmailError {}

/// Canonicalises a Gmail address.
///
/// Two spellings of one mailbox canonicalise to the same string, and therefore
/// to the same on-chain commitment, which is what makes "one Gmail, one mining
/// account" enforceable.
pub fn canonical_gmail(email: &str) -> Result<String, GmailError> {
    let trimmed = email.trim();
    if trimmed.is_empty() {
        return Err(GmailError::Empty);
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(GmailError::InvalidCharacter(' '));
    }
    let (local, domain) = match trimmed.split_once('@') {
        Some((local, domain)) => {
            if domain.contains('@') {
                return Err(GmailError::MultipleAt);
            }
            (local, domain)
        }
        None => return Err(GmailError::MissingAt),
    };
    if local.is_empty() {
        return Err(GmailError::EmptyLocalPart);
    }
    if domain.is_empty() {
        return Err(GmailError::EmptyDomain);
    }

    // `+tag` is delivered to the same mailbox.
    let local = match local.split_once('+') {
        Some((head, _tag)) => head,
        None => local,
    };
    // Gmail ignores dots in the local part.
    let local: String = local
        .chars()
        .filter(|c| *c != '.')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if local.is_empty() {
        return Err(GmailError::EmptyLocalPart);
    }
    for character in local.chars() {
        if !character.is_ascii_alphanumeric() {
            return Err(GmailError::InvalidCharacter(character));
        }
    }

    let domain = domain.to_ascii_lowercase();
    let domain = if domain == "googlemail.com" {
        "gmail.com".to_string()
    } else {
        domain
    };
    if domain != "gmail.com" {
        return Err(GmailError::NotGmail);
    }

    Ok(format!("{}@{}", local, domain))
}

/// True when the address canonicalises to a Gmail identity.
pub fn is_gmail(email: &str) -> bool {
    canonical_gmail(email).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_of_one_mailbox_collapse_to_one_identity() {
        let canonical = canonical_gmail("Miner.One+obsidian@Gmail.com").unwrap();
        assert_eq!(canonical, "minerone@gmail.com");
        for spelling in [
            "minerone@gmail.com",
            "MINERONE@GMAIL.COM",
            "miner.one@gmail.com",
            "miner.one+anything@gmail.com",
            "Miner.One@googlemail.com",
            "  minerone@gmail.com  ",
            "miner.one+tag+tag2@googlemail.com",
        ] {
            assert_eq!(
                canonical_gmail(spelling).unwrap(),
                canonical,
                "{} must canonicalise to the same identity",
                spelling
            );
        }
    }

    #[test]
    fn other_domains_are_refused() {
        for address in [
            "someone@example.com",
            "someone@mail.gmail.com",
            "someone@gmail.com.evil.example",
            "someone@google.com",
            "",
            "   ",
        ] {
            let result = canonical_gmail(address);
            assert!(result.is_err(), "{} must not be accepted", address);
        }
        assert_eq!(canonical_gmail("a@example.com"), Err(GmailError::NotGmail));
    }

    #[test]
    fn malformed_addresses_are_refused() {
        assert_eq!(canonical_gmail("nodomain@"), Err(GmailError::EmptyDomain));
        assert_eq!(canonical_gmail("@gmail.com"), Err(GmailError::EmptyLocalPart));
        assert_eq!(canonical_gmail("a@@gmail.com"), Err(GmailError::MultipleAt));
        assert_eq!(canonical_gmail("nobody"), Err(GmailError::MissingAt));
        assert_eq!(canonical_gmail(""), Err(GmailError::Empty));
        assert_eq!(canonical_gmail("+tag@gmail.com"), Err(GmailError::EmptyLocalPart));
        assert_eq!(canonical_gmail("....@gmail.com"), Err(GmailError::EmptyLocalPart));
        assert!(matches!(
            canonical_gmail("has space@gmail.com"),
            Err(GmailError::InvalidCharacter(_))
        ));
        assert!(matches!(
            canonical_gmail("under_score@gmail.com"),
            Err(GmailError::InvalidCharacter('_'))
        ));
        assert!(matches!(
            canonical_gmail("inject\nline@gmail.com"),
            Err(GmailError::InvalidCharacter(_))
        ));
    }

    #[test]
    fn errors_explain_themselves() {
        assert!(GmailError::NotGmail.to_string().contains("Gmail"));
        assert!(GmailError::MultipleAt.to_string().contains("'@'"));
    }

    #[test]
    fn is_gmail_matches_the_canonicaliser() {
        assert!(is_gmail("miner@gmail.com"));
        assert!(!is_gmail("miner@example.com"));
        assert!(!is_gmail(""));
    }
}
