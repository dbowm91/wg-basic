//! IdP email domain policy helpers.

/// Parses a comma-separated allow-list into trimmed, non-empty domain entries.
pub fn parse_allowed_domains(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Serializes a domain list for durable storage (comma-separated, sorted).
pub fn format_allowed_domains(domains: &[String]) -> String {
    let mut entries: Vec<&str> = domains.iter().map(String::as_str).collect();
    entries.sort_unstable();
    entries.dedup();
    entries.join(",")
}

/// Extracts the domain part of an email address (after `@`).
pub fn email_domain(email: &str) -> Option<&str> {
    let (local, domain) = email.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(domain)
}

/// Whether `email` satisfies a possibly empty allow-list (case-insensitive domain match).
pub fn email_allowed_by_domain_list(email: &str, allowed_domains: &[String]) -> bool {
    if allowed_domains.is_empty() {
        return true;
    }
    let Some(domain) = email_domain(email) else {
        return false;
    };
    allowed_domains
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(domain))
}

/// Derives a stable administrator username from an IdP email.
pub fn username_from_idp_email(email: &str) -> Option<String> {
    let email = email.trim();
    const MAX_USERNAME_BYTES: usize = 64;
    if email.is_empty() || email.len() > MAX_USERNAME_BYTES {
        return None;
    }
    if email.contains('@') {
        Some(email.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_allow_list_is_case_insensitive() {
        let domains = parse_allowed_domains("Example.COM, corp.io");
        assert!(email_allowed_by_domain_list("a@corp.io", &domains));
        assert!(email_allowed_by_domain_list("a@example.com", &domains));
        assert!(!email_allowed_by_domain_list("a@other.net", &domains));
    }

    #[test]
    fn empty_allow_list_permits_any_domain() {
        assert!(email_allowed_by_domain_list(
            "a@anywhere.example",
            &parse_allowed_domains("")
        ));
    }
}
