//! Header names from before the rename to Twigpine, next to their new names.
//!
//! The node sends every one of these under both names, so a client or a
//! webhook receiver written against the old names keeps working. Clients in
//! this repo read the new name first and fall back to the old one, so they
//! also work against a node that predates the rename.
//!
//! Everything about the old names lives here, so dropping them later is one
//! deletion.

/// Response header naming why the node refused a request. Lowercase, as HTTP
/// libraries normalise header names.
pub const ERROR: &str = "x-twigpine-error";

/// [`ERROR`] before the rename.
pub const LEGACY_ERROR: &str = "x-gitlawb-error";

/// Response header on git smart-HTTP answers.
pub const NODE: &str = "x-twigpine-node";

/// [`NODE`] before the rename.
pub const LEGACY_NODE: &str = "x-gitlawb-node";

/// The names to try, in order, when reading the error header from a node that
/// may be older than the rename: current name first.
pub const ERROR_READ_ORDER: [&str; 2] = [ERROR, LEGACY_ERROR];

/// Response headers the node sends under both names: `(name, old name)`.
pub const RESPONSE_PAIRS: [(&str, &str); 2] = [(ERROR, LEGACY_ERROR), (NODE, LEGACY_NODE)];

/// Webhook delivery headers, sent under both names: `(name, old name)`.
pub const WEBHOOK_EVENT: (&str, &str) = ("X-Twigpine-Event", "X-Gitlawb-Event");
pub const WEBHOOK_DELIVERY: (&str, &str) = ("X-Twigpine-Delivery", "X-Gitlawb-Delivery");
pub const WEBHOOK_SIGNATURE: (&str, &str) = ("X-Twigpine-Signature-256", "X-Gitlawb-Signature-256");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pair_differs_only_by_the_prefix() {
        let webhook = [WEBHOOK_EVENT, WEBHOOK_DELIVERY, WEBHOOK_SIGNATURE];
        for (new, old) in RESPONSE_PAIRS.iter().chain(webhook.iter()) {
            let new = new.to_ascii_lowercase();
            let old = old.to_ascii_lowercase();
            assert_eq!(
                new.strip_prefix("x-twigpine-"),
                old.strip_prefix("x-gitlawb-"),
                "{new} / {old}"
            );
            assert!(new.starts_with("x-twigpine-"), "{new}");
        }
    }
}
