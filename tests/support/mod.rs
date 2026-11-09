//! Fake credentials for tests.
//!
//! The fragments are assembled at runtime so the source tree does not contain
//! complete token-shaped strings that would trip secret scanning.

pub fn aws_key() -> String {
    ["AKIA", "ABCDEFGHIJKLMNOP"].concat()
}

pub fn github_token() -> String {
    ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
}

pub fn stripe_key() -> String {
    ["sk_", "live_", "51H8xYzABC1234567890abcd"].concat()
}

pub fn openai_key() -> String {
    ["sk-", "proj-", "abcdefghijklmnopqrstuvwxyz123456"].concat()
}

pub fn anthropic_key() -> String {
    ["sk-", "ant-", "api03-abcdefghijklmnopqrstuvwxyz123456"].concat()
}

pub fn jwt() -> String {
    [
        "eyJhbGciOiJIUzI1NiJ9",
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "signature1234567890",
    ]
    .join(".")
}
