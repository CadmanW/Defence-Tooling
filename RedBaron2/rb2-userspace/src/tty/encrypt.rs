//! Encryption support for TTY session recordings using age with SSH ed25519 keys.

use age::ssh::Recipient as SshRecipient;
use std::io::{self, Write};

/// Encrypt a buffer of plaintext bytes using the given SSH ed25519 public key.
///
/// Returns the raw age-encrypted ciphertext (not base64-encoded).
pub fn encrypt_buffer(plaintext: &[u8], pubkey: &str) -> io::Result<Vec<u8>> {
    let recipient = parse_ssh_recipient(pubkey)?;

    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .expect("recipients should not be empty");

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| io::Error::other(format!("Encryption error: {}", e)))?;

    writer.write_all(plaintext)?;
    writer
        .finish()
        .map_err(|e| io::Error::other(format!("Encryption finish error: {}", e)))?;

    Ok(encrypted)
}

/// Parse an SSH ed25519 public key from the authorized_keys format.
fn parse_ssh_recipient(pubkey: &str) -> io::Result<SshRecipient> {
    pubkey.parse::<SshRecipient>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SSH key: {:?}", e),
        )
    })
}
