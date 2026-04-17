use std::cmp::Ordering;
use std::io;
use std::path::{Path, PathBuf};
use tokio::fs;

pub const ENCRYPTED_CHUNK_EXT: &str = ".cast.age";
pub const PLAIN_CHUNK_EXT: &str = ".cast.lzma";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkDescriptor {
    pub session_id: String,
    pub seq: u64,
    pub start_unix_ns: u64,
    pub end_unix_ns: u64,
    pub encrypted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyChunk {
    pub path: PathBuf,
    pub s3_key: String,
    pub descriptor: ChunkDescriptor,
}

impl ChunkDescriptor {
    pub fn filename(&self) -> String {
        format!(
            "{}-{:020}-{:020}-{:020}{}",
            self.session_id,
            self.seq,
            self.start_unix_ns,
            self.end_unix_ns,
            self.extension(),
        )
    }

    pub const fn extension(&self) -> &'static str {
        if self.encrypted {
            ENCRYPTED_CHUNK_EXT
        } else {
            PLAIN_CHUNK_EXT
        }
    }
}

pub fn parse_chunk_name(name: &str) -> Option<ChunkDescriptor> {
    let (stem, encrypted) = if let Some(stem) = name.strip_suffix(ENCRYPTED_CHUNK_EXT) {
        (stem, true)
    } else if let Some(stem) = name.strip_suffix(PLAIN_CHUNK_EXT) {
        (stem, false)
    } else {
        return None;
    };

    let (rest, end_unix_ns) = split_last_numeric(stem)?;
    let (rest, start_unix_ns) = split_last_numeric(rest)?;
    let (session_id, seq) = split_last_numeric(rest)?;
    if session_id.is_empty() {
        return None;
    }

    Some(ChunkDescriptor {
        session_id: session_id.to_string(),
        seq,
        start_unix_ns,
        end_unix_ns,
        encrypted,
    })
}

pub fn parse_chunk_key(key: &str) -> Option<ChunkDescriptor> {
    parse_chunk_name(key.rsplit('/').next()?)
}

pub fn is_supported_chunk_key(key: &str) -> bool {
    parse_chunk_key(key).is_some()
}

pub async fn persist_chunk(
    root: &Path,
    descriptor: &ChunkDescriptor,
    payload: &[u8],
) -> io::Result<PathBuf> {
    let session_dir = root.join(&descriptor.session_id);
    fs::create_dir_all(&session_dir).await?;

    let filename = descriptor.filename();
    let final_path = session_dir.join(&filename);
    if fs::try_exists(&final_path).await? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("chunk already exists: {}", final_path.display()),
        ));
    }

    // Write to a temporary name, then atomically rename once the chunk is complete.
    let temp_path = session_dir.join(format!(".{filename}.tmp"));
    fs::write(&temp_path, payload).await?;
    fs::rename(&temp_path, &final_path).await?;
    Ok(final_path)
}

pub async fn collect_ready_chunks(root: &Path, hostname: &str) -> io::Result<Vec<ReadyChunk>> {
    if !fs::try_exists(root).await? {
        return Ok(Vec::new());
    }

    let mut chunks = Vec::new();
    let mut roots = fs::read_dir(root).await?;
    while let Some(entry) = roots.next_entry().await? {
        if !entry.file_type().await?.is_dir() {
            continue;
        }

        let mut children = fs::read_dir(entry.path()).await?;
        while let Some(child) = children.next_entry().await? {
            if !child.file_type().await?.is_file() {
                continue;
            }

            let path = child.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(descriptor) = parse_chunk_name(name) else {
                continue;
            };
            let s3_key = format!(
                "{hostname}/{}/{}",
                descriptor.session_id,
                descriptor.filename()
            );
            chunks.push(ReadyChunk {
                path,
                s3_key,
                descriptor,
            });
        }
    }

    chunks.sort_by(|left, right| compare_descriptors(&left.descriptor, &right.descriptor));
    Ok(chunks)
}

pub fn sort_chunk_keys(keys: &mut [String]) {
    keys.sort_by(|left, right| compare_chunk_keys(left, right));
}

pub fn compare_chunk_keys(left: &str, right: &str) -> Ordering {
    match (parse_chunk_key(left), parse_chunk_key(right)) {
        (Some(left_desc), Some(right_desc)) => {
            compare_descriptors(&left_desc, &right_desc).then_with(|| left.cmp(right))
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => left.cmp(right),
    }
}

fn compare_descriptors(left: &ChunkDescriptor, right: &ChunkDescriptor) -> Ordering {
    left.session_id
        .cmp(&right.session_id)
        .then_with(|| left.start_unix_ns.cmp(&right.start_unix_ns))
        .then_with(|| left.end_unix_ns.cmp(&right.end_unix_ns))
        .then_with(|| left.seq.cmp(&right.seq))
}

fn split_last_numeric(value: &str) -> Option<(&str, u64)> {
    let (head, tail) = value.rsplit_once('-')?;
    Some((head, tail.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip_preserves_metadata() {
        let descriptor = ChunkDescriptor {
            session_id: "ef8d8c8d-f9ea-44f1-bbea-14a590f9a1e5".to_string(),
            seq: 7,
            start_unix_ns: 1_700_000_000_000_000_000,
            end_unix_ns: 1_700_000_030_000_000_000,
            encrypted: true,
        };

        let parsed = parse_chunk_name(&descriptor.filename()).expect("parse chunk filename");
        assert_eq!(parsed, descriptor);
    }

    #[test]
    fn sort_chunk_keys_uses_sequence_not_listing_order() {
        let mut keys = vec![
            "host/session/session-00000000000000000002-00000000000000000030-00000000000000000040.cast.age".to_string(),
            "host/session/session-00000000000000000000-00000000000000000010-00000000000000000020.cast.age".to_string(),
            "host/session/session-00000000000000000001-00000000000000000020-00000000000000000030.cast.age".to_string(),
        ];

        sort_chunk_keys(&mut keys);

        assert!(keys[0].contains("00000000000000000000"));
        assert!(keys[1].contains("00000000000000000001"));
        assert!(keys[2].contains("00000000000000000002"));
    }

    #[test]
    fn sort_chunk_keys_uses_sequence_as_tiebreaker() {
        let mut keys = vec![
            "host/session/session-00000000000000000009-00000000000000000010-00000000000000000020.cast.age".to_string(),
            "host/session/session-00000000000000000003-00000000000000000010-00000000000000000020.cast.age".to_string(),
        ];

        sort_chunk_keys(&mut keys);

        assert!(keys[0].contains("00000000000000000003"));
        assert!(keys[1].contains("00000000000000000009"));
    }
}
