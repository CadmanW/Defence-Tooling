use super::encrypt::encrypt_buffer;
use super::spool::{self, ChunkDescriptor};

use asciicastlib::{Event, Header, interval_from_ns, output_event_json_line};
use log::warn;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;

struct ActiveChunk {
    descriptor: ChunkDescriptor,
    buffer: Vec<u8>,
}

pub struct CastSession {
    spool_dir: PathBuf,
    session_id: Uuid,
    pubkey: Option<String>,
    active_chunk: Option<ActiveChunk>,
    next_seq: u64,
    last_ts_ns: u64,
    current_rows: u16,
    current_cols: u16,
    closed: bool,
}

impl CastSession {
    pub fn new_spool(
        dir: &Path,
        session_id: Uuid,
        rows: u16,
        cols: u16,
        ts_ns: u64,
        pubkey: Option<&str>,
    ) -> io::Result<Self> {
        let mut session = Self {
            spool_dir: dir.to_path_buf(),
            session_id,
            pubkey: pubkey.map(str::to_owned),
            active_chunk: None,
            next_seq: 0,
            last_ts_ns: ts_ns,
            current_rows: rows,
            current_cols: cols,
            closed: false,
        };
        session.start_chunk(rows, cols, ts_ns)?;
        Ok(session)
    }

    pub async fn write_tty_output(
        &mut self,
        ts_ns: u64,
        rows: u16,
        cols: u16,
        data: &[u8],
    ) -> io::Result<()> {
        let wall_clock_ns = unix_now_ns();
        if self.active_chunk.is_none() {
            self.current_rows = rows;
            self.current_cols = cols;
            self.start_chunk(rows, cols, ts_ns)?;
        }

        if rows != self.current_rows || cols != self.current_cols {
            let interval = interval_from_ns(ts_ns, self.last_ts_ns);
            self.last_ts_ns = ts_ns;

            let event = Event::resize(interval, cols, rows);
            match event.to_json_line() {
                Ok(json) => self.write_bytes(json.into_bytes())?,
                Err(e) => warn!("Failed to serialize resize event: {e}"),
            }

            self.current_rows = rows;
            self.current_cols = cols;
        }

        if !data.is_empty() {
            let interval = interval_from_ns(ts_ns, self.last_ts_ns);
            self.last_ts_ns = ts_ns;
            let json = output_event_json_line(interval, data);
            self.write_bytes(json.into_bytes())?;
        }

        if let Some(chunk) = self.active_chunk.as_mut() {
            chunk.descriptor.end_unix_ns = wall_clock_ns;
        }

        Ok(())
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        let Some(chunk) = self.active_chunk.as_mut() else {
            return Ok(());
        };

        let descriptor = chunk.descriptor.clone();
        let plain = chunk.buffer.clone();
        let pubkey = self.pubkey.clone();

        let payload = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
            let compressed = {
                let mut compressed = Vec::new();
                lzma_rs::lzma_compress(&mut plain.as_slice(), &mut compressed)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                compressed
            };

            let payload = if let Some(key) = pubkey {
                encrypt_buffer(&compressed, &key)?
            } else {
                compressed
            };

            Ok(payload)
        })
        .await
        .map_err(|e| io::Error::other(format!("chunk flush join: {e}")))??;

        spool::persist_chunk(&self.spool_dir, &descriptor, &payload).await?;

        self.active_chunk = None;
        Ok(())
    }

    pub async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        let result = self.flush().await;
        if result.is_ok() {
            self.closed = true;
        }
        result
    }

    fn start_chunk(&mut self, rows: u16, cols: u16, ts_ns: u64) -> io::Result<()> {
        let started_at_unix_ns = unix_now_ns();
        let descriptor = ChunkDescriptor {
            session_id: self.session_id.to_string(),
            seq: self.next_seq,
            start_unix_ns: started_at_unix_ns,
            end_unix_ns: started_at_unix_ns,
            encrypted: self.pubkey.is_some(),
        };
        self.next_seq += 1;

        let header = Self::build_header(cols, rows, started_at_unix_ns);
        let header_json = header
            .to_json_line()
            .map_err(|e| io::Error::other(format!("header JSON: {e}")))?;

        self.active_chunk = Some(ActiveChunk {
            descriptor,
            buffer: header_json.into_bytes(),
        });
        self.last_ts_ns = ts_ns;
        Ok(())
    }

    fn write_bytes(&mut self, data: Vec<u8>) -> io::Result<()> {
        let chunk = self
            .active_chunk
            .as_mut()
            .ok_or_else(|| io::Error::other("chunk buffer missing"))?;
        chunk.buffer.extend_from_slice(&data);
        Ok(())
    }

    fn build_header(cols: u16, rows: u16, started_at_unix_ns: u64) -> Header {
        Header::with_timestamp(cols, rows, (started_at_unix_ns / 1_000_000_000) as i64)
    }
}

impl Drop for CastSession {
    fn drop(&mut self) {
        if !self.closed {
            warn!("CastSession dropped without explicit close().await; pending data may be lost");
        }
    }
}

fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tty::spool;
    use std::fs;
    use std::io::Cursor;

    fn temp_spool_dir(test_name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rb2-cast-{test_name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create temp spool dir");
        dir
    }

    fn decode_plain_chunk(path: &Path) -> String {
        let data = fs::read(path).expect("read chunk");
        let mut plain = Vec::new();
        lzma_rs::lzma_decompress(&mut Cursor::new(data), &mut plain).expect("decompress chunk");
        String::from_utf8(plain).expect("chunk text")
    }

    #[tokio::test]
    async fn flush_rotates_to_distinct_chunk_files() {
        let spool_dir = temp_spool_dir("flush-rotates");
        let session_id = Uuid::new_v4();
        let mut session = CastSession::new_spool(&spool_dir, session_id, 24, 80, 0, None).unwrap();

        session
            .write_tty_output(10, 24, 80, b"first line\n")
            .await
            .unwrap();
        session.flush().await.unwrap();

        session
            .write_tty_output(20, 24, 80, b"second line\n")
            .await
            .unwrap();
        session.close().await.unwrap();

        let chunks = spool::collect_ready_chunks(&spool_dir, "host")
            .await
            .unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].descriptor.seq, 0);
        assert_eq!(chunks[1].descriptor.seq, 1);

        let first = decode_plain_chunk(&chunks[0].path);
        let second = decode_plain_chunk(&chunks[1].path);
        assert!(first.lines().next().unwrap_or_default().starts_with('{'));
        assert!(second.lines().next().unwrap_or_default().starts_with('{'));
        assert!(first.contains("first line"));
        assert!(second.contains("second line"));
    }

    #[tokio::test]
    async fn close_flushes_pending_chunk() {
        let spool_dir = temp_spool_dir("close-flushes");
        let session_id = Uuid::new_v4();
        let mut session = CastSession::new_spool(&spool_dir, session_id, 24, 80, 0, None).unwrap();

        session
            .write_tty_output(15, 24, 80, b"pending chunk\n")
            .await
            .unwrap();
        session.close().await.unwrap();

        let chunks = spool::collect_ready_chunks(&spool_dir, "host")
            .await
            .unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(decode_plain_chunk(&chunks[0].path).contains("pending chunk"));
    }
}
