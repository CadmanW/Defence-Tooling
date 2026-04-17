package s3client

import "testing"

func TestParseChunkKeySupportsEncryptedAndPlainChunks(t *testing.T) {
	tests := []string{
		"host/session-123/session-123-00000000000000000003-00000000000000000010-00000000000000000020.cast.age",
		"host/session-123/session-123-00000000000000000004-00000000000000000020-00000000000000000030.cast.lzma",
	}

	for _, key := range tests {
		meta, ok := parseChunkKey(key)
		if !ok {
			t.Fatalf("expected %q to parse", key)
		}
		if meta.host != "host" || meta.sessionID != "session-123" {
			t.Fatalf("unexpected parsed metadata for %q: %#v", key, meta)
		}
	}
}

func TestCompareChunkKeysSortsByTimeThenSequence(t *testing.T) {
	late, _ := parseChunkKey("host/session/session-00000000000000000009-00000000000000000020-00000000000000000030.cast.age")
	earlyHighSeq, _ := parseChunkKey("host/session/session-00000000000000000009-00000000000000000010-00000000000000000020.cast.age")
	earlyLowSeq, _ := parseChunkKey("host/session/session-00000000000000000003-00000000000000000010-00000000000000000020.cast.age")

	if compareChunkKeys(earlyLowSeq, earlyHighSeq) >= 0 {
		t.Fatalf("expected lower sequence to win when timestamps tie")
	}
	if compareChunkKeys(earlyHighSeq, late) >= 0 {
		t.Fatalf("expected earlier chunk time to sort first")
	}
}

func TestParseChunkKeyRejectsMismatchedSessionID(t *testing.T) {
	key := "host/session-a/session-b-00000000000000000001-00000000000000000010-00000000000000000020.cast.age"
	if _, ok := parseChunkKey(key); ok {
		t.Fatalf("expected mismatched session id in filename to be rejected")
	}
}
