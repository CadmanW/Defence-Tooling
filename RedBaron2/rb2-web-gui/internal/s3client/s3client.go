package s3client

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"rb2-tty/internal/models"
)

const (
	encryptedChunkExt = ".cast.age"
	plainChunkExt     = ".cast.lzma"
)

type chunkKey struct {
	key         string
	host        string
	sessionID   string
	seq         uint64
	startUnixNs uint64
	endUnixNs   uint64
}

// Config holds S3/MinIO connection parameters.
type Config struct {
	Endpoint  string
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	PathStyle bool
}

// Client wraps the MinIO client for TTY session operations.
type Client struct {
	mc     *minio.Client
	bucket string
}

// New creates a new S3 session client.
func New(cfg Config) (*Client, error) {
	// Parse endpoint to extract host and determine TLS.
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint: %w", err)
	}

	host := u.Host
	secure := u.Scheme == "https"

	mc, err := minio.New(host, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("creating minio client: %w", err)
	}

	return &Client{mc: mc, bucket: cfg.Bucket}, nil
}

// ListSessions discovers all sessions in the bucket, sorted by most-recent
// end time first.
//
// Bucket layout:
//   {hostname}/{session-uuid}/{session-uuid}-{seq}-{start_unix_ns}-{end_unix_ns}.cast.age
//   {hostname}/{session-uuid}/{session-uuid}-{seq}-{start_unix_ns}-{end_unix_ns}.cast.lzma
func (c *Client) ListSessions(ctx context.Context) ([]models.Session, error) {
	sessMap := make(map[string]*models.Session)

	for obj := range c.mc.ListObjects(ctx, c.bucket, minio.ListObjectsOptions{
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("listing objects: %w", obj.Err)
		}

		meta, ok := parseChunkKey(obj.Key)
		if !ok {
			continue
		}

		pathKey := meta.host + "/" + meta.sessionID
		startTime := time.Unix(0, int64(meta.startUnixNs))
		endTime := time.Unix(0, int64(meta.endUnixNs))

		sess, ok := sessMap[pathKey]
		if !ok {
			sess = &models.Session{
				Host:      meta.host,
				SessionID: meta.sessionID,
				StartTime: startTime,
				EndTime:   endTime,
				S3Path:    pathKey,
			}
			sessMap[pathKey] = sess
		}

		sess.TotalSize += obj.Size
		sess.BlobCount++
		if startTime.Before(sess.StartTime) {
			sess.StartTime = startTime
		}
		if endTime.After(sess.EndTime) {
			sess.EndTime = endTime
		}
	}

	sessions := make([]models.Session, 0, len(sessMap))
	for _, s := range sessMap {
		s.Finalize()
		sessions = append(sessions, *s)
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].EndTime.After(sessions[j].EndTime)
	})

	return sessions, nil
}

// ListSessionKeys returns all supported tty chunk object keys under a session
// prefix, sorted chronologically by chunk metadata.
func (c *Client) ListSessionKeys(ctx context.Context, s3Path string) ([]string, error) {
	prefix := s3Path
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var chunks []chunkKey
	for obj := range c.mc.ListObjects(ctx, c.bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("listing session keys: %w", obj.Err)
		}
		if meta, ok := parseChunkKey(obj.Key); ok {
			chunks = append(chunks, meta)
		}
	}

	sort.Slice(chunks, func(i, j int) bool {
		return compareChunkKeys(chunks[i], chunks[j]) < 0
	})

	keys := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		keys = append(keys, chunk.key)
	}
	return keys, nil
}

// DownloadObject downloads a single S3 object and returns its raw bytes.
func (c *Client) DownloadObject(ctx context.Context, key string) ([]byte, error) {
	obj, err := c.mc.GetObject(ctx, c.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting object %s: %w", key, err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("reading object %s: %w", key, err)
	}
	return data, nil
}

func parseChunkKey(key string) (chunkKey, bool) {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) != 3 {
		return chunkKey{}, false
	}

	filename := parts[2]
	stem := ""
	switch {
	case strings.HasSuffix(filename, encryptedChunkExt):
		stem = strings.TrimSuffix(filename, encryptedChunkExt)
	case strings.HasSuffix(filename, plainChunkExt):
		stem = strings.TrimSuffix(filename, plainChunkExt)
	default:
		return chunkKey{}, false
	}

	rest, endUnixNs, ok := splitLastNumeric(stem)
	if !ok {
		return chunkKey{}, false
	}
	rest, startUnixNs, ok := splitLastNumeric(rest)
	if !ok {
		return chunkKey{}, false
	}
	sessionIDFromName, seq, ok := splitLastNumeric(rest)
	if !ok || sessionIDFromName != parts[1] {
		return chunkKey{}, false
	}

	return chunkKey{
		key:         key,
		host:        parts[0],
		sessionID:   parts[1],
		seq:         seq,
		startUnixNs: startUnixNs,
		endUnixNs:   endUnixNs,
	}, true
}

func splitLastNumeric(value string) (string, uint64, bool) {
	lastDash := strings.LastIndex(value, "-")
	if lastDash == -1 {
		return "", 0, false
	}
	head := value[:lastDash]
	tail := value[lastDash+1:]
	parsed, err := strconv.ParseUint(tail, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return head, parsed, true
}

func compareChunkKeys(left, right chunkKey) int {
	if left.startUnixNs != right.startUnixNs {
		if left.startUnixNs < right.startUnixNs {
			return -1
		}
		return 1
	}
	if left.endUnixNs != right.endUnixNs {
		if left.endUnixNs < right.endUnixNs {
			return -1
		}
		return 1
	}
	if left.seq != right.seq {
		if left.seq < right.seq {
			return -1
		}
		return 1
	}
	return strings.Compare(left.key, right.key)
}
