package vault

import (
	"crypto/cipher"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SaltSize           = 16
	KeySize            = chacha20poly1305.KeySize    // 32 byte (256-bit)
	NonceSize          = chacha20poly1305.NonceSizeX // 24 byte (192-bit)
	StreamIDSize       = 15                          // 15B StreamID + 8B ChunkCounter + 1B FinalFlag = 24B Nonce
	HeaderSize         = 8 + StreamIDSize            // 8B Magic + 15B StreamID = 23 byte
	ChunkSize          = 4 * 1024 * 1024             // 4 MB per chunk
	MaxCompressedChunk = ChunkSize + (ChunkSize / 8) + 65536
	MaxTextPreviewSize = 16 * 1024 * 1024 // Limite 16 MB per editor di testo
	ArgonTime          = 3
	ArgonMemory        = 64 * 1024 // 64 MB
	ArgonThreads       = 4
	VaultStreamMagic   = "SVAULT03"
)

type ProgressFunc func(processedBytes, totalBytes int64)

type FileEntry struct {
	VirtualPath  string    `json:"virtual_path"`
	BlobID       string    `json:"blob_id"`
	IsDir        bool      `json:"is_dir"`
	OriginalSize int64     `json:"original_size"`
	DiskSize     int64     `json:"disk_size"`
	ChunkSizes   []uint32  `json:"chunk_sizes,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type VaultIndex struct {
	Entries map[string]FileEntry `json:"entries"`
}

const KeyWrapAAD = "SVAULT03-KEYWRAP"

type SecureVault struct {
	mu             sync.RWMutex
	rootPath       string
	salt           []byte
	dek            []byte // Master Data Encryption Key (32B) protetta da Key Wrapping
	aead           cipher.AEAD
	encoder        *zstd.Encoder
	decoder        *zstd.Decoder
	chunkPool      sync.Pool
	index          VaultIndex
	streamListener net.Listener
	streamToken    string
}

// IntegrityReport riassume l'esito dello scrubbing Poly1305 globale
type IntegrityReport struct {
	FilesChecked   int
	ChunksVerified int
	BytesVerified  int64
	CorruptedFiles []string
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)
}

func buildChunkNonceAndAAD(streamID []byte, chunkIndex uint64, isFinal bool) (nonce []byte, aad []byte) {
	var finalByte byte
	if isFinal {
		finalByte = 0x01
	}

	nonce = make([]byte, NonceSize)
	copy(nonce[0:StreamIDSize], streamID)
	binary.BigEndian.PutUint64(nonce[StreamIDSize:StreamIDSize+8], chunkIndex)
	nonce[NonceSize-1] = finalByte

	aad = make([]byte, len(VaultStreamMagic)+8+1)
	copy(aad[0:len(VaultStreamMagic)], VaultStreamMagic)
	binary.BigEndian.PutUint64(aad[len(VaultStreamMagic):len(VaultStreamMagic)+8], chunkIndex)
	aad[len(aad)-1] = finalByte

	return nonce, aad
}
