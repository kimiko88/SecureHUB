package vault

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
)

// VaultReadSeeker implementa io.ReadSeekCloser e io.ReaderAt con complessità O(1) per singolo chunk da 4 MB.
type VaultReadSeeker struct {
	mu             sync.Mutex
	vault          *SecureVault
	file           *os.File
	entry          FileEntry
	streamID       []byte
	chunkOffsets   []int64
	pos            int64
	cachedChunkIdx int64
	cachedPlain    []byte
	cipherScratch  []byte
	compScratch    []byte
}

func (v *SecureVault) OpenReadSeeker(virtualPath string) (*VaultReadSeeker, error) {
	virtualPath = normalizePath(virtualPath)

	v.mu.RLock()
	entry, exists := v.index.Entries[virtualPath]
	v.mu.RUnlock()

	if !exists || entry.IsDir {
		return nil, errors.New("file non trovato nel Vault")
	}
	if len(entry.ChunkSizes) == 0 {
		return nil, errors.New("il file non possiede una tabella chunk per il random-access")
	}

	blobPath := filepath.Join(v.rootPath, "blocks", entry.BlobID)
	f, err := os.Open(blobPath)
	if err != nil {
		return nil, err
	}

	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(f, header); err != nil {
		_ = f.Close()
		return nil, errors.New("header SVAULT03 illeggibile")
	}
	if string(header[:len(VaultStreamMagic)]) != VaultStreamMagic {
		_ = f.Close()
		return nil, errors.New("versione blocco non valida per random-access (richiesto SVAULT03)")
	}

	offsets := make([]int64, len(entry.ChunkSizes))
	curOffset := int64(HeaderSize)
	for i, cSize := range entry.ChunkSizes {
		offsets[i] = curOffset
		curOffset += 4 + int64(cSize)
	}

	return &VaultReadSeeker{
		vault:          v,
		file:           f,
		entry:          entry,
		streamID:       header[len(VaultStreamMagic):],
		chunkOffsets:   offsets,
		pos:            0,
		cachedChunkIdx: -1,
	}, nil
}

func (s *VaultReadSeeker) Size() int64 {
	return s.entry.OriginalSize
}

func (s *VaultReadSeeker) Seek(offset int64, whence int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = s.pos
	case io.SeekEnd:
		base = s.entry.OriginalSize
	default:
		return 0, errors.New("whence non valido in Seek")
	}

	// Evita overflow signed quando si sommano offset non attendibili provenienti
	// da chiamanti FUSE, parser o viewer.
	if (offset > 0 && base > int64(^uint64(0)>>1)-offset) ||
		(offset < 0 && base < (-int64(^uint64(0)>>1)-1)-offset) {
		return 0, errors.New("offset fuori intervallo in Seek")
	}
	newPos := base + offset
	if newPos < 0 {
		return 0, errors.New("seek a posizione negativa non consentito")
	}
	s.pos = newPos
	return s.pos, nil
}

func (s *VaultReadSeeker) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	if s.pos >= s.entry.OriginalSize {
		return 0, io.EOF
	}

	targetChunk := int64(s.pos / ChunkSize)
	offsetInChunk := int(s.pos % ChunkSize)

	if targetChunk >= int64(len(s.chunkOffsets)) {
		return 0, io.EOF
	}

	if s.cachedChunkIdx != targetChunk {
		if err := s.loadAndVerifyChunk(int(targetChunk)); err != nil {
			return 0, err
		}
	}

	if offsetInChunk >= len(s.cachedPlain) {
		return 0, io.EOF
	}

	n := copy(p, s.cachedPlain[offsetInChunk:])
	s.pos += int64(n)
	return n, nil
}

// ReadAt consente letture concorrenti/posizionali dirette (usato da FUSE/WinFsp e dal parser PDF).
func (s *VaultReadSeeker) ReadAt(p []byte, off int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if off < 0 {
		return 0, errors.New("offset negativo in ReadAt")
	}
	if off >= s.entry.OriginalSize {
		return 0, io.EOF
	}

	totalCopied := 0
	curOff := off

	for totalCopied < len(p) && curOff < s.entry.OriginalSize {
		targetChunk := int64(curOff / ChunkSize)
		offsetInChunk := int(curOff % ChunkSize)

		if targetChunk >= int64(len(s.chunkOffsets)) {
			break
		}
		if s.cachedChunkIdx != targetChunk {
			if err := s.loadAndVerifyChunk(int(targetChunk)); err != nil {
				return totalCopied, err
			}
		}
		if offsetInChunk >= len(s.cachedPlain) {
			break
		}

		n := copy(p[totalCopied:], s.cachedPlain[offsetInChunk:])
		totalCopied += n
		curOff += int64(n)
	}

	if totalCopied < len(p) {
		return totalCopied, io.EOF
	}
	return totalCopied, nil
}

func (s *VaultReadSeeker) loadAndVerifyChunk(chunkIdx int) error {
	diskOffset := s.chunkOffsets[chunkIdx]
	expectedCipherLen := s.entry.ChunkSizes[chunkIdx]

	totalPacketSize := 4 + int(expectedCipherLen)
	if cap(s.cipherScratch) < totalPacketSize {
		s.cipherScratch = make([]byte, totalPacketSize)
	} else {
		s.cipherScratch = s.cipherScratch[:totalPacketSize]
	}

	if _, err := s.file.ReadAt(s.cipherScratch, diskOffset); err != nil {
		return fmt.Errorf("errore ReadAt al chunk %d: %w", chunkIdx, err)
	}

	recordedLen := binary.LittleEndian.Uint32(s.cipherScratch[0:4])
	if recordedLen != expectedCipherLen {
		return fmt.Errorf("corruzione metadati al chunk %d: atteso %d, trovato %d", chunkIdx, expectedCipherLen, recordedLen)
	}

	isFinal := (chunkIdx == len(s.chunkOffsets)-1)
	nonce, aad := buildChunkNonceAndAAD(s.streamID, uint64(chunkIdx), isFinal)

	compData, err := s.vault.aead.Open(s.compScratch[:0], nonce, s.cipherScratch[4:], aad)
	if err != nil {
		return fmt.Errorf("autenticazione Poly1305 fallita in random-access al chunk %d: %w", chunkIdx, err)
	}
	s.compScratch = compData

	plainData, err := s.vault.decoder.DecodeAll(s.compScratch, s.cachedPlain[:0])
	if err != nil {
		return fmt.Errorf("errore decompressione Zstd al chunk %d: %w", chunkIdx, err)
	}

	s.cachedPlain = plainData
	s.cachedChunkIdx = int64(chunkIdx)
	return nil
}

func (s *VaultReadSeeker) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cachedPlain = nil
	s.cipherScratch = nil
	s.compScratch = nil
	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		return err
	}
	return nil
}

func (v *SecureVault) GetStreamURL(virtualPath string) (string, error) {
	v.mu.Lock()
	if v.streamListener == nil {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			v.mu.Unlock()
			return "", err
		}
		tokBytes := make([]byte, 16)
		_, _ = io.ReadFull(rand.Reader, tokBytes)
		v.streamToken = hex.EncodeToString(tokBytes)
		v.streamListener = ln

		mux := http.NewServeMux()
		mux.HandleFunc("/stream/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("token") != v.streamToken {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			vPath := r.URL.Query().Get("path")
			seeker, err := v.OpenReadSeeker(vPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			defer seeker.Close()

			http.ServeContent(w, r, filepath.Base(vPath), seeker.entry.UpdatedAt, seeker)
		})

		srv := &http.Server{Handler: mux}
		go func() {
			_ = srv.Serve(ln)
		}()
	}
	addr := v.streamListener.Addr().String()
	token := v.streamToken
	v.mu.Unlock()

	cleanPath := normalizePath(virtualPath)
	fileName := url.PathEscape(filepath.Base(cleanPath))
	streamURL := fmt.Sprintf("http://%s/stream/%s?token=%s&path=%s",
		addr, fileName, token, url.QueryEscape(cleanPath))
	return streamURL, nil
}
