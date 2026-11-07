package main

// func main() {
// 	files := map[string]string{
// 		"go.mod":                            goModContent,
// 		"main.go":                           mainGoContent,
// 		"internal/usb/format.go":            usbFormatContent,
// 		"internal/vault/types.go":           vaultTypesContent,
// 		"internal/vault/crypto_parallel.go": vaultCryptoParallelContent,
// 		"internal/vault/seeker.go":          vaultSeekerContent,
// 		"internal/vault/vault.go":           vaultCoreContent,
// 		"internal/vault/vault_test.go":      vaultTestContent,
// 		"internal/fuse/mount.go":            fuseMountContent,
// 		"internal/ui/preview.go":            uiPreviewContent,
// 		"internal/ui/app.go":                uiAppContent,
// 	}

// 	fmt.Println("=== Generazione del progetto modulare SecureUSB (SVAULT03) ===")
// 	for relPath, content := range files {
// 		fullPath := filepath.FromSlash(relPath)
// 		dir := filepath.Dir(fullPath)
// 		if dir != "." {
// 			if err := os.MkdirAll(dir, 0755); err != nil {
// 				fmt.Fprintf(os.Stderr, "Errore creazione cartella %s: %v\n", dir, err)
// 				os.Exit(1)
// 			}
// 		}
// 		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
// 			fmt.Fprintf(os.Stderr, "Errore scrittura file %s: %v\n", fullPath, err)
// 			os.Exit(1)
// 		}
// 		fmt.Printf(" [OK] Creato %s (%d byte)\n", relPath, len(content))
// 	}

// 	fmt.Println("\nProgetto generato con successo! Comandi successivi:")
// 	fmt.Println("  1. go mod tidy")
// 	fmt.Println("  2. go test -v ./internal/vault/...")
// 	fmt.Println("  3. go test -fuzz=FuzzVaultRoundTripAndSeeker -fuzztime=10s ./internal/vault")
// 	fmt.Println("  4. go test -bench=. -benchmem ./internal/vault")
// 	fmt.Println("  5. go build -ldflags=\"-s -w\" -o secureusb .")
// }

const goModContent = `module secureusb

go 1.22

require (
	fyne.io/fyne/v2 v2.5.3
	github.com/klauspost/compress v1.17.11
	github.com/winfsp/cgofuse v1.5.0
	golang.org/x/crypto v0.31.0
)
`

const mainGoContent = `package main

import "secureusb/internal/ui"

func main() {
	ui.Run()
}
`

const usbFormatContent = `package usb

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// FormatPhysicalUSB formatta fisicamente la chiavetta in exFAT su Windows, Linux e macOS.
func FormatPhysicalUSB(devicePath, label string) error {
	devicePath = strings.TrimSpace(devicePath)
	if devicePath == "" {
		return errors.New("specificare il percorso del dispositivo (es. E:, /dev/sdb1, /dev/disk2)")
	}
	if label == "" {
		label = "SECURE_USB"
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", "format", devicePath, "/FS:exFAT", "/V:"+label, "/Q", "/Y")
	case "linux":
		cmd = exec.Command("mkfs.exfat", "-n", label, devicePath)
	case "darwin":
		cmd = exec.Command("diskutil", "eraseDisk", "ExFAT", label, devicePath)
	default:
		return fmt.Errorf("sistema operativo non supportato: %s", runtime.GOOS)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("errore formattazione (%v): %s", err, string(out))
	}
	return nil
}
`

const vaultTypesContent = `package vault

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
	KeySize            = chacha20poly1305.KeySize   // 32 byte (256-bit)
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
	VirtualPath  string    ` + "`json:\"virtual_path\"`" + `
	BlobID       string    ` + "`json:\"blob_id\"`" + `
	IsDir        bool      ` + "`json:\"is_dir\"`" + `
	OriginalSize int64     ` + "`json:\"original_size\"`" + `
	DiskSize     int64     ` + "`json:\"disk_size\"`" + `
	ChunkSizes   []uint32  ` + "`json:\"chunk_sizes,omitempty\"`" + `
	UpdatedAt    time.Time ` + "`json:\"updated_at\"`" + `
}

type VaultIndex struct {
	Entries map[string]FileEntry ` + "`json:\"entries\"`" + `
}

type SecureVault struct {
	mu             sync.RWMutex
	rootPath       string
	salt           []byte
	aead           cipher.AEAD
	encoder        *zstd.Encoder
	decoder        *zstd.Decoder
	chunkPool      sync.Pool
	index          VaultIndex
	streamListener net.Listener
	streamToken    string
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
`

const vaultCryptoParallelContent = `package vault

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
)

type encJob struct {
	chunkIndex uint64
	plainBuf   *[]byte
	plainLen   int
	isFinal    bool
	resCh      chan encResult
}

type encResult struct {
	cipherPacket []byte
	plainLen     int
	err          error
}

// encryptStreamParallel comprime e cifra blocchi da 4 MB in parallelo su tutti i core CPU.
func (v *SecureVault) encryptStreamParallel(
	src io.Reader,
	dst io.Writer,
	totalSize int64,
	onProgress ProgressFunc,
) (int64, int64, []uint32, error) {

	streamID := make([]byte, StreamIDSize)
	if _, err := io.ReadFull(rand.Reader, streamID); err != nil {
		return 0, 0, nil, err
	}

	var diskWritten int64
	if n, err := dst.Write([]byte(VaultStreamMagic)); err != nil {
		return 0, 0, nil, err
	} else {
		diskWritten += int64(n)
	}
	if n, err := dst.Write(streamID); err != nil {
		return 0, 0, nil, err
	} else {
		diskWritten += int64(n)
	}

	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}

	jobCh := make(chan encJob, workers)
	orderCh := make(chan chan encResult, workers*2)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var compScratch []byte
			for job := range jobCh {
				plainSlice := (*job.plainBuf)[:job.plainLen]
				compScratch = v.encoder.EncodeAll(plainSlice, compScratch[:0])
				v.chunkPool.Put(job.plainBuf)

				nonce, aad := buildChunkNonceAndAAD(streamID, job.chunkIndex, job.isFinal)

				cipherLen := len(compScratch) + v.aead.Overhead()
				packet := make([]byte, 4+cipherLen)
				binary.LittleEndian.PutUint32(packet[0:4], uint32(cipherLen))
				v.aead.Seal(packet[4:4], nonce, compScratch, aad)

				job.resCh <- encResult{
					cipherPacket: packet,
					plainLen:     job.plainLen,
				}
			}
		}()
	}

	var readErrOut error
	go func() {
		defer close(jobCh)
		defer close(orderCh)

		br := bufio.NewReaderSize(src, 128*1024)
		var chunkIndex uint64

		for {
			bufPtr := v.chunkPool.Get().(*[]byte)
			buf := *bufPtr

			readBytes, readErr := io.ReadFull(br, buf)
			if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
				v.chunkPool.Put(bufPtr)
				readErrOut = readErr
				return
			}

			_, peekErr := br.Peek(1)
			isFinal := (readErr == io.EOF || readErr == io.ErrUnexpectedEOF || peekErr == io.EOF)

			resCh := make(chan encResult, 1)
			orderCh <- resCh
			jobCh <- encJob{
				chunkIndex: chunkIndex,
				plainBuf:   bufPtr,
				plainLen:   readBytes,
				isFinal:    isFinal,
				resCh:      resCh,
			}

			if isFinal {
				break
			}
			chunkIndex++
		}
	}()

	var totalPlain int64
	var chunkSizes []uint32
	var writeErr error

	for resCh := range orderCh {
		res := <-resCh
		if writeErr != nil {
			continue
		}
		if res.err != nil {
			writeErr = res.err
			continue
		}

		if n, err := dst.Write(res.cipherPacket); err != nil {
			writeErr = err
			continue
		} else {
			diskWritten += int64(n)
		}

		cipherOnlyLen := uint32(len(res.cipherPacket) - 4)
		chunkSizes = append(chunkSizes, cipherOnlyLen)
		totalPlain += int64(res.plainLen)

		if onProgress != nil {
			onProgress(totalPlain, totalSize)
		}
	}

	wg.Wait()

	if readErrOut != nil {
		return totalPlain, diskWritten, nil, readErrOut
	}
	if writeErr != nil {
		return totalPlain, diskWritten, nil, writeErr
	}
	return totalPlain, diskWritten, chunkSizes, nil
}

type decJob struct {
	chunkIndex uint64
	cipherData []byte
	resCh      chan decResult
}

type decResult struct {
	plainData []byte
	isFinal   bool
	err       error
}

// decryptStreamParallel autentica e decomprime i chunk da 4 MB in parallelo su tutti i core CPU.
func (v *SecureVault) decryptStreamParallel(
	src io.Reader,
	dst io.Writer,
	totalPlainSize int64,
	onProgress ProgressFunc,
) error {

	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return errors.New("intestazione del flusso mancante o corrotta")
	}
	if string(header[:len(VaultStreamMagic)]) != VaultStreamMagic {
		return errors.New("formato del blocco non riconosciuto (richiesto SVAULT03)")
	}
	streamID := header[len(VaultStreamMagic):]

	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}

	jobCh := make(chan decJob, workers)
	orderCh := make(chan chan decResult, workers*2)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var compScratch []byte
			for job := range jobCh {
				isFinal := false
				nonce, aad := buildChunkNonceAndAAD(streamID, job.chunkIndex, false)
				compData, authErr := v.aead.Open(compScratch[:0], nonce, job.cipherData, aad)
				if authErr != nil {
					nonceFinal, aadFinal := buildChunkNonceAndAAD(streamID, job.chunkIndex, true)
					compData, authErr = v.aead.Open(compScratch[:0], nonceFinal, job.cipherData, aadFinal)
					if authErr != nil {
						job.resCh <- decResult{
							err: fmt.Errorf("autenticazione Poly1305 fallita al chunk %d: dati manomessi o password errata", job.chunkIndex),
						}
						continue
					}
					isFinal = true
				}
				compScratch = compData

				plainData, err := v.decoder.DecodeAll(compScratch, nil)
				if err != nil {
					job.resCh <- decResult{
						err: fmt.Errorf("errore decompressione Zstd al chunk %d: %w", job.chunkIndex, err),
					}
					continue
				}

				job.resCh <- decResult{
					plainData: plainData,
					isFinal:   isFinal,
				}
			}
		}()
	}

	var readErrOut error
	go func() {
		defer close(jobCh)
		defer close(orderCh)

		var lenBuf [4]byte
		var chunkIndex uint64

		for {
			_, err := io.ReadFull(src, lenBuf[:])
			if err == io.EOF {
				break
			}
			if err != nil {
				readErrOut = fmt.Errorf("errore lettura lunghezza chunk %d: %w", chunkIndex, err)
				return
			}

			packetLen := binary.LittleEndian.Uint32(lenBuf[:])
			if packetLen == 0 || packetLen > uint32(MaxCompressedChunk+v.aead.Overhead()) {
				readErrOut = fmt.Errorf("dimensione chunk %d fuori scala (%d byte)", chunkIndex, packetLen)
				return
			}

			cipherBuf := make([]byte, packetLen)
			if _, err := io.ReadFull(src, cipherBuf); err != nil {
				readErrOut = fmt.Errorf("chunk %d troncato su disco: %w", chunkIndex, err)
				return
			}

			resCh := make(chan decResult, 1)
			orderCh <- resCh
			jobCh <- decJob{
				chunkIndex: chunkIndex,
				cipherData: cipherBuf,
				resCh:      resCh,
			}
			chunkIndex++
		}
	}()

	var writtenPlain int64
	var sawFinal bool
	var procErr error

	for resCh := range orderCh {
		res := <-resCh
		if procErr != nil {
			continue
		}
		if res.err != nil {
			procErr = res.err
			continue
		}
		if sawFinal {
			procErr = errors.New("rilevati chunk aggiuntivi non autorizzati dopo il flag EOF")
			continue
		}
		if res.isFinal {
			sawFinal = true
		}

		if _, err := dst.Write(res.plainData); err != nil {
			procErr = err
			continue
		}
		writtenPlain += int64(len(res.plainData))

		if onProgress != nil {
			onProgress(writtenPlain, totalPlainSize)
		}
	}

	wg.Wait()

	if procErr != nil {
		return procErr
	}
	if readErrOut != nil {
		return readErrOut
	}
	if !sawFinal {
		return errors.New("troncamento anomalo rilevato: flag di fine flusso (EOF) mancante")
	}
	return nil
}
`

const vaultSeekerContent = `package vault

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

	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = s.pos + offset
	case io.SeekEnd:
		newPos = s.entry.OriginalSize + offset
	default:
		return 0, errors.New("whence non valido in Seek")
	}

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
`

const vaultCoreContent = `package vault

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
)

func InitOrOpenVault(usbMountPath, password string, createNew bool) (*SecureVault, error) {
	vaultDir := filepath.Join(usbMountPath, ".secure_vault")
	blocksDir := filepath.Join(vaultDir, "blocks")
	saltFile := filepath.Join(vaultDir, "vault.salt")
	indexFile := filepath.Join(vaultDir, "index.meta")

	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, err
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}

	v := &SecureVault{
		rootPath: vaultDir,
		encoder:  encoder,
		decoder:  decoder,
		chunkPool: sync.Pool{
			New: func() any {
				buf := make([]byte, ChunkSize)
				return &buf
			},
		},
		index: VaultIndex{Entries: make(map[string]FileEntry)},
	}

	if createNew {
		_ = os.RemoveAll(vaultDir)
		if err := os.MkdirAll(blocksDir, 0700); err != nil {
			return nil, fmt.Errorf("impossibile creare le cartelle sulla USB: %w", err)
		}

		v.salt = make([]byte, SaltSize)
		if _, err := io.ReadFull(rand.Reader, v.salt); err != nil {
			return nil, err
		}
		if err := os.WriteFile(saltFile, v.salt, 0600); err != nil {
			return nil, err
		}

		key := deriveKey(password, v.salt)
		v.aead, err = chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}

		if err := v.saveIndexLocked(); err != nil {
			return nil, err
		}
		return v, nil
	}

	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		return nil, errors.New("nessun Vault trovato in questo percorso: usa 'Inizializza Nuovo Vault'")
	}

	v.salt, err = os.ReadFile(saltFile)
	if err != nil || len(v.salt) != SaltSize {
		return nil, errors.New("file salt corrotto o illeggibile")
	}

	key := deriveKey(password, v.salt)
	v.aead, err = chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	if err := v.loadIndex(); err != nil {
		return nil, errors.New("password errata o indice corrotto")
	}

	return v, nil
}

func (v *SecureVault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.streamListener != nil {
		_ = v.streamListener.Close()
		v.streamListener = nil
	}
}

func (v *SecureVault) Stat(virtualPath string) (FileEntry, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	virtualPath = normalizePath(virtualPath)
	if virtualPath == "/" {
		return FileEntry{VirtualPath: "/", IsDir: true, UpdatedAt: time.Now()}, true
	}
	e, ok := v.index.Entries[virtualPath]
	return e, ok
}

func (v *SecureVault) Rename(oldPath, newPath string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	oldPath = normalizePath(oldPath)
	newPath = normalizePath(newPath)
	if oldPath == "/" || newPath == "/" {
		return errors.New("impossibile rinominare la radice")
	}

	entry, exists := v.index.Entries[oldPath]
	if !exists {
		return errors.New("percorso origine non trovato")
	}

	entry.VirtualPath = newPath
	entry.UpdatedAt = time.Now()
	v.index.Entries[newPath] = entry
	delete(v.index.Entries, oldPath)

	if entry.IsDir {
		prefix := oldPath + "/"
		for k, child := range v.index.Entries {
			if strings.HasPrefix(k, prefix) {
				sub := strings.TrimPrefix(k, oldPath)
				newChildPath := normalizePath(newPath + sub)
				child.VirtualPath = newChildPath
				v.index.Entries[newChildPath] = child
				delete(v.index.Entries, k)
			}
		}
	}

	return v.saveIndexLocked()
}

func (v *SecureVault) WriteStream(virtualPath string, src io.Reader, expectedSize int64, onProgress ProgressFunc) error {
	virtualPath = normalizePath(virtualPath)

	v.mu.RLock()
	existing, exists := v.index.Entries[virtualPath]
	v.mu.RUnlock()

	blobID := existing.BlobID
	if !exists || blobID == "" {
		rnd := make([]byte, 16)
		_, _ = io.ReadFull(rand.Reader, rnd)
		blobID = hex.EncodeToString(rnd) + ".bin"
	}

	blobPath := filepath.Join(v.rootPath, "blocks", blobID)
	tmpBlob := fmt.Sprintf("%s.%d.tmp", blobPath, time.Now().UnixNano())

	outFile, err := os.OpenFile(tmpBlob, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	bw := bufio.NewWriterSize(outFile, 1024*1024)
	plainSize, diskSize, chunkSizes, streamErr := v.encryptStreamParallel(src, bw, expectedSize, onProgress)
	if streamErr == nil {
		streamErr = bw.Flush()
	}
	if streamErr == nil {
		streamErr = outFile.Sync()
	}
	_ = outFile.Close()

	if streamErr != nil {
		_ = os.Remove(tmpBlob)
		return streamErr
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if err := os.Rename(tmpBlob, blobPath); err != nil {
		_ = os.Remove(tmpBlob)
		return err
	}

	v.index.Entries[virtualPath] = FileEntry{
		VirtualPath:  virtualPath,
		BlobID:       blobID,
		IsDir:        false,
		OriginalSize: plainSize,
		DiskSize:     diskSize,
		ChunkSizes:   chunkSizes,
		UpdatedAt:    time.Now(),
	}

	return v.saveIndexLocked()
}

func (v *SecureVault) ReadStream(virtualPath string, dst io.Writer, onProgress ProgressFunc) error {
	virtualPath = normalizePath(virtualPath)

	v.mu.RLock()
	entry, exists := v.index.Entries[virtualPath]
	v.mu.RUnlock()

	if !exists || entry.IsDir {
		return errors.New("file non trovato nel Vault")
	}

	blobPath := filepath.Join(v.rootPath, "blocks", entry.BlobID)
	inFile, err := os.Open(blobPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	br := bufio.NewReaderSize(inFile, 1024*1024)
	return v.decryptStreamParallel(br, dst, entry.OriginalSize, onProgress)
}

func (v *SecureVault) WriteFile(virtualPath string, data []byte) error {
	return v.WriteStream(virtualPath, bytes.NewReader(data), int64(len(data)), nil)
}

func (v *SecureVault) ReadFile(virtualPath string) ([]byte, error) {
	var buf bytes.Buffer
	if err := v.ReadStream(virtualPath, &buf, nil); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v *SecureVault) saveIndexLocked() error {
	rawJSON, err := json.Marshal(v.index)
	if err != nil {
		return err
	}
	indexFile := filepath.Join(v.rootPath, "index.meta")
	tmpFile := indexFile + ".tmp"

	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, _, _, streamErr := v.encryptStreamParallel(bytes.NewReader(rawJSON), f, int64(len(rawJSON)), nil)
	_ = f.Close()
	if streamErr != nil {
		_ = os.Remove(tmpFile)
		return streamErr
	}
	return os.Rename(tmpFile, indexFile)
}

func (v *SecureVault) loadIndex() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	indexFile := filepath.Join(v.rootPath, "index.meta")
	f, err := os.Open(indexFile)
	if err != nil {
		return err
	}
	defer f.Close()

	var buf bytes.Buffer
	if err := v.decryptStreamParallel(f, &buf, 0, nil); err != nil {
		return err
	}
	return json.Unmarshal(buf.Bytes(), &v.index)
}

func normalizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = filepath.ToSlash(filepath.Clean(p))
	if p == "." {
		return "/"
	}
	return p
}

func (v *SecureVault) CreateDir(virtualDir string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	virtualDir = normalizePath(virtualDir)
	if virtualDir == "/" {
		return nil
	}
	if _, exists := v.index.Entries[virtualDir]; exists {
		return errors.New("il percorso esiste già")
	}

	v.index.Entries[virtualDir] = FileEntry{
		VirtualPath: virtualDir,
		IsDir:       true,
		UpdatedAt:   time.Now(),
	}
	return v.saveIndexLocked()
}

func (v *SecureVault) Delete(virtualPath string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	virtualPath = normalizePath(virtualPath)
	prefix := virtualPath + "/"

	for pathKey, entry := range v.index.Entries {
		if pathKey == virtualPath || strings.HasPrefix(pathKey, prefix) {
			if !entry.IsDir && entry.BlobID != "" {
				blobPath := filepath.Join(v.rootPath, "blocks", entry.BlobID)
				SecureEraseFile(blobPath)
			}
			delete(v.index.Entries, pathKey)
		}
	}
	return v.saveIndexLocked()
}

func (v *SecureVault) ListDir(dirPath string) []FileEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()

	dirPath = normalizePath(dirPath)
	var list []FileEntry

	for _, entry := range v.index.Entries {
		parent := normalizePath(filepath.Dir(entry.VirtualPath))
		if parent == dirPath && entry.VirtualPath != "/" {
			list = append(list, entry)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].IsDir != list[j].IsDir {
			return list[i].IsDir
		}
		return strings.ToLower(list[i].VirtualPath) < strings.ToLower(list[j].VirtualPath)
	})
	return list
}

func SecureEraseFile(path string) {
	info, err := os.Stat(path)
	if err == nil && info.Size() > 0 {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0600); err == nil {
			zeroBuf := make([]byte, 1024*1024)
			remaining := info.Size()
			for remaining > 0 {
				toWrite := int64(len(zeroBuf))
				if remaining < toWrite {
					toWrite = remaining
				}
				if _, err := f.Write(zeroBuf[:toWrite]); err != nil {
					break
				}
				remaining -= toWrite
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}
`

const vaultTestContent = `package vault

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// 1. UNIT TESTS
// ============================================================================

func TestChunkNonceAndAAD_Unit(t *testing.T) {
	streamID := []byte("0123456789abcde") // 15 byte
	n1, a1 := buildChunkNonceAndAAD(streamID, 0, false)
	n2, a2 := buildChunkNonceAndAAD(streamID, 1, false)
	n3, a3 := buildChunkNonceAndAAD(streamID, 1, true)

	if len(n1) != NonceSize {
		t.Fatalf("lunghezza nonce errata: got %d, want %d", len(n1), NonceSize)
	}
	if bytes.Equal(n1, n2) || bytes.Equal(a1, a2) {
		t.Fatal("chunk con indici diversi devono produrre Nonce e AAD differenti")
	}
	if bytes.Equal(n2, n3) || bytes.Equal(a2, a3) {
		t.Fatal("flag EOF diverso deve modificare sia Nonce che AAD")
	}
}

func TestNormalizePath_Unit(t *testing.T) {
	cases := map[string]string{
		"\\Documenti\\test.txt": "/Documenti/test.txt",
		"video/clip.mp4":        "/video/clip.mp4",
		"/a/b/../c.bin":         "/a/c.bin",
		"":                      "/",
		".":                     "/",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// ============================================================================
// 2. INTEGRATION TESTS (Pipeline Multi-Core Multi-Chunk + Rilevamento Manomissioni)
// ============================================================================

func TestParallelPipelineMultiChunk_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	v, err := InitOrOpenVault(tmpDir, "Passw0rd-Sicura-2026!", true)
	if err != nil {
		t.Fatalf("InitOrOpenVault fallito: %v", err)
	}
	defer v.Close()

	// Genera 10.5 MB di dati misti (attraversa 3 chunk da 4 MB: 4MB + 4MB + 2.5MB)
	totalSize := 2*ChunkSize + (ChunkSize / 2) + 12345
	original := make([]byte, totalSize)
	// Prima metà comprimibile, seconda metà entropia casuale
	for i := 0; i < totalSize/2; i++ {
		original[i] = byte(i % 251)
	}
	_, _ = rand.Read(original[totalSize/2:])

	if err := v.WriteFile("/dataset/multichunk.bin", original); err != nil {
		t.Fatalf("WriteFile multi-core fallito: %v", err)
	}

	entry, ok := v.Stat("/dataset/multichunk.bin")
	if !ok {
		t.Fatal("file non trovato nell'indice dopo WriteFile")
	}
	if len(entry.ChunkSizes) != 3 {
		t.Fatalf("attesi 3 chunk da 4 MB, trovati %d", len(entry.ChunkSizes))
	}

	decrypted, err := v.ReadFile("/dataset/multichunk.bin")
	if err != nil {
		t.Fatalf("ReadFile multi-core fallito: %v", err)
	}
	if !bytes.Equal(original, decrypted) {
		t.Fatal("i dati decifrati in parallelo non corrispondono al payload originale")
	}
}

func TestTamperAndTruncationDetection_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	v, err := InitOrOpenVault(tmpDir, "ChiaveSegreta123!", true)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	payload := bytes.Repeat([]byte("PatternCriticoDiSicurezza"), (ChunkSize/20)+50000)
	if err := v.WriteFile("/sec.bin", payload); err != nil {
		t.Fatal(err)
	}

	entry, _ := v.Stat("/sec.bin")
	blobPath := filepath.Join(tmpDir, ".secure_vault", "blocks", entry.BlobID)
	rawDisk, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test Bit-Flip a metà del primo chunk
	corrupted := append([]byte(nil), rawDisk...)
	corrupted[HeaderSize+50] ^= 0xFF
	if err := os.WriteFile(blobPath, corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadFile("/sec.bin"); err == nil {
		t.Fatal("la decifratura avrebbe dovuto fallire su blocco manomesso (Poly1305)")
	}

	// 2. Test Troncamento del secondo chunk (rimozione flag EOF)
	firstChunkTotal := HeaderSize + 4 + int(entry.ChunkSizes[0])
	truncated := rawDisk[:firstChunkTotal]
	if err := os.WriteFile(blobPath, truncated, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadFile("/sec.bin"); err == nil {
		t.Fatal("la decifratura avrebbe dovuto rilevare il troncamento prematuro (EOF mancante)")
	}
}

// ============================================================================
// 3. END-TO-END (E2E) TEST (Ciclo di vita completo + Seeker O(1) + HTTP Range)
// ============================================================================

func TestEndToEndLifecycle_E2E(t *testing.T) {
	tmpDir := t.TempDir()
	password := "E2E-MasterKey-99!"

	// 1. Creazione Vault e struttura directory
	v, err := InitOrOpenVault(tmpDir, password, true)
	if err != nil {
		t.Fatalf("creazione vault fallita: %v", err)
	}
	if err := v.CreateDir("/Video"); err != nil {
		t.Fatal(err)
	}

	// 2. Scrittura video simulato da 9 MB (3 chunk)
	videoData := make([]byte, 2*ChunkSize+1024*1024)
	for i := range videoData {
		videoData[i] = byte((i * 31) & 0xFF)
	}
	if err := v.WriteFile("/Video/film.mp4", videoData); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// 3. Tentativo di riapertura con password errata
	if _, err := InitOrOpenVault(tmpDir, "PasswordSbagliata", false); err == nil {
		t.Fatal("apertura con password errata non bloccata")
	}

	// 4. Riapertura con password corretta
	v2, err := InitOrOpenVault(tmpDir, password, false)
	if err != nil {
		t.Fatalf("riapertura vault fallita: %v", err)
	}
	defer v2.Close()

	// 5. Verifica Random-Access Seeker O(1) a cavallo del confine tra chunk 0 e chunk 1
	seeker, err := v2.OpenReadSeeker("/Video/film.mp4")
	if err != nil {
		t.Fatal(err)
	}
	defer seeker.Close()

	boundaryOffset := int64(ChunkSize - 128)
	if _, err := seeker.Seek(boundaryOffset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	sliceBuf := make([]byte, 512)
	if _, err := io.ReadFull(seeker, sliceBuf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sliceBuf, videoData[boundaryOffset:boundaryOffset+512]) {
		t.Fatal("mismatch nei dati letti tramite Seek sul confine dei 4 MB")
	}

	// 6. Verifica Server HTTP di Streaming con header "Range: bytes=..."
	streamURL, err := v2.GetStreamURL("/Video/film.mp4")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", streamURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rangeStart := int64(ChunkSize + 5000)
	rangeEnd := rangeStart + 4095
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", rangeStart, rangeEnd))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("atteso HTTP 206 Partial Content, ottenuto %d", resp.StatusCode)
	}
	rangeBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rangeBody, videoData[rangeStart:rangeEnd+1]) {
		t.Fatal("il payload HTTP Range non coincide con la finestra richiesta")
	}

	// 7. Eliminazione sicura
	if err := v2.Delete("/Video/film.mp4"); err != nil {
		t.Fatal(err)
	}
	if _, ok := v2.Stat("/Video/film.mp4"); ok {
		t.Fatal("il file eliminato risulta ancora presente nell'indice")
	}
}

// ============================================================================
// 4. FUZZ TEST (Go Native Fuzzing: Round-Trip + Random-Access Seeker)
// ============================================================================

func FuzzVaultRoundTripAndSeeker(f *testing.F) {
	f.Add([]byte("Hello SecureUSB Fuzzing!"), int64(4), uint16(10))
	f.Add(bytes.Repeat([]byte{0xAA, 0x55, 0x00, 0xFF}, 1024), int64(128), uint16(512))
	f.Add([]byte(""), int64(0), uint16(0))

	tmpDir, err := os.MkdirTemp("", "svault_fuzz_*")
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	v, err := InitOrOpenVault(tmpDir, "FuzzKey", true)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { v.Close() })

	f.Fuzz(func(t *testing.T, payload []byte, seekOffset int64, readLen uint16) {
		if len(payload) > 2*ChunkSize {
			payload = payload[:2*ChunkSize]
		}

		if err := v.WriteFile("/fuzz.bin", payload); err != nil {
			t.Fatalf("WriteFile fallito durante il fuzzing: %v", err)
		}

		gotAll, err := v.ReadFile("/fuzz.bin")
		if err != nil {
			t.Fatalf("ReadFile fallito: %v", err)
		}
		if !bytes.Equal(payload, gotAll) {
			t.Fatal("violazione invariante round-trip sul file completo")
		}

		if len(payload) == 0 {
			return
		}

		seeker, err := v.OpenReadSeeker("/fuzz.bin")
		if err != nil {
			t.Fatalf("OpenReadSeeker fallito: %v", err)
		}
		defer seeker.Close()

		// Normalizza l'offset all'interno della dimensione del payload
		normOffset := seekOffset % int64(len(payload))
		if normOffset < 0 {
			normOffset = -normOffset
		}

		maxLen := len(payload) - int(normOffset)
		reqLen := int(readLen) % (maxLen + 1)
		if reqLen == 0 {
			reqLen = 1
		}

		buf := make([]byte, reqLen)
		n, err := seeker.ReadAt(buf, normOffset)
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt(%d, %d) fallito: %v", normOffset, reqLen, err)
		}
		if !bytes.Equal(buf[:n], payload[int(normOffset):int(normOffset)+n]) {
			t.Fatalf("ReadAt mismatch all'offset %d (len %d)", normOffset, n)
		}
	})
}

// ============================================================================
// 5. BENCHMARKS (Throughput MB/s Pipeline Parallela e Seeker O(1))
// ============================================================================

func BenchmarkParallelEncryptStream(b *testing.B) {
	tmpDir := b.TempDir()
	v, err := InitOrOpenVault(tmpDir, "BenchKey", true)
	if err != nil {
		b.Fatal(err)
	}
	defer v.Close()

	// Payload da 16 MB (4 chunk da 4 MB)
	data := bytes.Repeat([]byte("BenchmarkDataBlockForZstdAndXChaCha20Poly1305!"), (16*1024*1024)/46+1)[:16*1024*1024]
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _, err := v.encryptStreamParallel(bytes.NewReader(data), io.Discard, int64(len(data)), nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParallelDecryptStream(b *testing.B) {
	tmpDir := b.TempDir()
	v, err := InitOrOpenVault(tmpDir, "BenchKey", true)
	if err != nil {
		b.Fatal(err)
	}
	defer v.Close()

	data := bytes.Repeat([]byte("BenchmarkDataBlockForZstdAndXChaCha20Poly1305!"), (16*1024*1024)/46+1)[:16*1024*1024]
	var cipherBuf bytes.Buffer
	if _, _, _, err := v.encryptStreamParallel(bytes.NewReader(data), &cipherBuf, int64(len(data)), nil); err != nil {
		b.Fatal(err)
	}
	encryptedBytes := cipherBuf.Bytes()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := v.decryptStreamParallel(bytes.NewReader(encryptedBytes), io.Discard, int64(len(data)), nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRandomAccessSeekO1(b *testing.B) {
	tmpDir := b.TempDir()
	v, err := InitOrOpenVault(tmpDir, "BenchKey", true)
	if err != nil {
		b.Fatal(err)
	}
	defer v.Close()

	// File da 16 MB (4 chunk)
	data := make([]byte, 16*1024*1024)
	_, _ = rand.Read(data)
	if err := v.WriteFile("/random.bin", data); err != nil {
		b.Fatal(err)
	}

	seeker, err := v.OpenReadSeeker("/random.bin")
	if err != nil {
		b.Fatal(err)
	}
	defer seeker.Close()

	readBuf := make([]byte, 4096)
	b.SetBytes(int64(len(readBuf)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Salta all'interno dello stesso chunk o tra chunk con ReadAt
		offset := int64((i * 65536) % (15 * 1024 * 1024))
		if _, err := seeker.ReadAt(readBuf, offset); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}
`

const fuseMountContent = `package fusemount

import (
	"bytes"
	"io"
	"sync"

	"secureusb/internal/vault"

	"github.com/winfsp/cgofuse/fuse"
)

type openHandle struct {
	path   string
	seeker *vault.VaultReadSeeker
	buf    []byte
	dirty  bool
}

// VaultFuseFS adatta SecureVault all'interfaccia cgofuse (FUSE su Linux/macOS e WinFsp su Windows).
type VaultFuseFS struct {
	fuse.FileSystemBase
	vault   *vault.SecureVault
	mu      sync.Mutex
	nextFH  uint64
	handles map[uint64]*openHandle
}

func NewVaultFuseFS(v *vault.SecureVault) *VaultFuseFS {
	return &VaultFuseFS{
		vault:   v,
		nextFH:  1,
		handles: make(map[uint64]*openHandle),
	}
}

// MountDynamic monta il Vault su mountPoint (es. "Z:" su Windows o "/mnt/secureusb" su Linux/macOS)
// restituendo una funzione per smontare il disco virtuale.
func MountDynamic(v *vault.SecureVault, mountPoint string) (unmount func(), err error) {
	fs := NewVaultFuseFS(v)
	host := fuse.NewFileSystemHost(fs)
	host.SetCapReaddirPlus(true)

	go func() {
		_ = host.Mount(mountPoint, []string{"-o", "volname=SecureUSB"})
	}()

	return func() {
		host.Unmount()
	}, nil
}

func (f *VaultFuseFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	entry, ok := f.vault.Stat(path)
	if !ok {
		return -fuse.ENOENT
	}

	ts := fuse.NewTimespec(entry.UpdatedAt)
	stat.Atim = ts
	stat.Mtim = ts
	stat.Ctim = ts

	if entry.IsDir {
		stat.Mode = fuse.S_IFDIR | 0755
		stat.Nlink = 2
	} else {
		stat.Mode = fuse.S_IFREG | 0644
		stat.Nlink = 1
		stat.Size = entry.OriginalSize
	}
	return 0
}

func (f *VaultFuseFS) Readdir(path string, fill func(name string, stat *fuse.Stat_t, ofst int64) bool, ofst int64, fh uint64) int {
	fill(".", nil, 0)
	fill("..", nil, 0)

	children := f.vault.ListDir(path)
	for _, c := range children {
		var st fuse.Stat_t
		if c.IsDir {
			st.Mode = fuse.S_IFDIR | 0755
		} else {
			st.Mode = fuse.S_IFREG | 0644
			st.Size = c.OriginalSize
		}
		name := c.VirtualPath
		for i := len(name) - 1; i >= 0; i-- {
			if name[i] == '/' {
				name = name[i+1:]
				break
			}
		}
		if !fill(name, &st, 0) {
			break
		}
	}
	return 0
}

func (f *VaultFuseFS) Mkdir(path string, mode uint32) int {
	if err := f.vault.CreateDir(path); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *VaultFuseFS) Unlink(path string) int {
	if err := f.vault.Delete(path); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *VaultFuseFS) Rmdir(path string) int {
	if err := f.vault.Delete(path); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *VaultFuseFS) Rename(oldpath string, newpath string) int {
	if err := f.vault.Rename(oldpath, newpath); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *VaultFuseFS) Create(path string, flags int, mode uint32) (int, uint64) {
	if err := f.vault.WriteFile(path, []byte{}); err != nil {
		return -fuse.EIO, ^uint64(0)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fh := f.nextFH
	f.nextFH++
	f.handles[fh] = &openHandle{
		path:  path,
		buf:   []byte{},
		dirty: true,
	}
	return 0, fh
}

func (f *VaultFuseFS) Open(path string, flags int) (int, uint64) {
	seeker, err := f.vault.OpenReadSeeker(path)
	if err != nil {
		return -fuse.ENOENT, ^uint64(0)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	fh := f.nextFH
	f.nextFH++
	f.handles[fh] = &openHandle{
		path:   path,
		seeker: seeker,
	}
	return 0, fh
}

func (f *VaultFuseFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	f.mu.Lock()
	h, ok := f.handles[fh]
	f.mu.Unlock()
	if !ok {
		return -fuse.EBADF
	}

	if h.dirty {
		if ofst >= int64(len(h.buf)) {
			return 0
		}
		return copy(buff, h.buf[ofst:])
	}

	if h.seeker == nil {
		return -fuse.EIO
	}
	n, err := h.seeker.ReadAt(buff, ofst)
	if err != nil && err != io.EOF {
		return -fuse.EIO
	}
	return n
}

func (f *VaultFuseFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	f.mu.Lock()
	h, ok := f.handles[fh]
	if !ok {
		f.mu.Unlock()
		return -fuse.EBADF
	}

	if !h.dirty {
		if h.seeker != nil {
			_ = h.seeker.Close()
			h.seeker = nil
		}
		existing, err := f.vault.ReadFile(path)
		if err == nil {
			h.buf = existing
		}
		h.dirty = true
	}

	end := int(ofst) + len(buff)
	if end > len(h.buf) {
		newBuf := make([]byte, end)
		copy(newBuf, h.buf)
		h.buf = newBuf
	}
	copy(h.buf[ofst:], buff)
	f.mu.Unlock()
	return len(buff)
}

func (f *VaultFuseFS) Flush(path string, fh uint64) int {
	f.mu.Lock()
	h, ok := f.handles[fh]
	f.mu.Unlock()
	if !ok {
		return 0
	}
	if h.dirty {
		if err := f.vault.WriteStream(h.path, bytes.NewReader(h.buf), int64(len(h.buf)), nil); err != nil {
			return -fuse.EIO
		}
		h.dirty = false
	}
	return 0
}

func (f *VaultFuseFS) Release(path string, fh uint64) int {
	_ = f.Flush(path, fh)
	f.mu.Lock()
	if h, ok := f.handles[fh]; ok {
		if h.seeker != nil {
			_ = h.seeker.Close()
		}
		h.buf = nil
		delete(f.handles, fh)
	}
	f.mu.Unlock()
	return 0
}
`

const uiPreviewContent = `package ui

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"secureusb/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func isImageExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif"
}

func isPDFExt(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".pdf"
}

// buildImagePreview decodifica l'immagine direttamente dal VaultReadSeeker in RAM (zero file temporanei)
func buildImagePreview(v *vault.SecureVault, virtualPath string) (fyne.CanvasObject, error) {
	seeker, err := v.OpenReadSeeker(virtualPath)
	if err != nil {
		return nil, err
	}
	defer seeker.Close()

	img, format, err := image.Decode(seeker)
	if err != nil {
		return nil, fmt.Errorf("impossibile decodificare immagine: %w", err)
	}

	cImg := canvas.NewImageFromImage(img)
	cImg.FillMode = canvas.ImageFillContain
	cImg.SetMinSize(fyne.NewSize(480, 380))

	bounds := img.Bounds()
	header := widget.NewLabelWithStyle(
		fmt.Sprintf("Visualizzatore Immagini Integrato — Formato: %s | Risoluzione: %dx%d px (Zero-Temp in RAM)",
			strings.ToUpper(format), bounds.Dx(), bounds.Dy()),
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true},
	)

	return container.NewBorder(header, nil, nil, nil, container.NewPadded(cImg)), nil
}

type pdfPageData struct {
	PageNumber int
	Text       string
	Images     []image.Image
}

// buildPDFPreview legge il documento PDF direttamente dal VaultReadSeeker in RAM,
// decomprimendo gli stream /FlateDecode per il testo ed estraendo eventuali immagini /DCTDecode.
func buildPDFPreview(v *vault.SecureVault, virtualPath string) (fyne.CanvasObject, error) {
	seeker, err := v.OpenReadSeeker(virtualPath)
	if err != nil {
		return nil, err
	}
	defer seeker.Close()

	rawPDF, err := io.ReadAll(seeker)
	if err != nil {
		return nil, err
	}

	pages := parsePDFStreamsInMemory(rawPDF)
	if len(pages) == 0 {
		pages = []pdfPageData{{
			PageNumber: 1,
			Text:       "[Documento PDF caricato in RAM — Nessun flusso di testo standard rilevato o font convertiti in tracciati vettoriali.]",
		}}
	}

	currentIdx := 0
	pageTitle := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	textArea := widget.NewMultiLineEntry()
	textArea.Wrapping = fyne.TextWrapWord

	imgBox := container.NewHBox()
	imgScroll := container.NewHScroll(imgBox)
	imgScroll.Hide()

	updatePage := func() {
		p := pages[currentIdx]
		pageTitle.SetText(fmt.Sprintf("Visualizzatore PDF Integrato — Pagina %d di %d (Decodifica in RAM)", p.PageNumber, len(pages)))
		textArea.SetText(p.Text)

		imgBox.Objects = nil
		if len(p.Images) > 0 {
			for _, im := range p.Images {
				ci := canvas.NewImageFromImage(im)
				ci.FillMode = canvas.ImageFillContain
				ci.SetMinSize(fyne.NewSize(260, 200))
				imgBox.Add(ci)
			}
			imgScroll.Show()
		} else {
			imgScroll.Hide()
		}
		imgBox.Refresh()
	}

	prevBtn := widget.NewButtonWithIcon("Pagina Precedente", theme.NavigateBackIcon(), func() {
		if currentIdx > 0 {
			currentIdx--
			updatePage()
		}
	})
	nextBtn := widget.NewButtonWithIcon("Pagina Successiva", theme.NavigateNextIcon(), func() {
		if currentIdx < len(pages)-1 {
			currentIdx++
			updatePage()
		}
	})

	navBar := container.NewBorder(nil, nil, prevBtn, nextBtn, pageTitle)
	updatePage()

	return container.NewBorder(navBar, imgScroll, nil, nil, textArea), nil
}

var (
	rePDFStream  = regexp.MustCompile(` + "`(?s)<<(.*?)>>\\s*stream\\r?\\n(.*?)\\r?\\nendstream`" + `)
	reTextParens = regexp.MustCompile(` + "`\\(([^()\\\\]*(?:\\\\.[^()\\\\]*)*)\\)`" + `)
)

func parsePDFStreamsInMemory(raw []byte) []pdfPageData {
	matches := rePDFStream.FindAllSubmatch(raw, -1)
	var pages []pdfPageData
	var currentText strings.Builder
	var currentImgs []image.Image
	pageCounter := 1

	for _, m := range matches {
		dict := string(m[1])
		streamBytes := m[2]

		// Se lo stream è un'immagine JPEG incorporata (/DCTDecode), la decodifica in RAM
		if strings.Contains(dict, "/DCTDecode") {
			if img, _, err := image.Decode(bytes.NewReader(streamBytes)); err == nil {
				currentImgs = append(currentImgs, img)
			}
			continue
		}

		data := streamBytes
		if strings.Contains(dict, "/FlateDecode") {
			zr, err := zlib.NewReader(bytes.NewReader(streamBytes))
			if err == nil {
				if decomp, err := io.ReadAll(zr); err == nil {
					data = decomp
				}
				_ = zr.Close()
			}
		}

		strData := string(data)
		if strings.Contains(strData, "BT") && strings.Contains(strData, "ET") {
			tokens := reTextParens.FindAllStringSubmatch(strData, -1)
			for _, tok := range tokens {
				cleaned := strings.ReplaceAll(tok[1], "\\(", "(")
				cleaned = strings.ReplaceAll(cleaned, "\\)", ")")
				cleaned = strings.ReplaceAll(cleaned, "\\n", "\n")
				currentText.WriteString(cleaned)
				currentText.WriteString(" ")
			}
			currentText.WriteString("\n")

			if currentText.Len() > 1200 {
				pages = append(pages, pdfPageData{
					PageNumber: pageCounter,
					Text:       strings.TrimSpace(currentText.String()),
					Images:     currentImgs,
				})
				pageCounter++
				currentText.Reset()
				currentImgs = nil
			}
		}
	}

	if currentText.Len() > 0 || len(currentImgs) > 0 {
		txt := strings.TrimSpace(currentText.String())
		if txt == "" {
			txt = fmt.Sprintf("[Pagina %d contenente %d immagini incorporate]", pageCounter, len(currentImgs))
		}
		pages = append(pages, pdfPageData{
			PageNumber: pageCounter,
			Text:       txt,
			Images:     currentImgs,
		})
	}
	return pages
}
`

const uiAppContent = `package ui

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	fusemount "secureusb/internal/fuse"
	"secureusb/internal/usb"
	"secureusb/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func Run() {
	a := app.NewWithID("it.secureusb.explorer.v3")
	w := a.NewWindow(fmt.Sprintf("SecureUSB Explorer — SVAULT03 (%d Core) + FUSE/WinFsp + PDF/Image Viewer", runtime.NumCPU()))
	w.Resize(fyne.NewSize(1180, 720))

	showUnlockScreen(w)
	w.ShowAndRun()
}

func showUnlockScreen(w fyne.Window) {
	usbPathEntry := widget.NewEntry()
	usbPathEntry.SetPlaceHolder("Percorso della chiavetta montata (es. E:\\, /Volumes/SECURE_USB, /media/usb)")

	browseBtn := widget.NewButtonWithIcon("Sfoglia Cartella USB", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				usbPathEntry.SetText(uri.Path())
			}
		}, w)
	})

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Password crittografica (Argon2id)")

	openBtn := widget.NewButtonWithIcon("Sblocca ed Esplora", theme.LoginIcon(), func() {
		path := strings.TrimSpace(usbPathEntry.Text)
		pass := passEntry.Text
		if path == "" || pass == "" {
			dialog.ShowError(errors.New("inserire sia il percorso della USB che la password"), w)
			return
		}
		v, err := vault.InitOrOpenVault(path, pass, false)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		showExplorerScreen(w, v)
	})
	openBtn.Importance = widget.HighImportance

	initBtn := widget.NewButtonWithIcon("Inizializza Nuovo Vault (SVAULT03)", theme.ContentAddIcon(), func() {
		path := strings.TrimSpace(usbPathEntry.Text)
		pass := passEntry.Text
		if path == "" || len(pass) < 6 {
			dialog.ShowError(errors.New("seleziona il percorso USB e usa una password di almeno 6 caratteri"), w)
			return
		}
		dialog.ShowConfirm("Conferma Inizializzazione",
			"Questo creerà un nuovo Vault SVAULT03 sulla chiavetta. Procedere?",
			func(ok bool) {
				if !ok {
					return
				}
				v, err := vault.InitOrOpenVault(path, pass, true)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				showExplorerScreen(w, v)
			}, w)
	})

	devEntry := widget.NewEntry()
	devEntry.SetPlaceHolder("Dispositivo grezzo (es. E: su Windows, /dev/sdb1 su Linux, /dev/disk2 su Mac)")
	formatBtn := widget.NewButtonWithIcon("Formatta Hardware USB in exFAT", theme.StorageIcon(), func() {
		dev := strings.TrimSpace(devEntry.Text)
		if dev == "" {
			dialog.ShowError(errors.New("specifica l'identificativo del disco da formattare"), w)
			return
		}
		dialog.ShowConfirm("ATTENZIONE: Formattazione Fisica",
			fmt.Sprintf("Stai per formattare fisicamente %s in exFAT. TUTTI i dati sul dispositivo verranno distrutti. Continuare?", dev),
			func(ok bool) {
				if !ok {
					return
				}
				if err := usb.FormatPhysicalUSB(dev, "SECURE_USB"); err != nil {
					dialog.ShowError(err, w)
				} else {
					dialog.ShowInformation("Formattazione Completata",
						"Chiavetta formattata in exFAT! Ora seleziona la cartella montata e clicca 'Inizializza Nuovo Vault'.", w)
				}
			}, w)
	})

	card := container.NewVBox(
		widget.NewLabelWithStyle("Sblocco e Gestione Chiavetta Cifrata (Multi-Core + FUSE/WinFsp + Viewer Integrato)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, browseBtn, usbPathEntry),
		passEntry,
		container.NewGridWithColumns(2, openBtn, initBtn),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Utilità Formattazione Fisica (exFAT Cross-Platform)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		devEntry,
		formatBtn,
	)

	w.SetContent(container.NewPadded(card))
}

func showExplorerScreen(w fyne.Window, v *vault.SecureVault) {
	currentDir := "/"
	var entries []vault.FileEntry
	var selectedEntry *vault.FileEntry
	var unmountFuse func()

	pathLabel := widget.NewLabelWithStyle("Percorso: /", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	infoLabel := widget.NewLabel("Seleziona un file per visualizzarlo (Testo, Immagini PNG/JPG/GIF, PDF o Video in Streaming).")

	editor := widget.NewMultiLineEntry()
	editor.SetPlaceHolder("Editor integrato per file di testo (fino a 16 MB). Seleziona un'immagine o un PDF per aprire automaticamente il visualizzatore integrato.")
	editor.Disable()

	previewHolder := container.NewMax(editor)

	var listWidget *widget.List

	refreshList := func() {
		entries = v.ListDir(currentDir)
		selectedEntry = nil
		editor.SetText("")
		editor.Disable()
		previewHolder.Objects = []fyne.CanvasObject{editor}
		previewHolder.Refresh()
		pathLabel.SetText("Percorso: " + currentDir)
		infoLabel.SetText(fmt.Sprintf("%d elementi nella cartella corrente", len(entries)))
		if listWidget != nil {
			listWidget.UnselectAll()
			listWidget.Refresh()
		}
	}

	listWidget = widget.NewList(
		func() int { return len(entries) },
		func() fyne.CanvasObject {
			icon := widget.NewIcon(theme.FileIcon())
			name := widget.NewLabel("Nome File")
			meta := widget.NewLabel("Dimensioni")
			return container.NewBorder(nil, nil, icon, meta, name)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(entries) {
				return
			}
			e := entries[i]
			box := o.(*fyne.Container)
			icon := box.Objects[1].(*widget.Icon)
			meta := box.Objects[2].(*widget.Label)
			name := box.Objects[0].(*widget.Label)

			baseName := filepath.Base(e.VirtualPath)
			if e.IsDir {
				icon.SetResource(theme.FolderIcon())
				name.SetText(baseName + "/")
				meta.SetText("Cartella")
			} else {
				if isImageExt(baseName) {
					icon.SetResource(theme.MediaPhotoIcon())
				} else {
					icon.SetResource(theme.DocumentIcon())
				}
				name.SetText(baseName)
				ratio := 100.0
				if e.OriginalSize > 0 {
					ratio = (float64(e.DiskSize) / float64(e.OriginalSize)) * 100
				}
				meta.SetText(fmt.Sprintf("%s (%d chunk | %.0f%%)", formatBytes(e.OriginalSize), len(e.ChunkSizes), ratio))
			}
		},
	)

	listWidget.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(entries) {
			return
		}
		e := entries[id]
		selectedEntry = &e

		if e.IsDir {
			currentDir = e.VirtualPath
			refreshList()
			return
		}

		infoLabel.SetText(fmt.Sprintf("File: %s | Reale: %s | Su disco: %s | Chunk da 4MB: %d",
			filepath.Base(e.VirtualPath), formatBytes(e.OriginalSize), formatBytes(e.DiskSize), len(e.ChunkSizes)))

		// 1. Visualizzatore Integrato per Immagini (PNG/JPG/GIF) in RAM
		if isImageExt(e.VirtualPath) {
			if imgView, err := buildImagePreview(v, e.VirtualPath); err == nil {
				editor.Disable()
				previewHolder.Objects = []fyne.CanvasObject{imgView}
				previewHolder.Refresh()
				return
			}
		}

		// 2. Visualizzatore Integrato per PDF in RAM
		if isPDFExt(e.VirtualPath) && e.OriginalSize <= 64*1024*1024 {
			if pdfView, err := buildPDFPreview(v, e.VirtualPath); err == nil {
				editor.Disable()
				previewHolder.Objects = []fyne.CanvasObject{pdfView}
				previewHolder.Refresh()
				return
			}
		}

		previewHolder.Objects = []fyne.CanvasObject{editor}
		previewHolder.Refresh()

		if e.OriginalSize > vault.MaxTextPreviewSize {
			editor.Disable()
			editor.SetText(fmt.Sprintf("[File di grandi dimensioni (%s in %d chunk da 4 MB).\n• Clicca 'Stream Video al Volo' per riprodurlo subito con Random-Access O(1).\n• Oppure monta il Vault come disco FUSE/WinFsp.]",
				formatBytes(e.OriginalSize), len(e.ChunkSizes)))
			return
		}

		data, err := v.ReadFile(e.VirtualPath)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		if isLikelyText(data) {
			editor.Enable()
			editor.SetText(string(data))
		} else {
			editor.Disable()
			editor.SetText("[File binario — Usa 'Stream Video al Volo', 'Monta Disco FUSE' o 'Modifica con App Esterna']")
		}
	}

	upBtn := widget.NewButtonWithIcon("Su", theme.NavigateBackIcon(), func() {
		if currentDir == "/" {
			return
		}
		parent := filepath.ToSlash(filepath.Dir(currentDir))
		if parent == "." {
			parent = "/"
		}
		currentDir = parent
		refreshList()
	})

	newFolderBtn := widget.NewButtonWithIcon("Nuova Cartella", theme.FolderNewIcon(), func() {
		nameEntry := widget.NewEntry()
		dialog.ShowForm("Crea Cartella", "Crea", "Annulla", []*widget.FormItem{
			widget.NewFormItem("Nome cartella", nameEntry),
		}, func(ok bool) {
			if ok && strings.TrimSpace(nameEntry.Text) != "" {
				target := filepath.Join(currentDir, strings.TrimSpace(nameEntry.Text))
				if err := v.CreateDir(target); err != nil {
					dialog.ShowError(err, w)
				}
				refreshList()
			}
		}, w)
	})

	newFileBtn := widget.NewButtonWithIcon("Nuovo Testo", theme.DocumentCreateIcon(), func() {
		nameEntry := widget.NewEntry()
		nameEntry.SetPlaceHolder("note.txt")
		dialog.ShowForm("Nuovo File", "Crea", "Annulla", []*widget.FormItem{
			widget.NewFormItem("Nome file", nameEntry),
		}, func(ok bool) {
			if ok && strings.TrimSpace(nameEntry.Text) != "" {
				target := filepath.Join(currentDir, strings.TrimSpace(nameEntry.Text))
				if err := v.WriteFile(target, []byte("")); err != nil {
					dialog.ShowError(err, w)
				}
				refreshList()
			}
		}, w)
	})

	importBtn := widget.NewButtonWithIcon("Importa", theme.UploadIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			filePath := reader.URI().Path()
			fileName := reader.URI().Name()
			_ = reader.Close()

			info, statErr := os.Stat(filePath)
			var totalSize int64
			if statErr == nil {
				totalSize = info.Size()
			}

			inFile, openErr := os.Open(filePath)
			if openErr != nil {
				dialog.ShowError(openErr, w)
				return
			}

			prog := dialog.NewProgress("Compressione e Cifratura Multi-Core",
				fmt.Sprintf("Importazione parallela (%d core) di %s...", runtime.NumCPU(), fileName), w)
			prog.Show()

			target := filepath.Join(currentDir, fileName)
			go func() {
				defer inFile.Close()
				err := v.WriteStream(target, inFile, totalSize, func(done, total int64) {
					if total > 0 {
						prog.SetValue(float64(done) / float64(total))
					}
				})
				prog.Hide()
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				refreshList()
			}()
		}, w)
		fd.Show()
	})

	streamPlayBtn := widget.NewButtonWithIcon("Stream Video al Volo", theme.MediaPlayIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir {
			dialog.ShowInformation("Info", "Seleziona prima un video o un file multimediale dalla lista.", w)
			return
		}
		streamURL, err := v.GetStreamURL(selectedEntry.VirtualPath)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		openURLOrFileInOS(streamURL)
	})
	streamPlayBtn.Importance = widget.HighImportance

	// Pulsante Montaggio Disco Virtuale Nativo (FUSE / WinFsp)
	var fuseBtn *widget.Button
	fuseBtn = widget.NewButtonWithIcon("Monta Disco FUSE/WinFsp", theme.StorageIcon(), func() {
		if unmountFuse != nil {
			unmountFuse()
			unmountFuse = nil
			fuseBtn.SetText("Monta Disco FUSE/WinFsp")
			dialog.ShowInformation("Disco Smontato", "Il disco virtuale FUSE/WinFsp è stato smontato correttamente.", w)
			refreshList()
			return
		}

		mpEntry := widget.NewEntry()
		if runtime.GOOS == "windows" {
			mpEntry.SetText("Z:")
		} else {
			mpEntry.SetText("/tmp/secureusb_mount")
		}

		dialog.ShowForm("Monta come Unità Disco Nativa (FUSE / WinFsp)", "Monta", "Annulla", []*widget.FormItem{
			widget.NewFormItem("Punto di Mount / Lettera Unità", mpEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			mp := strings.TrimSpace(mpEntry.Text)
			if mp == "" {
				return
			}
			if runtime.GOOS != "windows" {
				_ = os.MkdirAll(mp, 0700)
			}
			unmountFn, err := fusemount.MountDynamic(v, mp)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			unmountFuse = unmountFn
			fuseBtn.SetText("Smonta Disco (" + mp + ")")
			dialog.ShowInformation("Disco Virtuale Attivo",
				fmt.Sprintf("Vault montato in %s tramite FUSE/WinFsp!\nOra puoi aprirlo direttamente nel File Explorer di sistema.", mp), w)
		}, w)
	})

	openExtBtn := widget.NewButtonWithIcon("App Esterna", theme.VisibilityIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir {
			dialog.ShowInformation("Info", "Seleziona prima un file dalla lista.", w)
			return
		}
		openWithSystemAppStreaming(w, v, *selectedEntry, refreshList)
	})

	exportBtn := widget.NewButtonWithIcon("Esporta", theme.DownloadIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir {
			return
		}
		entry := *selectedEntry
		fs := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			destPath := writer.URI().Path()
			_ = writer.Close()

			outFile, openErr := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if openErr != nil {
				dialog.ShowError(openErr, w)
				return
			}

			prog := dialog.NewProgress("Decifratura Parallela Multi-Core",
				fmt.Sprintf("Esportazione di %s...", filepath.Base(entry.VirtualPath)), w)
			prog.Show()

			go func() {
				bw := bufio.NewWriterSize(outFile, 1024*1024)
				err := v.ReadStream(entry.VirtualPath, bw, func(done, total int64) {
					if total > 0 {
						prog.SetValue(float64(done) / float64(total))
					}
				})
				if err == nil {
					err = bw.Flush()
				}
				_ = outFile.Close()
				prog.Hide()

				if err != nil {
					_ = os.Remove(destPath)
					dialog.ShowError(err, w)
				} else {
					dialog.ShowInformation("Esportazione Completata", "File decifrato e verificato con successo!", w)
				}
			}()
		}, w)
		fs.SetFileName(filepath.Base(entry.VirtualPath))
		fs.Show()
	})

	saveBtn := widget.NewButtonWithIcon("Salva Testo", theme.DocumentSaveIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir || editor.Disabled() {
			return
		}
		if err := v.WriteFile(selectedEntry.VirtualPath, []byte(editor.Text)); err != nil {
			dialog.ShowError(err, w)
			return
		}
		dialog.ShowInformation("Salvato", "File compresso e cifrato in formato SVAULT03!", w)
		refreshList()
	})
	saveBtn.Importance = widget.HighImportance

	deleteBtn := widget.NewButtonWithIcon("Elimina", theme.DeleteIcon(), func() {
		if selectedEntry == nil {
			return
		}
		target := selectedEntry.VirtualPath
		dialog.ShowConfirm("Eliminazione Sicura",
			fmt.Sprintf("Vuoi eliminare definitivamente '%s' sovrascrivendo i blocchi sulla USB?", filepath.Base(target)),
			func(ok bool) {
				if ok {
					_ = v.Delete(target)
					refreshList()
				}
			}, w)
	})
	deleteBtn.Importance = widget.DangerImportance

	lockBtn := widget.NewButtonWithIcon("Blocca USB", theme.LogoutIcon(), func() {
		if unmountFuse != nil {
			unmountFuse()
			unmountFuse = nil
		}
		v.Close()
		showUnlockScreen(w)
	})

	topBar := container.NewVBox(
		container.NewHBox(upBtn, newFolderBtn, newFileBtn, importBtn, streamPlayBtn, fuseBtn, openExtBtn, exportBtn, deleteBtn, lockBtn),
		container.NewBorder(nil, nil, pathLabel, nil, widget.NewLabel("")),
		widget.NewSeparator(),
	)

	rightPane := container.NewBorder(
		container.NewBorder(nil, nil, infoLabel, saveBtn),
		nil, nil, nil,
		previewHolder,
	)

	split := container.NewHSplit(listWidget, rightPane)
	split.Offset = 0.38

	refreshList()
	w.SetContent(container.NewBorder(topBar, nil, nil, nil, split))
}

func openURLOrFileInOS(target string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", "start", "", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	_ = cmd.Start()
}

func openWithSystemAppStreaming(w fyne.Window, v *vault.SecureVault, entry vault.FileEntry, onDone func()) {
	tmpDir, err := os.MkdirTemp("", "svault_edit_*")
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	tmpFile := filepath.Join(tmpDir, filepath.Base(entry.VirtualPath))

	outFile, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		dialog.ShowError(err, w)
		return
	}

	prog := dialog.NewProgress("Decifratura Parallela", "Apertura file nell'applicazione esterna...", w)
	prog.Show()

	go func() {
		bw := bufio.NewWriterSize(outFile, 1024*1024)
		err := v.ReadStream(entry.VirtualPath, bw, func(done, total int64) {
			if total > 0 {
				prog.SetValue(float64(done) / float64(total))
			}
		})
		if err == nil {
			err = bw.Flush()
		}
		_ = outFile.Close()
		prog.Hide()

		if err != nil {
			vault.SecureEraseFile(tmpFile)
			_ = os.RemoveAll(tmpDir)
			dialog.ShowError(err, w)
			return
		}

		infoBefore, _ := os.Stat(tmpFile)
		openURLOrFileInOS(tmpFile)

		dialog.ShowConfirm("File Aperto nell'App Esterna",
			"Quando hai terminato le modifiche, clicca 'Salva e Chiudi' per ricifrare in parallelo le modifiche sulla USB e distruggere il file temporaneo.",
			func(saveChanges bool) {
				if saveChanges {
					infoAfter, statErr := os.Stat(tmpFile)
					if statErr == nil && (infoBefore == nil || !infoAfter.ModTime().Equal(infoBefore.ModTime()) || infoAfter.Size() != infoBefore.Size()) {
						inFile, openErr := os.Open(tmpFile)
						if openErr == nil {
							saveProg := dialog.NewProgress("Salvataggio Parallelo", "Ricifratura modifiche sulla USB...", w)
							saveProg.Show()
							_ = v.WriteStream(entry.VirtualPath, inFile, infoAfter.Size(), func(d, t int64) {
								if t > 0 {
									saveProg.SetValue(float64(d) / float64(t))
								}
							})
							_ = inFile.Close()
							saveProg.Hide()
						}
					}
				}
				vault.SecureEraseFile(tmpFile)
				_ = os.RemoveAll(tmpDir)
				onDone()
			}, w)
	}()
}

func isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	sample := data
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	for _, b := range sample {
		if b == 0 {
			return false
		}
	}
	return true
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

var _ = storage.NewFileURI
`
