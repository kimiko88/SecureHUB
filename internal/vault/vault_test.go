package vault

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
