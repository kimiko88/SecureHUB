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
// 1. UNIT TESTS (Nonce/AAD, Path Normalization & OS Junk File Filter)
// ============================================================================

func TestChunkNonceAndAAD_Unit(t *testing.T) {
	streamID := []byte("0123456789abcde")
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

func TestShouldIgnoreFile_Unit(t *testing.T) {
	ignored := []string{
		".DS_Store",
		"/path/to/.ds_store",
		"Thumbs.db",
		"thumbs.db:encryptable",
		"ehthumbs.db",
		"desktop.ini",
		"Desktop.INI",
		"._foto_vacanze.jpg",
		"~$Contratto.docx",
		"scaricamento.tmp",
		"backup.bak",
		".file.swp",
		"editor~",
		".Spotlight-V100",
		".Trashes",
		"$RECYCLE.BIN",
		".secure_vault",
	}
	for _, item := range ignored {
		if !ShouldIgnoreFile(item) {
			t.Errorf("ShouldIgnoreFile(%q) = false, atteso true (file temporaneo/spazzatura)", item)
		}
	}

	valid := []string{
		"relazione.pdf",
		"codice.go",
		"video_4k.mp4",
		".gitignore",
		"README.md",
	}
	for _, item := range valid {
		if ShouldIgnoreFile(item) {
			t.Errorf("ShouldIgnoreFile(%q) = true, atteso false (file utente valido)", item)
		}
	}
}

// ============================================================================
// 2. INTEGRATION TESTS (Pipeline Parallela, Tamper Detection & ImportDir/ExportDir)
// ============================================================================

func TestParallelPipelineMultiChunk_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	v, err := InitOrOpenVault(tmpDir, "Passw0rd-Sicura-2026!", true)
	if err != nil {
		t.Fatalf("InitOrOpenVault fallito: %v", err)
	}
	defer v.Close()

	totalSize := 2*ChunkSize + (ChunkSize / 2) + 12345
	original := make([]byte, totalSize)
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

func TestImportAndExportDirRecursiveWithJunkFilter_Integration(t *testing.T) {
	vaultUSBDir := t.TempDir()
	srcRootDir := filepath.Join(t.TempDir(), "ProgettoSegreto")
	exportDestDir := t.TempDir()

	// Crea gerarchia di sottocartelle locali
	subSrc := filepath.Join(srcRootDir, "src", "core")
	subDocs := filepath.Join(srcRootDir, "docs")
	junkDir := filepath.Join(srcRootDir, ".Spotlight-V100")
	for _, d := range []string{subSrc, subDocs, junkDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// File utente validi
	validFiles := map[string][]byte{
		filepath.Join(srcRootDir, "README.md"):          []byte("# Progetto Segreto SVAULT03"),
		filepath.Join(subSrc, "engine.go"):              bytes.Repeat([]byte("package core\n"), 5000),
		filepath.Join(subDocs, "specifica_tecnica.pdf"): []byte("%PDF-1.7 contenuto riservato"),
	}
	for path, content := range validFiles {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}

	// File spazzatura / temporanei che DEVONO essere esclusi automaticamente
	junkFiles := []string{
		filepath.Join(srcRootDir, ".DS_Store"),
		filepath.Join(srcRootDir, "Thumbs.db"),
		filepath.Join(subSrc, "desktop.ini"),
		filepath.Join(subSrc, "._engine.go"),
		filepath.Join(subDocs, "~$specifica_tecnica.pdf"),
		filepath.Join(subDocs, "bozza.tmp"),
		filepath.Join(junkDir, "index.bin"),
	}
	for _, jPath := range junkFiles {
		if err := os.WriteFile(jPath, []byte("junk data"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	v, err := InitOrOpenVault(vaultUSBDir, "DirImportPass!", true)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	if err := v.CreateDir("/Archivio"); err != nil {
		t.Fatal(err)
	}

	// 1. Importazione ricorsiva della cartella
	var lastDone, lastTotal int64
	importedCount, err := v.ImportDir(srcRootDir, "/Archivio", func(done, total int64) {
		lastDone = done
		lastTotal = total
	})
	if err != nil {
		t.Fatalf("ImportDir fallito: %v", err)
	}
	if importedCount != 3 {
		t.Fatalf("attesi esattamente 3 file validi importati, ottenuti %d", importedCount)
	}
	if lastDone != lastTotal || lastTotal == 0 {
		t.Fatalf("progresso ImportDir incompleto: %d / %d", lastDone, lastTotal)
	}

	// Verifica assenza dei file temporanei nell'indice cifrato
	for _, forbidden := range []string{
		"/Archivio/ProgettoSegreto/.DS_Store",
		"/Archivio/ProgettoSegreto/Thumbs.db",
		"/Archivio/ProgettoSegreto/src/core/desktop.ini",
		"/Archivio/ProgettoSegreto/src/core/._engine.go",
		"/Archivio/ProgettoSegreto/docs/~$specifica_tecnica.pdf",
		"/Archivio/ProgettoSegreto/docs/bozza.tmp",
		"/Archivio/ProgettoSegreto/.Spotlight-V100/index.bin",
	} {
		if _, exists := v.Stat(forbidden); exists {
			t.Fatalf("il file temporaneo %s non è stato filtrato durante ImportDir!", forbidden)
		}
	}

	// 2. Esportazione ricorsiva della cartella verso il PC
	exportedCount, err := v.ExportDir("/Archivio/ProgettoSegreto", exportDestDir, nil)
	if err != nil {
		t.Fatalf("ExportDir fallito: %v", err)
	}
	if exportedCount != 3 {
		t.Fatalf("attesi 3 file esportati, ottenuti %d", exportedCount)
	}

	// 3. Verifica integrità byte-per-byte dei file esportati
	exportedBase := filepath.Join(exportDestDir, "ProgettoSegreto")
	for origPath, expectedBytes := range validFiles {
		rel, _ := filepath.Rel(srcRootDir, origPath)
		expPath := filepath.Join(exportedBase, rel)
		gotBytes, err := os.ReadFile(expPath)
		if err != nil {
			t.Fatalf("file esportato mancante %s: %v", expPath, err)
		}
		if !bytes.Equal(gotBytes, expectedBytes) {
			t.Fatalf("contenuto file esportato %s diverso dall'originale", expPath)
		}
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

	corrupted := append([]byte(nil), rawDisk...)
	corrupted[HeaderSize+50] ^= 0xFF
	if err := os.WriteFile(blobPath, corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadFile("/sec.bin"); err == nil {
		t.Fatal("la decifratura avrebbe dovuto fallire su blocco manomesso (Poly1305)")
	}

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
// 3. END-TO-END (E2E) TEST
// ============================================================================

func TestEndToEndLifecycle_E2E(t *testing.T) {
	tmpDir := t.TempDir()
	password := "E2E-MasterKey-99!"

	v, err := InitOrOpenVault(tmpDir, password, true)
	if err != nil {
		t.Fatalf("creazione vault fallita: %v", err)
	}
	if err := v.CreateDir("/Video"); err != nil {
		t.Fatal(err)
	}

	videoData := make([]byte, 2*ChunkSize+1024*1024)
	for i := range videoData {
		videoData[i] = byte((i * 31) & 0xFF)
	}
	if err := v.WriteFile("/Video/film.mp4", videoData); err != nil {
		t.Fatal(err)
	}
	v.Close()

	if _, err := InitOrOpenVault(tmpDir, "PasswordSbagliata", false); err == nil {
		t.Fatal("apertura con password errata non bloccata")
	}

	v2, err := InitOrOpenVault(tmpDir, password, false)
	if err != nil {
		t.Fatalf("riapertura vault fallita: %v", err)
	}
	defer v2.Close()

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

	if err := v2.Delete("/Video/film.mp4"); err != nil {
		t.Fatal(err)
	}
	if _, ok := v2.Stat("/Video/film.mp4"); ok {
		t.Fatal("il file eliminato risulta ancora presente nell'indice")
	}
}

// ============================================================================
// 4. FUZZ TEST
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
// 5. BENCHMARKS
// ============================================================================

func BenchmarkParallelEncryptStream(b *testing.B) {
	tmpDir := b.TempDir()
	v, err := InitOrOpenVault(tmpDir, "BenchKey", true)
	if err != nil {
		b.Fatal(err)
	}
	defer v.Close()

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
		offset := int64((i * 65536) % (15 * 1024 * 1024))
		if _, err := seeker.ReadAt(readBuf, offset); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}
