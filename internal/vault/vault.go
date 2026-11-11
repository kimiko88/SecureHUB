package vault

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
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

func ShouldIgnoreFile(nameOrPath string) bool {
	base := strings.TrimSpace(filepath.Base(nameOrPath))
	if base == "" || base == "." || base == "/" {
		return false
	}
	lower := strings.ToLower(base)

	switch lower {
	case ".ds_store", "thumbs.db", "thumbs.db:encryptable", "ehthumbs.db", "ehthumbs_vista.db",
		"desktop.ini", ".spotlight-v100", ".trashes", ".fseventsd", ".temporaryitems",
		"$recycle.bin", "system volume information", ".secure_vault":
		return true
	}

	if strings.HasPrefix(base, "._") || strings.HasPrefix(base, "~$") {
		return true
	}
	if strings.HasSuffix(lower, ".tmp") || strings.HasSuffix(lower, ".bak") ||
		strings.HasSuffix(lower, ".swp") || strings.HasSuffix(lower, ".swo") ||
		strings.HasSuffix(lower, "~") {
		return true
	}
	return false
}

func InitOrOpenVault(usbMountPath, password string, createNew bool) (*SecureVault, error) {
	vaultDir := filepath.Join(usbMountPath, ".secure_vault")
	blocksDir := filepath.Join(vaultDir, "blocks")
	saltFile := filepath.Join(vaultDir, "vault.salt")
	indexFile := filepath.Join(vaultDir, "index.meta")
	keyFile := filepath.Join(vaultDir, "vault.key")

	// Compressione ottimizzata con finestra Zstd allineata esattamente al chunk da 4 MB
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
		zstd.WithWindowSize(ChunkSize),
	)
	if err != nil {
		return nil, err
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}

	v := &SecureVault{
		rootPath:    vaultDir,
		activeIndex: "index.meta",
		encoder:     encoder,
		decoder:     decoder,
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

		v.dek = make([]byte, KeySize)
		if _, err := io.ReadFull(rand.Reader, v.dek); err != nil {
			return nil, err
		}
		if err := v.initDualSlotKeyAndShadow(password); err != nil {
			return nil, err
		}

		v.aead, err = chacha20poly1305.NewX(v.dek)
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

	if _, err := os.Stat(keyFile); err == nil {
		v.dek, v.isShadow, v.activeIndex, err = v.unwrapDualOrLegacyDEK(password, v.salt)
		if err != nil {
			return nil, errors.New("password errata o vault.key manomesso")
		}
	} else {
		v.dek = deriveKey(password, v.salt)
	}

	v.aead, err = chacha20poly1305.NewX(v.dek)
	if err != nil {
		return nil, err
	}

	if err := v.loadIndex(); err != nil {
		return nil, errors.New("password errata o indice corrotto")
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		_ = v.wrapAndSaveDEK(password, v.salt)
	}

	return v, nil
}

// IsMountAlive verifica che la chiavetta USB sia ancora fisicamente collegata e accessibile.
func (v *SecureVault) IsMountAlive() bool {
	_, err := os.Stat(filepath.Join(v.rootPath, "index.meta"))
	return err == nil
}

// Close azzera la DEK in RAM e chiude il listener di streaming.
func (v *SecureVault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.dek {
		v.dek[i] = 0
	}
	if v.streamListener != nil {
		_ = v.streamListener.Close()
		v.streamListener = nil
	}
}

func (v *SecureVault) wrapAndSaveDEK(password string, salt []byte) error {
	kek := deriveKey(password, salt)
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()
	kekAEAD, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	aad := []byte(VaultKeyMagic)
	wrapped := kekAEAD.Seal(nil, nonce, v.dek, aad)

	packet := make([]byte, 0, len(aad)+NonceSize+len(wrapped))
	packet = append(packet, aad...)
	packet = append(packet, nonce...)
	packet = append(packet, wrapped...)

	keyFile := filepath.Join(v.rootPath, "vault.key")
	tmpFile := keyFile + ".tmp"
	if err := os.WriteFile(tmpFile, packet, 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, keyFile)
}

func (v *SecureVault) unwrapDEK(password string, salt []byte) ([]byte, error) {
	keyFile := filepath.Join(v.rootPath, "vault.key")
	packet, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	magicLen := len(VaultKeyMagic)
	if len(packet) != magicLen+NonceSize+KeySize+16 || string(packet[:magicLen]) != VaultKeyMagic {
		return nil, errors.New("formato vault.key non valido")
	}
	kek := deriveKey(password, salt)
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()
	kekAEAD, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	nonce := packet[magicLen : magicLen+NonceSize]
	cipherDEK := packet[magicLen+NonceSize:]
	return kekAEAD.Open(nil, nonce, cipherDEK, packet[:magicLen])
}

// ChangePassword cambia istantaneamente la password del Vault tramite Key Wrapping (0 byte di file ricifrati).
func (v *SecureVault) ChangePassword(oldPassword, newPassword string) error {
	if len(newPassword) < 6 {
		return errors.New("la nuova password deve contenere almeno 6 caratteri")
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	verifiedDEK, err := v.unwrapDEK(oldPassword, v.salt)
	if err != nil {
		return errors.New("la password attuale inserita non è corretta")
	}
	matchesCurrentKey := subtle.ConstantTimeCompare(verifiedDEK, v.dek) == 1
	for i := range verifiedDEK {
		verifiedDEK[i] = 0
	}
	if !matchesCurrentKey {
		return errors.New("il vault.key non corrisponde alla chiave del Vault attualmente aperto")
	}

	newSalt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return err
	}
	if err := v.wrapAndSaveDEK(newPassword, newSalt); err != nil {
		return err
	}
	saltFile := filepath.Join(v.rootPath, "vault.salt")
	if err := os.WriteFile(saltFile, newSalt, 0600); err != nil {
		return err
	}
	v.salt = newSalt
	return nil
}

// Search filtra istantaneamente in RAM tutti i file e le cartelle che contengono query.
func (v *SecureVault) Search(query string) []FileEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return v.ListDir("/")
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	var results []FileEntry
	for _, entry := range v.index.Entries {
		if entry.VirtualPath == "/" {
			continue
		}
		if strings.Contains(strings.ToLower(entry.VirtualPath), q) {
			results = append(results, entry)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].IsDir != results[j].IsDir {
			return results[i].IsDir
		}
		return strings.ToLower(results[i].VirtualPath) < strings.ToLower(results[j].VirtualPath)
	})
	return results
}

// Stats restituisce le statistiche globali di spazio e compressione Zstd del Vault.
func (v *SecureVault) Stats() VaultStats {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var st VaultStats
	for _, entry := range v.index.Entries {
		if entry.VirtualPath == "/" {
			continue
		}
		if entry.IsDir {
			st.TotalFolders++
		} else {
			st.TotalFiles++
			st.TotalChunks += len(entry.ChunkSizes)
			st.OriginalSize += entry.OriginalSize
			st.DiskSize += entry.DiskSize
		}
	}
	st.IsShadowVault = v.isShadow
	for _, refCount := range v.index.ChunkRefCounts {
		if refCount > 1 {
			st.DeduplicatedChunks += (refCount - 1)
			st.SavedDedupBytes += int64(refCount-1) * ChunkSize
		}
	}
	return st
}

// ScrubIntegrity verifica in parallelo su tutti i core tutti i tag Poly1305 e i flussi Zstd sulla USB.
func (v *SecureVault) ScrubIntegrity(onProgress ProgressFunc) (ScrubReport, error) {
	v.mu.RLock()
	var files []FileEntry
	var totalBytes int64
	for _, entry := range v.index.Entries {
		if !entry.IsDir {
			files = append(files, entry)
			totalBytes += entry.OriginalSize
		}
	}
	v.mu.RUnlock()

	var report ScrubReport
	report.TotalFiles = len(files)
	var processedBytes int64

	for _, fEntry := range files {
		baseOffset := processedBytes
		err := v.ReadStream(fEntry.VirtualPath, io.Discard, func(done, _ int64) {
			if onProgress != nil {
				onProgress(baseOffset+done, totalBytes)
			}
		})
		if err != nil {
			report.CorruptedFiles = append(report.CorruptedFiles, fEntry.VirtualPath)
		} else {
			report.VerifiedChunks += len(fEntry.ChunkSizes)
			report.VerifiedBytes += fEntry.OriginalSize
		}
		processedBytes += fEntry.OriginalSize
	}

	return report, nil
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

func (v *SecureVault) ImportDir(localDirPath, targetParentVirtualDir string, onProgress ProgressFunc) (int, error) {
	localDirPath = filepath.Clean(localDirPath)
	info, err := os.Stat(localDirPath)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, errors.New("il percorso selezionato non è una cartella")
	}

	baseFolderName := filepath.Base(localDirPath)
	if ShouldIgnoreFile(baseFolderName) {
		return 0, nil
	}
	rootVirtualDir := normalizePath(filepath.Join(targetParentVirtualDir, baseFolderName))

	var totalBytes int64
	_ = filepath.WalkDir(localDirPath, func(currPath string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if currPath != localDirPath && ShouldIgnoreFile(d.Name()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			if fi, sErr := d.Info(); sErr == nil {
				totalBytes += fi.Size()
			}
		}
		return nil
	})

	var processedBytes int64
	var importedCount int

	err = filepath.WalkDir(localDirPath, func(currPath string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if currPath != localDirPath && ShouldIgnoreFile(d.Name()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, err := filepath.Rel(localDirPath, currPath)
		if err != nil {
			return err
		}

		var targetVirtualPath string
		if relPath == "." {
			targetVirtualPath = rootVirtualDir
		} else {
			targetVirtualPath = normalizePath(filepath.Join(rootVirtualDir, relPath))
		}

		if d.IsDir() {
			v.mu.Lock()
			if _, exists := v.index.Entries[targetVirtualPath]; !exists && targetVirtualPath != "/" {
				v.index.Entries[targetVirtualPath] = FileEntry{
					VirtualPath: targetVirtualPath,
					IsDir:       true,
					UpdatedAt:   time.Now(),
				}
			}
			v.mu.Unlock()
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		inFile, err := os.Open(currPath)
		if err != nil {
			return err
		}

		baseOffset := processedBytes
		wErr := v.WriteStream(targetVirtualPath, inFile, fi.Size(), func(fileDone, _ int64) {
			if onProgress != nil {
				onProgress(baseOffset+fileDone, totalBytes)
			}
		})
		_ = inFile.Close()
		if wErr != nil {
			return wErr
		}

		processedBytes += fi.Size()
		importedCount++
		return nil
	})

	if err != nil {
		return importedCount, err
	}

	v.mu.Lock()
	saveErr := v.saveIndexLocked()
	v.mu.Unlock()
	return importedCount, saveErr
}

func (v *SecureVault) ExportDir(virtualDirPath, localDestParentDir string, onProgress ProgressFunc) (int, error) {
	virtualDirPath = normalizePath(virtualDirPath)
	localDestParentDir = filepath.Clean(localDestParentDir)

	folderName := filepath.Base(virtualDirPath)
	if virtualDirPath == "/" || folderName == "." || folderName == "/" {
		folderName = "Vault_Export"
	}
	targetRootLocal := filepath.Join(localDestParentDir, folderName)

	if err := os.MkdirAll(targetRootLocal, 0700); err != nil {
		return 0, err
	}

	prefix := virtualDirPath + "/"
	if virtualDirPath == "/" {
		prefix = "/"
	}

	v.mu.RLock()
	var items []FileEntry
	var totalBytes int64
	for k, entry := range v.index.Entries {
		if k == virtualDirPath || strings.HasPrefix(k, prefix) {
			items = append(items, entry)
			if !entry.IsDir {
				totalBytes += entry.OriginalSize
			}
		}
	}
	v.mu.RUnlock()

	for _, entry := range items {
		if !entry.IsDir {
			continue
		}
		rel := strings.TrimPrefix(entry.VirtualPath, virtualDirPath)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			continue
		}
		localSubDir := filepath.Join(targetRootLocal, filepath.FromSlash(rel))
		if err := os.MkdirAll(localSubDir, 0700); err != nil {
			return 0, err
		}
	}

	var processedBytes int64
	var exportedCount int

	for _, entry := range items {
		if entry.IsDir {
			continue
		}
		rel := strings.TrimPrefix(entry.VirtualPath, virtualDirPath)
		rel = strings.TrimPrefix(rel, "/")
		localFilePath := filepath.Join(targetRootLocal, filepath.FromSlash(rel))

		if err := os.MkdirAll(filepath.Dir(localFilePath), 0700); err != nil {
			return exportedCount, err
		}

		outFile, err := os.OpenFile(localFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return exportedCount, err
		}

		bw := bufio.NewWriterSize(outFile, 1024*1024)
		baseOffset := processedBytes
		rErr := v.ReadStream(entry.VirtualPath, bw, func(fileDone, _ int64) {
			if onProgress != nil {
				onProgress(baseOffset+fileDone, totalBytes)
			}
		})
		if rErr == nil {
			rErr = bw.Flush()
		}
		_ = outFile.Close()
		if rErr != nil {
			return exportedCount, rErr
		}

		processedBytes += entry.OriginalSize
		exportedCount++
	}

	return exportedCount, nil
}

func (v *SecureVault) saveIndexLocked() error {
	rawJSON, err := json.Marshal(v.index)
	if err != nil {
		return err
	}
	indexName := v.activeIndex
	if indexName == "" {
		indexName = "index.meta"
	}
	indexFile := filepath.Join(v.rootPath, indexName)
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
	if err := os.Rename(tmpFile, indexFile); err != nil {
		return err
	}
	return WriteECCSidecar(indexFile)
}

func (v *SecureVault) loadIndex() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	indexName := v.activeIndex
	if indexName == "" {
		indexName = "index.meta"
	}
	indexFile := filepath.Join(v.rootPath, indexName)
	_, _, _ = VerifyAndHealWithECC(indexFile)
	f, err := os.Open(indexFile)
	if err != nil {
		return err
	}
	defer f.Close()

	var buf bytes.Buffer
	if err := v.decryptStreamParallel(f, &buf, 0, nil); err != nil {
		return err
	}
	if err := json.Unmarshal(buf.Bytes(), &v.index); err != nil {
		return err
	}
	if v.index.ChunkRefCounts == nil {
		v.index.ChunkRefCounts = make(map[string]int)
	}
	return nil
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

// AllFiles restituisce tutti i file (non cartelle) presenti sotto dirPrefix ordinati per dimensione decrescente.
func (v *SecureVault) AllFiles(dirPrefix string) []FileEntry {
	dirPrefix = normalizePath(dirPrefix)
	prefix := dirPrefix + "/"
	if dirPrefix == "/" {
		prefix = "/"
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	var files []FileEntry
	for _, entry := range v.index.Entries {
		if entry.IsDir || entry.VirtualPath == "/" {
			continue
		}
		if dirPrefix == "/" || strings.HasPrefix(entry.VirtualPath, prefix) {
			files = append(files, entry)
		}
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].OriginalSize != files[j].OriginalSize {
			return files[i].OriginalSize > files[j].OriginalSize
		}
		return files[i].VirtualPath < files[j].VirtualPath
	})
	return files
}
