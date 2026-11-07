package vault

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
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
)

// ShouldIgnoreFile restituisce true per i file e le cartelle temporanee/spazzatura del sistema operativo
// (.DS_Store, Thumbs.db, desktop.ini, ._* di macOS, ~$* di Office, *.tmp, *.swp, .secure_vault).
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

// func InitOrOpenVault(usbMountPath, password string, createNew bool) (*SecureVault, error) {
// 	vaultDir := filepath.Join(usbMountPath, ".secure_vault")
// 	blocksDir := filepath.Join(vaultDir, "blocks")
// 	saltFile := filepath.Join(vaultDir, "vault.salt")
// 	indexFile := filepath.Join(vaultDir, "index.meta")

// 	encoder, err := zstd.NewWriter(nil,
// 		zstd.WithEncoderLevel(zstd.SpeedBetterCompression), // Livello ottimale (alta compressione, zero impatto in lettura)
// 		zstd.WithWindowSize(ChunkSize),                     // Finestra di ricerca allineata all'intero chunk da 4 MB
// 		zstd.WithEncoderConcurrency(1),                     // Concorrenza già gestita dai worker sui chunk
// 	)
// 	if err != nil {
// 		return nil, err
// 	}
// 	decoder, err := zstd.NewReader(nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	v := &SecureVault{
// 		rootPath: vaultDir,
// 		encoder:  encoder,
// 		decoder:  decoder,
// 		chunkPool: sync.Pool{
// 			New: func() any {
// 				buf := make([]byte, ChunkSize)
// 				return &buf
// 			},
// 		},
// 		index: VaultIndex{Entries: make(map[string]FileEntry)},
// 	}

// 	if createNew {
// 		_ = os.RemoveAll(vaultDir)
// 		if err := os.MkdirAll(blocksDir, 0700); err != nil {
// 			return nil, fmt.Errorf("impossibile creare le cartelle sulla USB: %w", err)
// 		}

// 		v.salt = make([]byte, SaltSize)
// 		if _, err := io.ReadFull(rand.Reader, v.salt); err != nil {
// 			return nil, err
// 		}
// 		if err := os.WriteFile(saltFile, v.salt, 0600); err != nil {
// 			return nil, err
// 		}

// 		key := deriveKey(password, v.salt)
// 		v.aead, err = chacha20poly1305.NewX(key)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if err := v.saveIndexLocked(); err != nil {
// 			return nil, err
// 		}
// 		return v, nil
// 	}

// 	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
// 		return nil, errors.New("nessun Vault trovato in questo percorso: usa 'Inizializza Nuovo Vault'")
// 	}

// 	v.salt, err = os.ReadFile(saltFile)
// 	if err != nil || len(v.salt) != SaltSize {
// 		return nil, errors.New("file salt corrotto o illeggibile")
// 	}

// 	key := deriveKey(password, v.salt)
// 	v.aead, err = chacha20poly1305.NewX(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if err := v.loadIndex(); err != nil {
// 		return nil, errors.New("password errata o indice corrotto")
// 	}

//		return v, nil
//	}
func wrapDEK(kek, dek []byte) ([]byte, error) {
	kekAEAD, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	wrapped := kekAEAD.Seal(nil, nonce, dek, []byte(KeyWrapAAD))
	return append(nonce, wrapped...), nil
}

func unwrapDEK(kek, packet []byte) ([]byte, error) {
	if len(packet) != NonceSize+KeySize+chacha20poly1305.Overhead {
		return nil, errors.New("file vault.key corrotto")
	}
	kekAEAD, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	return kekAEAD.Open(nil, packet[:NonceSize], packet[NonceSize:], []byte(KeyWrapAAD))
}

func InitOrOpenVault(usbMountPath, password string, createNew bool) (*SecureVault, error) {
	vaultDir := filepath.Join(usbMountPath, ".secure_vault")
	blocksDir := filepath.Join(vaultDir, "blocks")
	saltFile := filepath.Join(vaultDir, "vault.salt")
	keyFile := filepath.Join(vaultDir, "vault.key")
	indexFile := filepath.Join(vaultDir, "index.meta")

	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
		zstd.WithWindowSize(ChunkSize),
		zstd.WithEncoderConcurrency(1),
	)
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

		// Genera DEK casuale a 256-bit e la cifra con la KEK derivata dalla password
		v.dek = make([]byte, KeySize)
		if _, err := io.ReadFull(rand.Reader, v.dek); err != nil {
			return nil, err
		}
		kek := deriveKey(password, v.salt)
		wrappedKey, err := wrapDEK(kek, v.dek)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyFile, wrappedKey, 0600); err != nil {
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

	kek := deriveKey(password, v.salt)
	if wrappedBytes, err := os.ReadFile(keyFile); err == nil {
		v.dek, err = unwrapDEK(kek, wrappedBytes)
		if err != nil {
			return nil, errors.New("password errata o vault.key manomesso")
		}
	} else {
		// Migrazione trasparente per Vault creati prima del Key Wrapping
		v.dek = kek
	}

	v.aead, err = chacha20poly1305.NewX(v.dek)
	if err != nil {
		return nil, err
	}
	if err := v.loadIndex(); err != nil {
		return nil, errors.New("password errata o indice corrotto")
	}

	// Se vault.key non esisteva ancora, lo salva ora per abilitare il Key Wrapping
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		if wrapped, wErr := wrapDEK(kek, v.dek); wErr == nil {
			_ = os.WriteFile(keyFile, wrapped, 0600)
		}
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

// ImportDir importa ricorsivamente una cartella dal PC dentro targetParentVirtualDir,
// filtrando automaticamente i file temporanei/spazzatura (.DS_Store, Thumbs.db, desktop.ini, ecc.).
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

// ExportDir esporta ricorsivamente una cartella virtuale dal Vault verso localDestParentDir sul PC.
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

// Search esegue una ricerca istantanea in RAM su tutto l'indice cifrato.
func (v *SecureVault) Search(query string) []FileEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()

	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}

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

// ChangePassword cambia istantaneamente la password ricifrando solo la DEK a 256-bit (Key Wrapping)
// senza toccare i blocchi dati sulla chiavetta USB.
func (v *SecureVault) ChangePassword(oldPassword, newPassword string) error {
	if len(newPassword) < 6 {
		return errors.New("la nuova password deve contenere almeno 6 caratteri")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	oldKEK := deriveKey(oldPassword, v.salt)
	keyFile := filepath.Join(v.rootPath, "vault.key")
	if wrappedBytes, err := os.ReadFile(keyFile); err == nil {
		if _, err := unwrapDEK(oldKEK, wrappedBytes); err != nil {
			return errors.New("la password attuale inserita non è corretta")
		}
	} else if !bytes.Equal(oldKEK, v.dek) {
		return errors.New("la password attuale inserita non è corretta")
	}

	newSalt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return err
	}
	newKEK := deriveKey(newPassword, newSalt)
	newWrapped, err := wrapDEK(newKEK, v.dek)
	if err != nil {
		return err
	}

	saltFile := filepath.Join(v.rootPath, "vault.salt")
	if err := os.WriteFile(keyFile+".tmp", newWrapped, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(saltFile+".tmp", newSalt, 0600); err != nil {
		_ = os.Remove(keyFile + ".tmp")
		return err
	}
	if err := os.Rename(keyFile+".tmp", keyFile); err != nil {
		return err
	}
	if err := os.Rename(saltFile+".tmp", saltFile); err != nil {
		return err
	}

	v.salt = newSalt
	return nil
}

// VerifyIntegrity esegue lo scrubbing parallelo su tutti i core verificando i tag Poly1305
// di ogni singolo chunk da 4 MB senza bisogno di decomprimere con Zstd.
func (v *SecureVault) VerifyIntegrity(onProgress ProgressFunc) (IntegrityReport, error) {
	v.mu.RLock()
	var files []FileEntry
	var totalDiskBytes int64
	for _, e := range v.index.Entries {
		if !e.IsDir {
			files = append(files, e)
			totalDiskBytes += e.DiskSize
		}
	}
	v.mu.RUnlock()

	var report IntegrityReport
	report.FilesChecked = len(files)

	var processedBytes int64
	var mu sync.Mutex
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}

	fileCh := make(chan FileEntry, len(files))
	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var compScratch []byte
			for entry := range fileCh {
				chunksOK, err := v.verifySingleFilePoly1305(entry, &compScratch)
				mu.Lock()
				if err != nil {
					report.CorruptedFiles = append(report.CorruptedFiles, fmt.Sprintf("%s (%v)", entry.VirtualPath, err))
				} else {
					report.ChunksVerified += chunksOK
					report.BytesVerified += entry.DiskSize
				}
				processedBytes += entry.DiskSize
				if onProgress != nil {
					onProgress(processedBytes, totalDiskBytes)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	sort.Strings(report.CorruptedFiles)
	return report, nil
}

func (v *SecureVault) verifySingleFilePoly1305(entry FileEntry, compScratch *[]byte) (int, error) {
	blobPath := filepath.Join(v.rootPath, "blocks", entry.BlobID)
	f, err := os.Open(blobPath)
	if err != nil {
		return 0, errors.New("blocco mancante su disco")
	}
	defer f.Close()

	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(f, header); err != nil {
		return 0, errors.New("header troncato")
	}
	if string(header[:len(VaultStreamMagic)]) != VaultStreamMagic {
		return 0, errors.New("magic SVAULT03 non valido")
	}
	streamID := header[len(VaultStreamMagic):]

	var lenBuf [4]byte
	var cipherBuf []byte
	for idx, expectedLen := range entry.ChunkSizes {
		if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
			return idx, fmt.Errorf("chunk %d mancante", idx)
		}
		gotLen := uint32(lenBuf[0]) | uint32(lenBuf[1])<<8 | uint32(lenBuf[2])<<16 | uint32(lenBuf[3])<<24
		if gotLen != expectedLen {
			return idx, fmt.Errorf("lunghezza chunk %d alterata", idx)
		}
		if cap(cipherBuf) < int(gotLen) {
			cipherBuf = make([]byte, gotLen)
		} else {
			cipherBuf = cipherBuf[:gotLen]
		}
		if _, err := io.ReadFull(f, cipherBuf); err != nil {
			return idx, fmt.Errorf("chunk %d troncato", idx)
		}

		isFinal := (idx == len(entry.ChunkSizes)-1)
		nonce, aad := buildChunkNonceAndAAD(streamID, uint64(idx), isFinal)
		if _, err := v.aead.Open((*compScratch)[:0], nonce, cipherBuf, aad); err != nil {
			return idx, fmt.Errorf("tag Poly1305 invalido al chunk %d", idx)
		}
	}
	return len(entry.ChunkSizes), nil
}
