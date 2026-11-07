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
