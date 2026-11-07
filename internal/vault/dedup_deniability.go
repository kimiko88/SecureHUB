package vault

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ============================================================================
// 1. IMPLEMENTAZIONE NATIVA BLAKE3 KEYED HASH (RFC-Compliant, Zero Dipendenze)
// ============================================================================

const (
	b3ChunkStart = 1 << 0
	b3ChunkEnd   = 1 << 1
	b3Parent     = 1 << 2
	b3Root       = 1 << 3
	b3KeyedHash  = 1 << 4
)

var b3IV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var b3MsgSchedule = [7][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
	{3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
	{10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
	{12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
	{9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
	{11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
}

func b3G(s *[16]uint32, a, b, c, d int, mx, my uint32) {
	s[a] = s[a] + s[b] + mx
	s[d] = bits.RotateLeft32(s[d]^s[a], -16)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -12)
	s[a] = s[a] + s[b] + my
	s[d] = bits.RotateLeft32(s[d]^s[a], -8)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -7)
}

func b3Compress(cv [8]uint32, block [16]uint32, counter uint64, blockLen uint32, flags uint32) [8]uint32 {
	s := [16]uint32{
		cv[0], cv[1], cv[2], cv[3],
		cv[4], cv[5], cv[6], cv[7],
		b3IV[0], b3IV[1], b3IV[2], b3IV[3],
		uint32(counter), uint32(counter >> 32), blockLen, flags,
	}
	for r := 0; r < 7; r++ {
		sch := b3MsgSchedule[r]
		b3G(&s, 0, 4, 8, 12, block[sch[0]], block[sch[1]])
		b3G(&s, 1, 5, 9, 13, block[sch[2]], block[sch[3]])
		b3G(&s, 2, 6, 10, 14, block[sch[4]], block[sch[5]])
		b3G(&s, 3, 7, 11, 15, block[sch[6]], block[sch[7]])
		b3G(&s, 0, 5, 10, 15, block[sch[8]], block[sch[9]])
		b3G(&s, 1, 6, 11, 12, block[sch[10]], block[sch[11]])
		b3G(&s, 2, 7, 8, 13, block[sch[12]], block[sch[13]])
		b3G(&s, 3, 4, 9, 14, block[sch[14]], block[sch[15]])
	}
	var out [8]uint32
	for i := 0; i < 8; i++ {
		out[i] = s[i] ^ s[i+8]
	}
	return out
}

func b3ChunkCV(keyWords [8]uint32, chunk []byte, chunkCounter uint64, isSingleChunk bool) [8]uint32 {
	cv := keyWords
	numBlocks := (len(chunk) + 63) / 64
	if numBlocks == 0 {
		numBlocks = 1
	}
	for b := 0; b < numBlocks; b++ {
		start := b * 64
		end := start + 64
		if end > len(chunk) {
			end = len(chunk)
		}
		slice := chunk[start:end]
		var words [16]uint32
		var raw [64]byte
		copy(raw[:], slice)
		for i := 0; i < 16; i++ {
			words[i] = binary.LittleEndian.Uint32(raw[i*4 : (i+1)*4])
		}
		flags := uint32(b3KeyedHash)
		if b == 0 {
			flags |= b3ChunkStart
		}
		if b == numBlocks-1 {
			flags |= b3ChunkEnd
			if isSingleChunk {
				flags |= b3Root
			}
		}
		cv = b3Compress(cv, words, chunkCounter, uint32(len(slice)), flags)
	}
	return cv
}

// Blake3KeyedHash256 calcola l'hash crittografico BLAKE3-256 con chiave DEK a 256-bit.
func Blake3KeyedHash256(key []byte, data []byte) [32]byte {
	var keyWords [8]uint32
	for i := 0; i < 8 && (i+1)*4 <= len(key); i++ {
		keyWords[i] = binary.LittleEndian.Uint32(key[i*4 : (i+1)*4])
	}

	if len(data) <= 1024 {
		cv := b3ChunkCV(keyWords, data, 0, true)
		var out [32]byte
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint32(out[i*4:(i+1)*4], cv[i])
		}
		return out
	}

	var stack [][8]uint32
	var chunkCounter uint64
	for offset := 0; offset < len(data); offset += 1024 {
		end := offset + 1024
		if end > len(data) {
			end = len(data)
		}
		cv := b3ChunkCV(keyWords, data[offset:end], chunkCounter, false)
		totalChunks := chunkCounter + 1
		for totalChunks&1 == 0 && len(stack) > 0 {
			left := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			var parentBlock [16]uint32
			copy(parentBlock[0:8], left[:])
			copy(parentBlock[8:16], cv[:])
			flags := uint32(b3KeyedHash | b3Parent)
			if end == len(data) && len(stack) == 0 {
				flags |= b3Root
			}
			cv = b3Compress(keyWords, parentBlock, 0, 64, flags)
			totalChunks >>= 1
		}
		stack = append(stack, cv)
		chunkCounter++
	}

	for len(stack) > 1 {
		right := stack[len(stack)-1]
		left := stack[len(stack)-2]
		stack = stack[:len(stack)-2]
		var parentBlock [16]uint32
		copy(parentBlock[0:8], left[:])
		copy(parentBlock[8:16], right[:])
		flags := uint32(b3KeyedHash | b3Parent)
		if len(stack) == 0 {
			flags |= b3Root
		}
		stack = append(stack, b3Compress(keyWords, parentBlock, 0, 64, flags))
	}

	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:(i+1)*4], stack[0][i])
	}
	return out
}

// ============================================================================
// 2. PLAUSIBLE DENIABILITY (Dual-Slot vault.key + index.shadow)
// ============================================================================

func encodeKeySlot(password string, dek []byte) ([DualSlotSize]byte, error) {
	var slot [DualSlotSize]byte
	salt := slot[0:16]
	nonce := slot[16:40]
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return slot, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return slot, err
	}

	kek := deriveKey(password, salt)
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return slot, err
	}

	sealed := aead.Seal(nil, nonce, dek, []byte(VaultKeyDualMagic))
	copy(slot[40:88], sealed) // 32B DEK + 16B Poly1305 Tag = 48B
	_, _ = io.ReadFull(rand.Reader, slot[88:96])
	return slot, nil
}

func decodeKeySlot(password string, slot []byte) ([]byte, error) {
	if len(slot) < DualSlotSize {
		return nil, errors.New("slot chiave corto")
	}
	salt := slot[0:16]
	nonce := slot[16:40]
	cipherDEK := slot[40:88]

	kek := deriveKey(password, salt)
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, cipherDEK, []byte(VaultKeyDualMagic))
}

// initDualSlotKeyAndShadow inizializza vault.key a 2 slot (Slot 0 = Primario, Slot 1 = Rumore CSPRNG indistinguibile)
// e crea anche un file index.shadow cifrato con chiave effimera per garantire la Plausible Deniability.
func (v *SecureVault) initDualSlotKeyAndShadow(primaryPassword string) error {
	slot0, err := encodeKeySlot(primaryPassword, v.dek)
	if err != nil {
		return err
	}
	var slot1 [DualSlotSize]byte
	if _, err := io.ReadFull(rand.Reader, slot1[:]); err != nil {
		return err
	}

	var packet bytes.Buffer
	packet.WriteString(VaultKeyDualMagic)
	packet.Write(slot0[:])
	packet.Write(slot1[:])

	keyFile := filepath.Join(v.rootPath, "vault.key")
	if err := os.WriteFile(keyFile, packet.Bytes(), 0600); err != nil {
		return err
	}
	_ = WriteECCSidecar(keyFile)

	// Crea sempre index.shadow cifrato con chiave usa-e-getta così ogni USB ha identica impronta su disco
	ephemeralKey := make([]byte, KeySize)
	_, _ = io.ReadFull(rand.Reader, ephemeralKey)
	if ephAEAD, err := chacha20poly1305.NewX(ephemeralKey); err == nil {
		emptyIdx, _ := json.Marshal(VaultIndex{Entries: map[string]FileEntry{}})
		shadowPath := filepath.Join(v.rootPath, "index.shadow")
		if sf, err := os.OpenFile(shadowPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
			prevAEAD := v.aead
			v.aead = ephAEAD
			_, _, _, _ = v.encryptStreamParallel(bytes.NewReader(emptyIdx), sf, int64(len(emptyIdx)), nil)
			v.aead = prevAEAD
			_ = sf.Close()
			_ = WriteECCSidecar(shadowPath)
		}
	}
	return nil
}

func (v *SecureVault) unwrapDualOrLegacyDEK(password string, legacySalt []byte) (dek []byte, isShadow bool, activeIndex string, err error) {
	keyFile := filepath.Join(v.rootPath, "vault.key")
	_, _, _ = VerifyAndHealWithECC(keyFile)

	packet, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, false, "index.meta", err
	}

	magicLen := len(VaultKeyDualMagic)
	if len(packet) == magicLen+(2*DualSlotSize) && string(packet[:magicLen]) == VaultKeyDualMagic {
		slot0 := packet[magicLen : magicLen+DualSlotSize]
		if d, err0 := decodeKeySlot(password, slot0); err0 == nil {
			return d, false, "index.meta", nil
		}
		slot1 := packet[magicLen+DualSlotSize : magicLen+(2*DualSlotSize)]
		if d, err1 := decodeKeySlot(password, slot1); err1 == nil {
			return d, true, "index.shadow", nil
		}
		return nil, false, "index.meta", errors.New("password non valida per nessuno degli slot (Primario / Shadow)")
	}

	// Fallback retrocompatibile per SVKEY03 a singolo slot
	d, err := v.unwrapDEK(password, legacySalt)
	return d, false, "index.meta", err
}

// ConfigureShadowVault configura o aggiorna il Vault Nascosto (Slot 1 + index.shadow) con una seconda password.
func (v *SecureVault) ConfigureShadowVault(shadowPassword string) error {
	if len(shadowPassword) < 6 {
		return errors.New("la password del Vault Nascosto deve avere almeno 6 caratteri")
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	keyFile := filepath.Join(v.rootPath, "vault.key")
	packet, err := os.ReadFile(keyFile)
	if err != nil || len(packet) < len(VaultKeyDualMagic)+(2*DualSlotSize) {
		return errors.New("vault.key non supporta il formato Dual-Slot SVKEY04")
	}

	shadowDEK := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, shadowDEK); err != nil {
		return err
	}
	slot1, err := encodeKeySlot(shadowPassword, shadowDEK)
	if err != nil {
		return err
	}

	magicLen := len(VaultKeyDualMagic)
	copy(packet[magicLen+DualSlotSize:], slot1[:])
	if err := os.WriteFile(keyFile, packet, 0600); err != nil {
		return err
	}
	_ = WriteECCSidecar(keyFile)

	// Inizializza index.shadow cifrato con la nuova shadowDEK
	shadowAEAD, err := chacha20poly1305.NewX(shadowDEK)
	if err != nil {
		return err
	}
	emptyIdx, _ := json.Marshal(VaultIndex{
		Entries:        make(map[string]FileEntry),
		ChunkRefCounts: make(map[string]int),
	})
	shadowPath := filepath.Join(v.rootPath, "index.shadow")
	sf, err := os.OpenFile(shadowPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	prevAEAD := v.aead
	v.aead = shadowAEAD
	_, _, _, sErr := v.encryptStreamParallel(bytes.NewReader(emptyIdx), sf, int64(len(emptyIdx)), nil)
	v.aead = prevAEAD
	_ = sf.Close()
	if sErr != nil {
		return sErr
	}
	return WriteECCSidecar(shadowPath)
}

func (v *SecureVault) IsShadowSession() bool {
	return v.isShadow
}

// ============================================================================
// 3. CONTENT-ADDRESSED DEDUPLICATION (BLAKE3 Keyed su Chunk da 4 MB)
// ============================================================================

// WriteFileDedup divide il flusso in chunk da 4 MB, calcola l'hash BLAKE3-Keyed(DEK, chunk)
// e salva su disco solo i chunk mai visti prima, riutilizzando quelli identici in O(1).
func (v *SecureVault) WriteStreamDedup(virtualPath string, src io.Reader, expectedSize int64, onProgress ProgressFunc) (dedupHits int, err error) {
	virtualPath = normalizePath(virtualPath)
	br := bufio.NewReaderSize(src, 128*1024)

	bufPtr := v.chunkPool.Get().(*[]byte)
	defer v.chunkPool.Put(bufPtr)
	plainBuf := *bufPtr

	var chunkRefs []string
	var chunkSizes []uint32
	var totalPlain int64
	var totalDisk int64

	for {
		readBytes, readErr := io.ReadFull(br, plainBuf)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return dedupHits, readErr
		}
		_, peekErr := br.Peek(1)
		isFinal := (readErr == io.EOF || readErr == io.ErrUnexpectedEOF || peekErr == io.EOF)

		chunkSlice := plainBuf[:readBytes]
		totalPlain += int64(readBytes)

		// 1. Calcola l'ID univoco Content-Addressed tramite BLAKE3 Keyed con la DEK del Vault
		b3Sum := Blake3KeyedHash256(v.dek, chunkSlice)
		cid := hex.EncodeToString(b3Sum[:]) + ".chk"
		chkPath := filepath.Join(v.rootPath, "blocks", cid)

		if st, statErr := os.Stat(chkPath); statErr == nil && st.Size() > 0 {
			// Fast-Path Deduplication Hit: il blocco da 4 MB esiste già sulla USB!
			dedupHits++
			chunkRefs = append(chunkRefs, cid)
			chunkSizes = append(chunkSizes, uint32(st.Size()))
		} else {
			// Cache Miss: comprime con Zstd e cifra legando l'hash BLAKE3 nell'AAD
			comp := v.encoder.EncodeAll(chunkSlice, nil)
			nonce := make([]byte, NonceSize)
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return dedupHits, err
			}
			sealed := v.aead.Seal(nil, nonce, comp, b3Sum[:])
			packet := append(nonce, sealed...)

			tmpChk := chkPath + ".tmp"
			if err := os.WriteFile(tmpChk, packet, 0600); err != nil {
				return dedupHits, err
			}
			if err := os.Rename(tmpChk, chkPath); err != nil {
				return dedupHits, err
			}
			chunkRefs = append(chunkRefs, cid)
			chunkSizes = append(chunkSizes, uint32(len(packet)))
			totalDisk += int64(len(packet))
		}

		if onProgress != nil {
			onProgress(totalPlain, expectedSize)
		}
		if isFinal {
			break
		}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.index.ChunkRefCounts == nil {
		v.index.ChunkRefCounts = make(map[string]int)
	}
	// Se sovrascriviamo un file deduplicato esistente, decrementa i vecchi riferimenti
	if oldEntry, exists := v.index.Entries[virtualPath]; exists {
		for _, oldCID := range oldEntry.ChunkRefs {
			v.index.ChunkRefCounts[oldCID]--
		}
	}
	for _, cid := range chunkRefs {
		v.index.ChunkRefCounts[cid]++
	}

	v.index.Entries[virtualPath] = FileEntry{
		VirtualPath:  virtualPath,
		BlobID:       chunkRefs[0],
		IsDir:        false,
		OriginalSize: totalPlain,
		DiskSize:     totalDisk,
		ChunkSizes:   chunkSizes,
		ChunkRefs:    chunkRefs,
		UpdatedAt:    time.Now(),
	}

	return dedupHits, v.saveIndexLocked()
}

// ReadDedupFile ricostruisce un file salvato tramite deduplicazione Content-Addressed BLAKE3.
func (v *SecureVault) ReadDedupFile(virtualPath string) ([]byte, error) {
	virtualPath = normalizePath(virtualPath)
	v.mu.RLock()
	entry, ok := v.index.Entries[virtualPath]
	v.mu.RUnlock()
	if !ok || entry.IsDir {
		return nil, errors.New("file non trovato")
	}
	if len(entry.ChunkRefs) == 0 {
		return v.ReadFile(virtualPath)
	}

	var out bytes.Buffer
	out.Grow(int(entry.OriginalSize))

	for _, cid := range entry.ChunkRefs {
		chkPath := filepath.Join(v.rootPath, "blocks", cid)
		packet, err := os.ReadFile(chkPath)
		if err != nil || len(packet) < NonceSize+v.aead.Overhead() {
			return nil, errors.New("chunk deduplicato mancante o corrotto")
		}
		hexStr := cid[:len(cid)-4]
		aadBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, err
		}
		comp, err := v.aead.Open(nil, packet[:NonceSize], packet[NonceSize:], aadBytes)
		if err != nil {
			return nil, errors.New("autenticazione Poly1305 fallita sul chunk deduplicato")
		}
		plain, err := v.decoder.DecodeAll(comp, nil)
		if err != nil {
			return nil, err
		}
		out.Write(plain)
	}
	return out.Bytes(), nil
}
