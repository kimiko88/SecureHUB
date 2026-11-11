package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"sync"
)

const (
	rsDataShards   = 8
	rsParityShards = 4
	rsTotalShards  = rsDataShards + rsParityShards
	eccMagicHeader = "RSECC01\x00"
)

var (
	gfOnce   sync.Once
	gfExp    [512]byte
	gfLog    [256]byte
	rsMatrix [rsTotalShards][rsDataShards]byte
)

// initGF256 inizializza le tabelle di logaritmo/esponenziale su GF(2^8) (polinomio 0x11d)
// e costruisce una matrice di codifica sistematica Vandermonde 12x8.
func initGF256() {
	gfOnce.Do(func() {
		x := 1
		for i := 0; i < 255; i++ {
			gfExp[i] = byte(x)
			gfExp[i+255] = byte(x)
			gfLog[x] = byte(i)
			x <<= 1
			if x&0x100 != 0 {
				x ^= 0x11d
			}
		}
		gfLog[0] = 0

		// Costruisce una matrice di Cauchy su GF(2^8) per i 4 shard di parità
		// (Qualsiasi sottomatrice quadrata di una matrice di Cauchy è garantita invertibile!)
		for r := 0; r < rsDataShards; r++ {
			rsMatrix[r][r] = 1
		}
		for r := 0; r < rsParityShards; r++ {
			for c := 0; c < rsDataShards; c++ {
				rsMatrix[rsDataShards+r][c] = gfInv(byte((rsDataShards + r) ^ c))
			}
		}
	})
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}

// WriteECCSidecar genera e salva il file "<targetPath>.ecc" con 4 shard di parità Reed-Solomon
// e gli hash SHA-256 dei 12 shard, permettendo di riparare fino al 33.3% di settori NAND corrotti.
func WriteECCSidecar(targetPath string) error {
	initGF256()
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return err
	}

	shardSize := (len(data) + rsDataShards - 1) / rsDataShards
	if shardSize == 0 {
		shardSize = 1
	}

	shards := make([][]byte, rsTotalShards)
	for i := 0; i < rsTotalShards; i++ {
		shards[i] = make([]byte, shardSize)
	}
	for i := 0; i < rsDataShards; i++ {
		start := i * shardSize
		if start < len(data) {
			end := start + shardSize
			if end > len(data) {
				end = len(data)
			}
			copy(shards[i], data[start:end])
		}
	}

	// Calcola i 4 shard di parità su GF(2^8)
	for p := 0; p < rsParityShards; p++ {
		row := rsMatrix[rsDataShards+p]
		pShard := shards[rsDataShards+p]
		for c := 0; c < rsDataShards; c++ {
			coeff := row[c]
			dShard := shards[c]
			for bIdx := 0; bIdx < shardSize; bIdx++ {
				pShard[bIdx] ^= gfMul(coeff, dShard[bIdx])
			}
		}
	}

	// Formato file .ecc:
	// [Magic 8B][OrigSize uint64 LE][ShardSize uint32 LE][12 * SHA256 (384B)][4 * ParityShards]
	var out bytes.Buffer
	out.WriteString(eccMagicHeader)
	var hdr [12]byte
	binary.LittleEndian.PutUint64(hdr[0:8], uint64(len(data)))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(shardSize))
	out.Write(hdr[:])

	for i := 0; i < rsTotalShards; i++ {
		sum := sha256.Sum256(shards[i])
		out.Write(sum[:])
	}
	for p := 0; p < rsParityShards; p++ {
		out.Write(shards[rsDataShards+p])
	}

	eccPath := targetPath + ".ecc"
	tmpEcc := eccPath + ".tmp"
	if err := os.WriteFile(tmpEcc, out.Bytes(), 0600); err != nil {
		return err
	}
	return os.Rename(tmpEcc, eccPath)
}

// VerifyAndHealWithECC verifica l'integrità di targetPath rispetto a "<targetPath>.ecc".
// Se rileva bit-rot o troncamento (fino a 4 shard corrotti su 12), ricostruisce i dati esatti
// mediante eliminazione di Gauss su GF(2^8) e ripara automaticamente il file su disco.
func VerifyAndHealWithECC(targetPath string) (healed bool, damagedShards int, err error) {
	initGF256()
	eccPath := targetPath + ".ecc"
	eccRaw, err := os.ReadFile(eccPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, 0, nil // Sidecar assente: nessun controllo ECC disponibile.
		}
		return false, 0, err
	}

	const fixedHdr = 8 + 12 + (rsTotalShards * 32)
	if len(eccRaw) < fixedHdr || string(eccRaw[:8]) != eccMagicHeader {
		return false, 0, errors.New("file .ecc corrotto")
	}

	origSize := int(binary.LittleEndian.Uint64(eccRaw[8:16]))
	shardSize := int(binary.LittleEndian.Uint32(eccRaw[16:20]))
	if shardSize <= 0 || len(eccRaw) != fixedHdr+(rsParityShards*shardSize) {
		return false, 0, errors.New("dimensioni .ecc incoerenti")
	}

	var expectedHashes [rsTotalShards][32]byte
	offset := 20
	for i := 0; i < rsTotalShards; i++ {
		copy(expectedHashes[i][:], eccRaw[offset:offset+32])
		offset += 32
	}

	rawData, readErr := os.ReadFile(targetPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		// Non confondere un errore di permessi/I/O con un file cancellato:
		// altrimenti la procedura potrebbe ricostruire e sovrascrivere dati.
		return false, damagedShards, readErr
	}
	shards := make([][]byte, rsTotalShards)
	validShard := make([]bool, rsTotalShards)

	for i := 0; i < rsDataShards; i++ {
		shards[i] = make([]byte, shardSize)
		start := i * shardSize
		if start < len(rawData) {
			end := start + shardSize
			if end > len(rawData) {
				end = len(rawData)
			}
			copy(shards[i], rawData[start:end])
		}
		if sha256.Sum256(shards[i]) == expectedHashes[i] {
			validShard[i] = true
		} else {
			damagedShards++
		}
	}

	if damagedShards == 0 && len(rawData) == origSize {
		return false, 0, nil
	}

	for p := 0; p < rsParityShards; p++ {
		idx := rsDataShards + p
		shards[idx] = make([]byte, shardSize)
		copy(shards[idx], eccRaw[offset:offset+shardSize])
		offset += shardSize
		if sha256.Sum256(shards[idx]) == expectedHashes[idx] {
			validShard[idx] = true
		}
	}

	// Seleziona 8 shard integri per invertire la sottomatrice 8x8 in GF(2^8)
	var subMatrix [rsDataShards][rsDataShards]byte
	var subShards [rsDataShards][]byte
	found := 0
	for i := 0; i < rsTotalShards && found < rsDataShards; i++ {
		if validShard[i] {
			subMatrix[found] = rsMatrix[i]
			subShards[found] = shards[i]
			found++
		}
	}
	if found < rsDataShards {
		return false, damagedShards, errors.New("troppi settori NAND danneggiati (> 4 shard su 12)")
	}

	invMatrix, err := invertMatrixGF256(subMatrix)
	if err != nil {
		return false, damagedShards, err
	}

	// Ricostruisce gli shard dati corrotti
	for d := 0; d < rsDataShards; d++ {
		if validShard[d] {
			continue
		}
		reconstructed := make([]byte, shardSize)
		row := invMatrix[d]
		for c := 0; c < rsDataShards; c++ {
			coeff := row[c]
			srcShard := subShards[c]
			for bIdx := 0; bIdx < shardSize; bIdx++ {
				reconstructed[bIdx] ^= gfMul(coeff, srcShard[bIdx])
			}
		}
		shards[d] = reconstructed
	}

	var healedBuf bytes.Buffer
	for d := 0; d < rsDataShards; d++ {
		healedBuf.Write(shards[d])
	}
	healedBytes := healedBuf.Bytes()
	if len(healedBytes) > origSize {
		healedBytes = healedBytes[:origSize]
	}

	if err := os.WriteFile(targetPath, healedBytes, 0600); err != nil {
		return false, damagedShards, err
	}
	return true, damagedShards, nil
}

func invertMatrixGF256(m [rsDataShards][rsDataShards]byte) ([rsDataShards][rsDataShards]byte, error) {
	var inv [rsDataShards][rsDataShards]byte
	for i := 0; i < rsDataShards; i++ {
		inv[i][i] = 1
	}

	for col := 0; col < rsDataShards; col++ {
		if m[col][col] == 0 {
			swapRow := -1
			for r := col + 1; r < rsDataShards; r++ {
				if m[r][col] != 0 {
					swapRow = r
					break
				}
			}
			if swapRow == -1 {
				return inv, errors.New("matrice singolare in GF(2^8)")
			}
			m[col], m[swapRow] = m[swapRow], m[col]
			inv[col], inv[swapRow] = inv[swapRow], inv[col]
		}

		pivotInv := gfInv(m[col][col])
		for j := 0; j < rsDataShards; j++ {
			m[col][j] = gfMul(m[col][j], pivotInv)
			inv[col][j] = gfMul(inv[col][j], pivotInv)
		}

		for r := 0; r < rsDataShards; r++ {
			if r == col || m[r][col] == 0 {
				continue
			}
			factor := m[r][col]
			for j := 0; j < rsDataShards; j++ {
				m[r][j] ^= gfMul(factor, m[col][j])
				inv[r][j] ^= gfMul(factor, inv[col][j])
			}
		}
	}
	return inv, nil
}
