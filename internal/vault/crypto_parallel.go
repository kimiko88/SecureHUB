package vault

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
