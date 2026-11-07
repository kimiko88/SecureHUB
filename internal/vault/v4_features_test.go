package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestV4_PlausibleDeniabilityDualVault(t *testing.T) {
	tmpDir := t.TempDir()
	primaryPass := "Password-Pubblica-Copertura-123"
	shadowPass := "Password-Segreta-Invisibile-999"

	// 1. Inizializza il Vault con la password primaria e salva un file di copertura
	vPrimary, err := InitOrOpenVault(tmpDir, primaryPass, true)
	if err != nil {
		t.Fatalf("Init primario fallito: %v", err)
	}
	if err := vPrimary.WriteFile("/ricette_cucina.txt", []byte("Pasta al pomodoro")); err != nil {
		t.Fatal(err)
	}

	// 2. Configura il secondo Vault Nascosto (Slot 1 + index.shadow)
	if err := vPrimary.ConfigureShadowVault(shadowPass); err != nil {
		t.Fatalf("ConfigureShadowVault fallito: %v", err)
	}
	vPrimary.Close()

	// 3. Apre il Vault inserendo la PASSWORD SEGRETA -> deve montare trasparentemente index.shadow!
	vShadow, err := InitOrOpenVault(tmpDir, shadowPass, false)
	if err != nil {
		t.Fatalf("Apertura Shadow Vault fallita: %v", err)
	}
	if !vShadow.IsShadowSession() {
		t.Fatal("La sessione dovrebbe essere riconosciuta come Shadow Vault")
	}
	if _, exists := vShadow.Stat("/ricette_cucina.txt"); exists {
		t.Fatal("I file del Vault primario NON devono apparire nello Shadow Vault")
	}
	if err := vShadow.WriteFile("/chiavi_private_btc.txt", []byte("seed-segreto-24-parole")); err != nil {
		t.Fatal(err)
	}
	vShadow.Close()

	// 4. Riapre con la PASSWORD PRIMARIA -> vede solo i file innocui di copertura!
	vCheckPrimary, err := InitOrOpenVault(tmpDir, primaryPass, false)
	if err != nil {
		t.Fatal(err)
	}
	defer vCheckPrimary.Close()
	if vCheckPrimary.IsShadowSession() {
		t.Fatal("Non dovrebbe essere una sessione Shadow con la password primaria")
	}
	if _, exists := vCheckPrimary.Stat("/chiavi_private_btc.txt"); exists {
		t.Fatal("I file segreti dello Shadow Vault NON devono mai comparire nel Vault primario!")
	}
}

func TestV4_Blake3ContentAddressedDeduplication(t *testing.T) {
	tmpDir := t.TempDir()
	v, err := InitOrOpenVault(tmpDir, "DedupMasterKey!", true)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Crea un payload di 5 MB (1 chunk da 4 MB + 1 chunk da 1 MB)
	payload := bytes.Repeat([]byte("BloccoRipetutoPerMacchinaVirtuale_"), (5*1024*1024)/34+1)[:5*1024*1024]

	// Prima scrittura: 0 dedup hits
	hits1, err := v.WriteStreamDedup("/vm/snapshot_v1.img", bytes.NewReader(payload), int64(len(payload)), nil)
	if err != nil {
		t.Fatalf("Prima WriteStreamDedup fallita: %v", err)
	}
	if hits1 != 0 {
		t.Fatalf("Attesi 0 dedup hit alla prima scrittura, ottenuti %d", hits1)
	}

	// Seconda scrittura dello stesso file (copia): tutti i 2 chunk devono fare Dedup Hit (0 byte scritti su disco!)
	hits2, err := v.WriteStreamDedup("/vm/snapshot_v2_copy.img", bytes.NewReader(payload), int64(len(payload)), nil)
	if err != nil {
		t.Fatalf("Seconda WriteStreamDedup fallita: %v", err)
	}
	if hits2 != 2 {
		t.Fatalf("Attesi 2 dedup hit completi sulla seconda copia, ottenuti %d", hits2)
	}

	e2, _ := v.Stat("/vm/snapshot_v2_copy.img")
	if e2.DiskSize != 0 {
		t.Fatalf("La seconda copia deduplicata dovrebbe occupare 0 byte aggiuntivi su disco, occupati %d", e2.DiskSize)
	}

	got, err := v.ReadDedupFile("/vm/snapshot_v2_copy.img")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("Il file ricostruito dai chunk deduplicati non coincide con l'originale")
	}
}

func TestV4_ReedSolomonBitRotAutoRepair(t *testing.T) {
	tmpDir := t.TempDir()
	pass := "ReedSolomonPass2026!"

	v, err := InitOrOpenVault(tmpDir, pass, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.WriteFile("/documento_critico.txt", []byte("Dati protetti da parità Reed-Solomon GF(256)")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// Simula un grave bit-rot NAND sovrascrivendo con 0xFF il 20% centrale di index.meta!
	indexPath := filepath.Join(tmpDir, ".secure_vault", "index.meta")
	rawIdx, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	corruptLen := len(rawIdx) / 5
	for i := 0; i < corruptLen; i++ {
		rawIdx[10+i] ^= 0xFF
	}
	if err := os.WriteFile(indexPath, rawIdx, 0600); err != nil {
		t.Fatal(err)
	}

	// Riaprendo il Vault, VerifyAndHealWithECC deve riparare automaticamente index.meta prima di Poly1305!
	vHealed, err := InitOrOpenVault(tmpDir, pass, false)
	if err != nil {
		t.Fatalf("Reed-Solomon ECC avrebbe dovuto riparare index.meta automaticamente, ma ha restituito errore: %v", err)
	}
	defer vHealed.Close()

	content, err := vHealed.ReadFile("/documento_critico.txt")
	if err != nil || string(content) != "Dati protetti da parità Reed-Solomon GF(256)" {
		t.Fatalf("Contenuto dopo auto-riparazione ECC non valido: %v", err)
	}
}
