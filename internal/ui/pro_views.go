package ui

import (
	"fmt"
	"image/color"
	"math"
	"os"
	"path/filepath"
	"strings"

	"secureusb/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func computeShannonEntropyGo(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	inv := 1.0 / float64(len(data))
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) * inv
			h -= p * math.Log2(p)
		}
	}
	return h
}

func entropyColorGo(h float64) color.NRGBA {
	switch {
	case h < 3.0:
		return color.NRGBA{R: 16, G: 185, B: 129, A: 255} // Emerald
	case h < 5.5:
		return color.NRGBA{R: 6, G: 182, B: 212, A: 255} // Cyan
	case h < 7.2:
		return color.NRGBA{R: 245, G: 158, B: 11, A: 255} // Amber
	default:
		return color.NRGBA{R: 244, G: 63, B: 94, A: 255} // Rose/Red
	}
}

// buildHexEntropyInspectorView costruisce l'Ispettore Hex O(1) con Mappa Termica dell'Entropia a 64 bande.
func buildHexEntropyInspectorView(v *vault.SecureVault, entry vault.FileEntry, onBackToTreemap func()) fyne.CanvasObject {
	var currentOffset int64
	offsetLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	hexArea := widget.NewMultiLineEntry()
	hexArea.TextStyle = fyne.TextStyle{Monospace: true}

	ribbonBox := container.NewGridWithColumns(32)

	loadWindow := func(off int64) {
		if off < 0 {
			off = 0
		}
		if entry.OriginalSize > 0 && off >= entry.OriginalSize {
			off = (entry.OriginalSize - 1) &^ 0x0F
		}
		currentOffset = off

		winSize := int64(4096)
		if entry.OriginalSize-off < winSize {
			winSize = entry.OriginalSize - off
		}
		buf := make([]byte, winSize)

		if len(entry.ChunkRefs) > 0 {
			if all, err := v.ReadDedupFile(entry.VirtualPath); err == nil && int(off) < len(all) {
				n := copy(buf, all[int(off):])
				buf = buf[:n]
			}
		} else if seeker, err := v.OpenReadSeeker(entry.VirtualPath); err == nil {
			n, _ := seeker.ReadAt(buf, off)
			buf = buf[:n]
			_ = seeker.Close()
		}

		globalH := computeShannonEntropyGo(buf)
		offsetLabel.SetText(fmt.Sprintf("🔬 Hex & Entropy Inspector: %s  |  Offset: 0x%08X  |  Entropia: %.2f / 8.00 bit/byte",
			filepath.Base(entry.VirtualPath), currentOffset, globalH))

		ribbonBox.Objects = nil
		step := len(buf) / 32
		if step < 16 {
			step = 16
		}
		for i := 0; i < 32; i++ {
			start := i * step
			var h float64
			if start < len(buf) {
				end := start + step
				if end > len(buf) {
					end = len(buf)
				}
				h = computeShannonEntropyGo(buf[start:end])
			}
			rect := canvas.NewRectangle(entropyColorGo(h))
			rect.SetMinSize(fyne.NewSize(12, 18))
			rect.CornerRadius = 3
			ribbonBox.Add(rect)
		}
		ribbonBox.Refresh()

		var sb strings.Builder
		for r := 0; r < len(buf); r += 16 {
			rowEnd := r + 16
			if rowEnd > len(buf) {
				rowEnd = len(buf)
			}
			chunk := buf[r:rowEnd]
			sb.WriteString(fmt.Sprintf("%08X  ", int(currentOffset)+r))
			for i := 0; i < 16; i++ {
				if i == 8 {
					sb.WriteByte(' ')
				}
				if i < len(chunk) {
					sb.WriteString(fmt.Sprintf("%02X ", chunk[i]))
				} else {
					sb.WriteString("   ")
				}
			}
			sb.WriteString(" |")
			for _, b := range chunk {
				if b >= 0x20 && b <= 0x7E {
					sb.WriteByte(b)
				} else {
					sb.WriteRune('·')
				}
			}
			sb.WriteString("|\n")
		}
		hexArea.SetText(sb.String())
	}

	prevBtn := widget.NewButton("◀ -4 KB", func() {
		loadWindow(currentOffset - 4096)
	})
	nextBtn := widget.NewButton("+4 KB ▶", func() {
		loadWindow(currentOffset + 4096)
	})
	nextChunkBtn := widget.NewButton("+4 MB (Chunk) ⏭", func() {
		loadWindow(currentOffset + 4*1024*1024)
	})
	backBtn := widget.NewButtonWithIcon("Torna a Donut & Treemap", theme.GridIcon(), onBackToTreemap)

	nav := container.NewHBox(prevBtn, nextBtn, nextChunkBtn, backBtn)
	header := container.NewVBox(
		container.NewBorder(nil, nil, offsetLabel, nav),
		widget.NewLabel("🌡️ Mappa Termica Entropia di Shannon (Verde = Testo/Bassa, Ciano = Codice, Ambra = Compresso, Rosso = Cifrato/Alta):"),
		ribbonBox,
		widget.NewSeparator(),
	)

	loadWindow(0)
	return container.NewBorder(header, nil, nil, nil, hexArea)
}

// buildSplitDualPaneView costruisce la vista a doppio pannello (Computer Locale ⟷ Vault USB).
func buildSplitDualPaneView(
	w fyne.Window,
	v *vault.SecureVault,
	currentVaultDir *string,
	onRefreshVault func(),
) fyne.CanvasObject {
	localDir := getDesktopDir()
	var localEntries []os.DirEntry
	var selectedLocalPath string

	localPathLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	var localList *widget.List

	refreshLocal := func() {
		localPathLabel.SetText("💻 PC Locale: " + localDir)
		raw, _ := os.ReadDir(localDir)
		localEntries = nil
		for _, e := range raw {
			if !vault.ShouldIgnoreFile(e.Name()) {
				localEntries = append(localEntries, e)
			}
		}
		selectedLocalPath = ""
		if localList != nil {
			localList.UnselectAll()
			localList.Refresh()
		}
	}

	localList = widget.NewList(
		func() int { return len(localEntries) },
		func() fyne.CanvasObject {
			return widget.NewLabel("Elemento Locale")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(localEntries) {
				return
			}
			e := localEntries[i]
			lbl := o.(*widget.Label)
			if e.IsDir() {
				lbl.SetText("📁 " + e.Name() + "/")
			} else {
				info, _ := e.Info()
				var sz int64
				if info != nil {
					sz = info.Size()
				}
				lbl.SetText(fmt.Sprintf("📄 %s  (%s)", e.Name(), formatBytes(sz)))
			}
		},
	)

	localList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(localEntries) {
			return
		}
		e := localEntries[id]
		full := filepath.Join(localDir, e.Name())
		if e.IsDir() {
			localDir = full
			refreshLocal()
		} else {
			selectedLocalPath = full
		}
	}

	upLocalBtn := widget.NewButton("⬆ Su PC", func() {
		parent := filepath.Dir(localDir)
		if parent != "" && parent != localDir {
			localDir = parent
			refreshLocal()
		}
	})

	encryptToVaultBtn := widget.NewButtonWithIcon("🔐 Cifra nel Vault USB ➔", theme.UploadIcon(), func() {
		if selectedLocalPath == "" {
			dialog.ShowInformation("Dual-Pane", "Seleziona prima un file dalla lista del PC locale a sinistra.", w)
			return
		}
		info, err := os.Stat(selectedLocalPath)
		if err != nil {
			return
		}
		_ = runWithBusySpinner(w, "Dual-Pane: Cifratura in Corso...", filepath.Base(selectedLocalPath), func() error {
			inFile, err := os.Open(selectedLocalPath)
			if err != nil {
				return err
			}
			defer inFile.Close()
			target := filepath.Join(*currentVaultDir, filepath.Base(selectedLocalPath))
			return v.WriteStream(target, inFile, info.Size(), nil)
		})
		onRefreshVault()
	})
	encryptToVaultBtn.Importance = widget.HighImportance

	encryptFolderBtn := widget.NewButtonWithIcon("📁 Cifra Cartella Attuale nel Vault ➔", theme.FolderOpenIcon(), func() {
		_ = runWithBusySpinner(w, "Dual-Pane: Cifratura Cartella...", localDir, func() error {
			_, err := v.ImportDir(localDir, *currentVaultDir, nil)
			return err
		})
		onRefreshVault()
	})

	decryptCurrentVaultBtn := widget.NewButtonWithIcon("⬅ Decifra Cartella Vault nel PC", theme.DownloadIcon(), func() {
		_ = runWithBusySpinner(w, "Dual-Pane: Decifratura verso PC...", *currentVaultDir, func() error {
			_, err := v.ExportDir(*currentVaultDir, localDir, nil)
			return err
		})
		refreshLocal()
	})

	refreshLocal()

	header := container.NewVBox(
		container.NewBorder(nil, nil, localPathLabel, upLocalBtn),
		container.NewGridWithColumns(3, encryptToVaultBtn, encryptFolderBtn, decryptCurrentVaultBtn),
		widget.NewSeparator(),
	)

	return container.NewBorder(header, nil, nil, nil, localList)
}

// showCommandPaletteModal apre la Command Palette rapida (Ctrl+K / Ctrl+P) in Fyne.
func showCommandPaletteModal(
	w fyne.Window,
	v *vault.SecureVault,
	onSelectFile func(vault.FileEntry),
	onSwitchTreemap func(),
	onSwitchDualPane func(),
	onScrub func(),
) {
	var modal dialog.Dialog
	searchInput := widget.NewEntry()
	searchInput.SetPlaceHolder("🔍 Digita un comando (treemap, dual-pane, scrub) o il nome di un file...")

	resultsBox := container.NewVBox()
	scroll := container.NewVScroll(resultsBox)
	scroll.SetMinSize(fyne.NewSize(580, 340))

	updateResults := func(q string) {
		resultsBox.Objects = nil
		ql := strings.ToLower(strings.TrimSpace(q))

		addCmd := func(label, keywords string, action func()) {
			if ql == "" || strings.Contains(strings.ToLower(label), ql) || strings.Contains(keywords, ql) {
				btn := widget.NewButton(label, func() {
					modal.Hide()
					action()
				})
				resultsBox.Add(btn)
			}
		}

		addCmd("🗺️ Apri Dashboard Spazio (Donut Chart + Sparkline + Treemap)", "treemap donut spazio", onSwitchTreemap)
		addCmd("🪟 Apri Vista Split Dual-Pane (Computer Locale ⟷ Vault USB)", "dual pane split locale pc", onSwitchDualPane)
		addCmd("🛡️ Esegui Verifica Integrità Globale (Scrub Poly1305)", "scrub poly1305 integrita", onScrub)

		matches := v.Search(ql)
		if len(matches) > 30 {
			matches = matches[:30]
		}
		for _, entry := range matches {
			eCopy := entry
			icon := "📄"
			if eCopy.IsDir {
				icon = "📁"
			}
			btn := widget.NewButton(fmt.Sprintf("%s %s  (%s)", icon, eCopy.VirtualPath, formatBytes(eCopy.OriginalSize)), func() {
				modal.Hide()
				onSelectFile(eCopy)
			})
			resultsBox.Add(btn)
		}
		resultsBox.Refresh()
	}

	searchInput.OnChanged = updateResults
	updateResults("")

	content := container.NewBorder(
		container.NewVBox(searchInput, widget.NewSeparator()),
		nil, nil, nil,
		scroll,
	)
	modal = dialog.NewCustom("⚡ Command Palette Rapida (Ctrl+K)", "Chiudi (Esc)", content, w)
	modal.Resize(fyne.NewSize(640, 440))
	modal.Show()
	w.Canvas().Focus(searchInput)
}
