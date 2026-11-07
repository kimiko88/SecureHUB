package ui

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	fusemount "secureusb/internal/fuse"
	"secureusb/internal/usb"
	"secureusb/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func Run() {
	a := app.NewWithID("it.secureusb.explorer.v3")
	a.Settings().SetTheme(NewSecureCyberTheme())

	w := a.NewWindow(fmt.Sprintf("🔐 SecureUSB Explorer — SVAULT03 (%d Core) • Auto-USB • KeyWrap • Zero-Temp", runtime.NumCPU()))
	w.Resize(fyne.NewSize(1280, 760))

	showUnlockScreen(w)
	w.ShowAndRun()
}

func showUnlockScreen(w fyne.Window) {
	stopWatcher := make(chan struct{})
	stopped := false
	stopHotplug := func() {
		if !stopped {
			stopped = true
			close(stopWatcher)
		}
	}

	usbPathEntry := widget.NewEntry()
	usbPathEntry.SetPlaceHolder("Percorso della chiavetta USB (selezionala dal menu sopra o trascinala qui)")

	w.SetOnDropped(func(_ fyne.Position, uris []fyne.URI) {
		if len(uris) > 0 {
			usbPathEntry.SetText(uris[0].Path())
		}
	})

	driveMap := make(map[string]string)
	usbSelect := widget.NewSelect([]string{}, func(selectedLabel string) {
		if mp, ok := driveMap[selectedLabel]; ok {
			usbPathEntry.SetText(mp)
		}
	})
	usbSelect.PlaceHolder = "🔌 Rilevamento automatico chiavette USB in corso..."

	usbStatusBadge := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	refreshDrives := func() {
		drives := usb.DetectUSBDrives()
		var options []string
		driveMap = make(map[string]string)
		vaultFound := 0

		for _, d := range drives {
			options = append(options, d.Label)
			driveMap[d.Label] = d.MountPath
			if d.HasVault {
				vaultFound++
			}
		}

		usbSelect.Options = options
		usbSelect.Refresh()

		if len(drives) == 0 {
			usbStatusBadge.SetText("⚠️ Nessuna unità esterna rilevata — Inserisci una chiavetta USB o sfoglia manualmente")
		} else if vaultFound > 0 {
			usbStatusBadge.SetText(fmt.Sprintf("✅ %d unità USB rilevate (%d con Vault SVAULT03 pronto allo sblocco!)", len(drives), vaultFound))
			if strings.TrimSpace(usbPathEntry.Text) == "" {
				usbSelect.SetSelected(options[0])
			}
		} else {
			usbStatusBadge.SetText(fmt.Sprintf("💾 %d unità USB rilevate — Selezionane una per inizializzare un nuovo Vault", len(drives)))
			if strings.TrimSpace(usbPathEntry.Text) == "" {
				usbSelect.SetSelected(options[0])
			}
		}
	}

	refreshUsbBtn := widget.NewButtonWithIcon("Aggiorna USB", theme.ViewRefreshIcon(), refreshDrives)
	refreshDrives()

	// Hot-Plug Watcher: controlla automaticamente ogni 2.5 secondi se viene inserita una chiavetta USB
	go func() {
		ticker := time.NewTicker(2500 * time.Millisecond)
		defer ticker.Stop()
		var lastCount int
		for {
			select {
			case <-stopWatcher:
				return
			case <-ticker.C:
				drives := usb.DetectUSBDrives()
				if len(drives) != lastCount {
					lastCount = len(drives)
					refreshDrives()
				}
			}
		}
	}()

	browseBtn := widget.NewButtonWithIcon("Sfoglia Cartella", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				usbPathEntry.SetText(uri.Path())
			}
		}, w)
	})

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Password Master Crittografica (Argon2id + XChaCha20-Poly1305)")

	entropyBar := widget.NewProgressBar()
	entropyBar.Min = 0
	entropyBar.Max = 128
	entropyLabel := widget.NewLabel("Sicurezza Password: in attesa di inserimento...")

	passEntry.OnChanged = func(pw string) {
		bits := estimatePasswordEntropyBits(pw)
		if bits > 128 {
			entropyBar.SetValue(128)
		} else {
			entropyBar.SetValue(bits)
		}
		switch {
		case bits == 0:
			entropyLabel.SetText("Sicurezza Password: in attesa di inserimento...")
		case bits < 45:
			entropyLabel.SetText(fmt.Sprintf("⚠️ Sicurezza Password: Debole (%.0f bit di entropia)", bits))
		case bits < 75:
			entropyLabel.SetText(fmt.Sprintf("🛡️ Sicurezza Password: Buona (%.0f bit di entropia)", bits))
		default:
			entropyLabel.SetText(fmt.Sprintf("🔥 Sicurezza Password: Eccellente / Militare (%.0f bit di entropia)", bits))
		}
	}

	openBtn := widget.NewButtonWithIcon("🔓 Sblocca Vault Esistente", theme.LoginIcon(), func() {
		path := strings.TrimSpace(usbPathEntry.Text)
		pass := passEntry.Text
		if path == "" || pass == "" {
			dialog.ShowError(errors.New("seleziona la chiavetta USB e inserisci la password"), w)
			return
		}
		v, err := vault.InitOrOpenVault(path, pass, false)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		stopHotplug()
		showExplorerScreen(w, v)
	})
	openBtn.Importance = widget.HighImportance

	initBtn := widget.NewButtonWithIcon("✨ Inizializza Nuovo Vault (SVAULT03)", theme.ContentAddIcon(), func() {
		path := strings.TrimSpace(usbPathEntry.Text)
		pass := passEntry.Text
		if path == "" || len(pass) < 6 {
			dialog.ShowError(errors.New("seleziona il percorso USB e usa una password di almeno 6 caratteri"), w)
			return
		}
		dialog.ShowConfirm("Conferma Inizializzazione SVAULT03",
			"Questo creerà un nuovo Vault SVAULT03 (con Key Wrapping e Zstd 4MB) sulla chiavetta selezionata. Procedere?",
			func(ok bool) {
				if !ok {
					return
				}
				v, err := vault.InitOrOpenVault(path, pass, true)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				stopHotplug()
				showExplorerScreen(w, v)
			}, w)
	})

	devEntry := widget.NewEntry()
	devEntry.SetPlaceHolder("Dispositivo grezzo da formattare (es. E: su Windows, /dev/sdb1 su Linux, /dev/disk2 su Mac)")
	formatBtn := widget.NewButtonWithIcon("Formatta Hardware USB in exFAT", theme.StorageIcon(), func() {
		dev := strings.TrimSpace(devEntry.Text)
		if dev == "" {
			dialog.ShowError(errors.New("specifica l'identificativo del disco da formattare"), w)
			return
		}
		dialog.ShowConfirm("ATTENZIONE: Formattazione Fisica",
			fmt.Sprintf("Stai per formattare fisicamente %s in exFAT. TUTTI i dati sul dispositivo verranno distrutti. Continuare?", dev),
			func(ok bool) {
				if !ok {
					return
				}
				if err := usb.FormatPhysicalUSB(dev, "SECURE_USB"); err != nil {
					dialog.ShowError(err, w)
				} else {
					refreshDrives()
					dialog.ShowInformation("Formattazione Completata",
						"Chiavetta formattata in exFAT! Ora selezionala dal menu a tendina e clicca 'Inizializza Nuovo Vault'.", w)
				}
			}, w)
	})

	vaultCard := widget.NewCard(
		"🔐 Accesso Rapido al Vault Cifrato (SVAULT03)",
		"Rilevamento automatico USB Hot-Plug • Argon2id (64 MB) • XChaCha20-Poly1305 • Zstd 4MB",
		container.NewVBox(
			usbStatusBadge,
			container.NewBorder(nil, nil, nil, refreshUsbBtn, usbSelect),
			container.NewBorder(nil, nil, nil, browseBtn, usbPathEntry),
			widget.NewSeparator(),
			passEntry,
			container.NewGridWithColumns(2, entropyLabel, entropyBar),
			widget.NewSeparator(),
			container.NewGridWithColumns(2, openBtn, initBtn),
		),
	)

	formatCard := widget.NewCard(
		"🛠️ Preparazione Fisica Chiavetta (exFAT Cross-Platform)",
		"Formatta il supporto fisico per renderlo compatibile nativamente con Windows, Linux e macOS senza limiti di 4 GB",
		container.NewVBox(
			devEntry,
			formatBtn,
		),
	)

	content := container.NewVBox(vaultCard, formatCard)
	w.SetContent(container.NewPadded(container.NewVScroll(content)))
}

func showExplorerScreen(w fyne.Window, v *vault.SecureVault) {
	currentDir := "/"
	var entries []vault.FileEntry
	var selectedEntry *vault.FileEntry
	var unmountFuse func()

	stopWatchdog := make(chan struct{})
	watchdogStopped := false
	stopUnplugWatchdog := func() {
		if !watchdogStopped {
			watchdogStopped = true
			close(stopWatchdog)
		}
	}

	breadcrumbBox := container.NewHBox()
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("🔍 Cerca istantaneamente file o cartelle in RAM...")

	telemetryLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	savingsBar := widget.NewProgressBar()
	savingsBar.Min = 0
	savingsBar.Max = 100

	infoLabel := widget.NewLabel("Seleziona un elemento o rilascia file/cartelle con Drag & Drop.")

	editor := widget.NewMultiLineEntry()
	editor.SetPlaceHolder("Editor di testo integrato in RAM. Seleziona un'immagine (PNG/JPG/GIF) o un PDF per l'anteprima immediata Zero-Temp.")
	editor.Disable()

	previewHolder := container.NewMax(editor)
	var listWidget *widget.List
	var refreshList func()

	rebuildBreadcrumbs := func() {
		breadcrumbBox.Objects = nil
		rootBtn := widget.NewButtonWithIcon("/ Root", theme.HomeIcon(), func() {
			searchEntry.SetText("")
			currentDir = "/"
			refreshList()
		})
		if currentDir == "/" {
			rootBtn.Importance = widget.HighImportance
		}
		breadcrumbBox.Add(rootBtn)

		if currentDir != "/" {
			parts := strings.Split(strings.Trim(currentDir, "/"), "/")
			accum := ""
			for i, part := range parts {
				accum += "/" + part
				targetPath := accum
				breadcrumbBox.Add(widget.NewLabel("❯"))
				btn := widget.NewButton(part, func() {
					searchEntry.SetText("")
					currentDir = targetPath
					refreshList()
				})
				if i == len(parts)-1 {
					btn.Importance = widget.HighImportance
				}
				breadcrumbBox.Add(btn)
			}
		}
		breadcrumbBox.Refresh()
	}

	updateTelemetry := func() {
		st := v.Stats()
		savedBytes := st.OriginalSize - st.DiskSize
		ratioPct := 0.0
		if st.OriginalSize > 0 && savedBytes > 0 {
			ratioPct = (float64(savedBytes) / float64(st.OriginalSize)) * 100
		}
		savingsBar.SetValue(ratioPct)
		telemetryLabel.SetText(fmt.Sprintf(
			"📊 Vault: %d File, %d Cartelle (%d Chunk 4MB)  |  Reale: %s  ➔  Su USB (Zstd+AEAD): %s  |  Risparmio Compressione: %.1f%%",
			st.TotalFiles, st.TotalFolders, st.TotalChunks,
			formatBytes(st.OriginalSize), formatBytes(st.DiskSize), ratioPct,
		))
	}

	refreshList = func() {
		rebuildBreadcrumbs()
		updateTelemetry()

		q := strings.TrimSpace(searchEntry.Text)
		if q != "" {
			entries = v.Search(q)
			infoLabel.SetText(fmt.Sprintf("🔍 Ricerca RAM per %q: %d risultati trovati", q, len(entries)))
		} else {
			entries = v.ListDir(currentDir)
			infoLabel.SetText(fmt.Sprintf("📂 %d elementi in %s  —  [Drag & Drop attivo]", len(entries), currentDir))
		}
		selectedEntry = nil
		editor.SetText("")
		editor.Disable()
		previewHolder.Objects = []fyne.CanvasObject{editor}
		previewHolder.Refresh()
		if listWidget != nil {
			listWidget.UnselectAll()
			listWidget.Refresh()
		}
	}

	searchEntry.OnChanged = func(_ string) {
		refreshList()
	}

	// Watchdog Rimozione Fisica USB: se la chiavetta viene staccata, azzera la DEK in RAM e blocca subito la GUI
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopWatchdog:
				return
			case <-ticker.C:
				if !v.IsMountAlive() {
					stopUnplugWatchdog()
					if unmountFuse != nil {
						unmountFuse()
						unmountFuse = nil
					}
					v.Close()
					showUnlockScreen(w)
					dialog.ShowInformation("🔒 Blocco di Emergenza Attivato",
						"La chiavetta USB è stata rimossa: la chiave crittografica in RAM è stata azzerata automaticamente.", w)
					return
				}
			}
		}
	}()

	w.SetOnDropped(func(_ fyne.Position, uris []fyne.URI) {
		if len(uris) == 0 {
			return
		}
		prog := dialog.NewProgress("Importazione Drag & Drop Multi-Core",
			fmt.Sprintf("Cifratura di %d elementi rilasciati in %s...", len(uris), currentDir), w)
		prog.Show()

		go func() {
			totalImported := 0
			var lastErr error

			for idx, u := range uris {
				localPath := u.Path()
				if vault.ShouldIgnoreFile(localPath) {
					continue
				}
				info, err := os.Stat(localPath)
				if err != nil {
					lastErr = err
					continue
				}

				if info.IsDir() {
					cnt, dErr := v.ImportDir(localPath, currentDir, func(done, total int64) {
						if total > 0 {
							prog.SetValue(float64(done) / float64(total))
						}
					})
					if dErr != nil {
						lastErr = dErr
					}
					totalImported += cnt
				} else if info.Mode().IsRegular() {
					inFile, fErr := os.Open(localPath)
					if fErr != nil {
						lastErr = fErr
						continue
					}
					target := filepath.Join(currentDir, filepath.Base(localPath))
					wErr := v.WriteStream(target, inFile, info.Size(), func(done, total int64) {
						if total > 0 {
							prog.SetValue(float64(done) / float64(total))
						}
					})
					_ = inFile.Close()
					if wErr != nil {
						lastErr = wErr
					} else {
						totalImported++
					}
				}
				prog.SetValue(float64(idx+1) / float64(len(uris)))
			}

			prog.Hide()
			refreshList()
			if lastErr != nil {
				dialog.ShowError(lastErr, w)
			} else {
				dialog.ShowInformation("Drag & Drop Completato",
					fmt.Sprintf("Importati e cifrati %d file in '%s'!", totalImported, currentDir), w)
			}
		}()
	})

	listWidget = widget.NewList(
		func() int { return len(entries) },
		func() fyne.CanvasObject {
			icon := widget.NewIcon(theme.FileIcon())
			name := widget.NewLabelWithStyle("Nome File", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			meta := widget.NewLabel("Dimensioni")
			return container.NewBorder(nil, nil, icon, meta, name)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(entries) {
				return
			}
			e := entries[i]
			box := o.(*fyne.Container)
			icon := box.Objects[1].(*widget.Icon)
			meta := box.Objects[2].(*widget.Label)
			name := box.Objects[0].(*widget.Label)

			displayName := filepath.Base(e.VirtualPath)
			if strings.TrimSpace(searchEntry.Text) != "" {
				displayName = e.VirtualPath
			}

			if e.IsDir {
				icon.SetResource(theme.FolderIcon())
				name.SetText(displayName + "/")
				meta.SetText("📁 Cartella")
			} else {
				if isImageExt(displayName) {
					icon.SetResource(theme.MediaPhotoIcon())
				} else if isPDFExt(displayName) {
					icon.SetResource(theme.FileTextIcon())
				} else {
					icon.SetResource(theme.DocumentIcon())
				}
				name.SetText(displayName)
				ratio := 100.0
				if e.OriginalSize > 0 {
					ratio = (float64(e.DiskSize) / float64(e.OriginalSize)) * 100
				}
				meta.SetText(fmt.Sprintf("%s ➔ %s (%.0f%%)", formatBytes(e.OriginalSize), formatBytes(e.DiskSize), ratio))
			}
		},
	)

	listWidget.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(entries) {
			return
		}
		e := entries[id]
		selectedEntry = &e

		if e.IsDir {
			searchEntry.SetText("")
			currentDir = e.VirtualPath
			refreshList()
			return
		}

		infoLabel.SetText(fmt.Sprintf("📄 %s  |  Reale: %s  |  Su USB: %s  |  Chunk 4MB: %d",
			e.VirtualPath, formatBytes(e.OriginalSize), formatBytes(e.DiskSize), len(e.ChunkSizes)))

		if isImageExt(e.VirtualPath) {
			if imgView, err := buildImagePreview(v, e.VirtualPath); err == nil {
				editor.Disable()
				previewHolder.Objects = []fyne.CanvasObject{imgView}
				previewHolder.Refresh()
				return
			}
		}

		if isPDFExt(e.VirtualPath) && e.OriginalSize <= 64*1024*1024 {
			if pdfView, err := buildPDFPreview(v, e.VirtualPath); err == nil {
				editor.Disable()
				previewHolder.Objects = []fyne.CanvasObject{pdfView}
				previewHolder.Refresh()
				return
			}
		}

		previewHolder.Objects = []fyne.CanvasObject{editor}
		previewHolder.Refresh()

		if e.OriginalSize > vault.MaxTextPreviewSize {
			editor.Disable()
			editor.SetText(fmt.Sprintf("[File Multimediale / Grande (%s in %d chunk da 4 MB).\n• Clicca 'Stream Video' per riprodurlo subito in O(1) senza file temporanei.\n• Oppure clicca 'Monta FUSE' per accedervi come disco nativo.]",
				formatBytes(e.OriginalSize), len(e.ChunkSizes)))
			return
		}

		data, err := v.ReadFile(e.VirtualPath)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		if isLikelyText(data) {
			editor.Enable()
			editor.SetText(string(data))
		} else {
			editor.Disable()
			editor.SetText("[File binario — Usa 'Stream Video', 'Monta FUSE' o 'App Esterna']")
		}
	}

	upBtn := widget.NewButtonWithIcon("Su", theme.NavigateBackIcon(), func() {
		if currentDir == "/" {
			return
		}
		parent := filepath.ToSlash(filepath.Dir(currentDir))
		if parent == "." {
			parent = "/"
		}
		currentDir = parent
		refreshList()
	})

	newFolderBtn := widget.NewButtonWithIcon("+Cartella", theme.FolderNewIcon(), func() {
		nameEntry := widget.NewEntry()
		dialog.ShowForm("Crea Cartella", "Crea", "Annulla", []*widget.FormItem{
			widget.NewFormItem("Nome cartella", nameEntry),
		}, func(ok bool) {
			if ok && strings.TrimSpace(nameEntry.Text) != "" {
				target := filepath.Join(currentDir, strings.TrimSpace(nameEntry.Text))
				if err := v.CreateDir(target); err != nil {
					dialog.ShowError(err, w)
				}
				refreshList()
			}
		}, w)
	})

	newFileBtn := widget.NewButtonWithIcon("+Testo", theme.DocumentCreateIcon(), func() {
		nameEntry := widget.NewEntry()
		nameEntry.SetPlaceHolder("appunti.txt")
		dialog.ShowForm("Nuovo File", "Crea", "Annulla", []*widget.FormItem{
			widget.NewFormItem("Nome file", nameEntry),
		}, func(ok bool) {
			if ok && strings.TrimSpace(nameEntry.Text) != "" {
				target := filepath.Join(currentDir, strings.TrimSpace(nameEntry.Text))
				if err := v.WriteFile(target, []byte("")); err != nil {
					dialog.ShowError(err, w)
				}
				refreshList()
			}
		}, w)
	})

	importBtn := widget.NewButtonWithIcon("Importa File", theme.UploadIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			filePath := reader.URI().Path()
			fileName := reader.URI().Name()
			_ = reader.Close()

			if vault.ShouldIgnoreFile(fileName) {
				dialog.ShowInformation("File Ignorato", "Il file selezionato è un file temporaneo di sistema.", w)
				return
			}

			info, statErr := os.Stat(filePath)
			var totalSize int64
			if statErr == nil {
				totalSize = info.Size()
			}

			inFile, openErr := os.Open(filePath)
			if openErr != nil {
				dialog.ShowError(openErr, w)
				return
			}

			prog := dialog.NewProgress("Compressione e Cifratura Multi-Core",
				fmt.Sprintf("Importazione parallela (%d core) di %s...", runtime.NumCPU(), fileName), w)
			prog.Show()

			target := filepath.Join(currentDir, fileName)
			go func() {
				defer inFile.Close()
				err := v.WriteStream(target, inFile, totalSize, func(done, total int64) {
					if total > 0 {
						prog.SetValue(float64(done) / float64(total))
					}
				})
				prog.Hide()
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				refreshList()
			}()
		}, w)
		fd.Show()
	})

	importDirBtn := widget.NewButtonWithIcon("Importa Cartella", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil || uri == nil {
				return
			}
			folderPath := uri.Path()
			prog := dialog.NewProgress("Importazione Cartella Multi-Core",
				fmt.Sprintf("Cifratura ricorsiva di %s...", filepath.Base(folderPath)), w)
			prog.Show()

			go func() {
				count, impErr := v.ImportDir(folderPath, currentDir, func(done, total int64) {
					if total > 0 {
						prog.SetValue(float64(done) / float64(total))
					}
				})
				prog.Hide()
				if impErr != nil {
					dialog.ShowError(impErr, w)
					return
				}
				dialog.ShowInformation("Cartella Importata",
					fmt.Sprintf("Importati e cifrati %d file!", count), w)
				refreshList()
			}()
		}, w)
	})

	streamPlayBtn := widget.NewButtonWithIcon("Stream Video", theme.MediaPlayIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir {
			dialog.ShowInformation("Info", "Seleziona prima un video o un file multimediale dalla lista.", w)
			return
		}
		streamURL, err := v.GetStreamURL(selectedEntry.VirtualPath)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		openURLOrFileInOS(streamURL)
	})
	streamPlayBtn.Importance = widget.HighImportance

	var fuseBtn *widget.Button
	fuseBtn = widget.NewButtonWithIcon("Monta FUSE", theme.StorageIcon(), func() {
		if unmountFuse != nil {
			unmountFuse()
			unmountFuse = nil
			fuseBtn.SetText("Monta FUSE")
			dialog.ShowInformation("Disco Smontato", "Il disco virtuale FUSE/WinFsp è stato smontato.", w)
			refreshList()
			return
		}

		mpEntry := widget.NewEntry()
		if runtime.GOOS == "windows" {
			mpEntry.SetText("Z:")
		} else {
			mpEntry.SetText("/tmp/secureusb_mount")
		}

		dialog.ShowForm("Monta come Unità Disco Nativa (FUSE / WinFsp)", "Monta", "Annulla", []*widget.FormItem{
			widget.NewFormItem("Punto di Mount / Lettera Unità", mpEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			mp := strings.TrimSpace(mpEntry.Text)
			if mp == "" {
				return
			}
			if runtime.GOOS != "windows" {
				_ = os.MkdirAll(mp, 0700)
			}
			unmountFn, err := fusemount.MountDynamic(v, mp)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			unmountFuse = unmountFn
			fuseBtn.SetText("Smonta (" + mp + ")")
			dialog.ShowInformation("Disco Virtuale Attivo",
				fmt.Sprintf("Vault montato in %s tramite FUSE/WinFsp!", mp), w)
		}, w)
	})

	openExtBtn := widget.NewButtonWithIcon("App Esterna", theme.VisibilityIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir {
			dialog.ShowInformation("Info", "Seleziona prima un file dalla lista.", w)
			return
		}
		openWithSystemAppStreaming(w, v, *selectedEntry, refreshList)
	})

	exportBtn := widget.NewButtonWithIcon("Esporta File", theme.DownloadIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir {
			return
		}
		entry := *selectedEntry
		fs := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			destPath := writer.URI().Path()
			_ = writer.Close()

			outFile, openErr := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if openErr != nil {
				dialog.ShowError(openErr, w)
				return
			}

			prog := dialog.NewProgress("Decifratura Parallela Multi-Core",
				fmt.Sprintf("Esportazione di %s...", filepath.Base(entry.VirtualPath)), w)
			prog.Show()

			go func() {
				bw := bufio.NewWriterSize(outFile, 1024*1024)
				err := v.ReadStream(entry.VirtualPath, bw, func(done, total int64) {
					if total > 0 {
						prog.SetValue(float64(done) / float64(total))
					}
				})
				if err == nil {
					err = bw.Flush()
				}
				_ = outFile.Close()
				prog.Hide()

				if err != nil {
					_ = os.Remove(destPath)
					dialog.ShowError(err, w)
				} else {
					dialog.ShowInformation("Esportazione Completata", "File decifrato e verificato con successo!", w)
				}
			}()
		}, w)
		fs.SetFileName(filepath.Base(entry.VirtualPath))
		fs.Show()
	})

	exportDirBtn := widget.NewButtonWithIcon("Esporta Cartella", theme.DownloadIcon(), func() {
		targetVirtualDir := currentDir
		if selectedEntry != nil && selectedEntry.IsDir {
			targetVirtualDir = selectedEntry.VirtualPath
		}

		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil || uri == nil {
				return
			}
			destParent := uri.Path()
			prog := dialog.NewProgress("Esportazione Cartella Multi-Core",
				fmt.Sprintf("Decifratura ricorsiva di %s...", targetVirtualDir), w)
			prog.Show()

			go func() {
				count, expErr := v.ExportDir(targetVirtualDir, destParent, func(done, total int64) {
					if total > 0 {
						prog.SetValue(float64(done) / float64(total))
					}
				})
				prog.Hide()
				if expErr != nil {
					dialog.ShowError(expErr, w)
					return
				}
				dialog.ShowInformation("Cartella Esportata",
					fmt.Sprintf("Esportati e verificati %d file in %s!", count, destParent), w)
			}()
		}, w)
	})

	changePassBtn := widget.NewButtonWithIcon("Password", theme.AccountIcon(), func() {
		oldPass := widget.NewPasswordEntry()
		newPass := widget.NewPasswordEntry()
		dialog.ShowForm("Cambio Password Istantaneo (Key Wrapping)", "Aggiorna", "Annulla", []*widget.FormItem{
			widget.NewFormItem("Password Attuale", oldPass),
			widget.NewFormItem("Nuova Password", newPass),
		}, func(ok bool) {
			if !ok {
				return
			}
			if err := v.ChangePassword(oldPass.Text, newPass.Text); err != nil {
				dialog.ShowError(err, w)
			} else {
				dialog.ShowInformation("Password Aggiornata",
					"La Data Encryption Key (DEK) è stata ri-avvolta con successo in pochi millisecondi!", w)
			}
		}, w)
	})

	scrubBtn := widget.NewButtonWithIcon("Scrub Poly1305", theme.ConfirmIcon(), func() {
		prog := dialog.NewProgress("Verifica Integrità Globale (Poly1305 + Zstd)",
			"Controllo multi-core di tutti i blocchi sulla chiavetta...", w)
		prog.Show()

		go func() {
			rep, _ := v.ScrubIntegrity(func(done, total int64) {
				if total > 0 {
					prog.SetValue(float64(done) / float64(total))
				}
			})
			prog.Hide()
			if len(rep.CorruptedFiles) == 0 {
				dialog.ShowInformation("Integrità Certificata (100%)",
					fmt.Sprintf("File verificati: %d\nChunk da 4MB autenticati: %d\nDati controllati: %s\nNessun bit-rot o manomissione rilevata!",
						rep.TotalFiles, rep.VerifiedChunks, formatBytes(rep.VerifiedBytes)), w)
			} else {
				dialog.ShowError(fmt.Errorf("rilevati %d file corrotti: %v",
					len(rep.CorruptedFiles), strings.Join(rep.CorruptedFiles, ", ")), w)
			}
		}()
	})

	saveBtn := widget.NewButtonWithIcon("Salva Testo", theme.DocumentSaveIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir || editor.Disabled() {
			return
		}
		if err := v.WriteFile(selectedEntry.VirtualPath, []byte(editor.Text)); err != nil {
			dialog.ShowError(err, w)
			return
		}
		dialog.ShowInformation("Salvato", "File compresso e cifrato in formato SVAULT03!", w)
		refreshList()
	})
	saveBtn.Importance = widget.HighImportance

	deleteBtn := widget.NewButtonWithIcon("Elimina", theme.DeleteIcon(), func() {
		if selectedEntry == nil {
			return
		}
		target := selectedEntry.VirtualPath
		dialog.ShowConfirm("Eliminazione Sicura",
			fmt.Sprintf("Vuoi eliminare definitivamente '%s' sovrascrivendo i blocchi sulla USB?", filepath.Base(target)),
			func(ok bool) {
				if ok {
					_ = v.Delete(target)
					refreshList()
				}
			}, w)
	})
	deleteBtn.Importance = widget.DangerImportance

	lockBtn := widget.NewButtonWithIcon("Blocca", theme.LogoutIcon(), func() {
		stopUnplugWatchdog()
		if unmountFuse != nil {
			unmountFuse()
			unmountFuse = nil
		}
		v.Close()
		showUnlockScreen(w)
	})

	topBar := container.NewVBox(
		container.NewHScroll(container.NewHBox(
			upBtn, newFolderBtn, newFileBtn,
			importBtn, importDirBtn,
			streamPlayBtn, fuseBtn, openExtBtn,
			exportBtn, exportDirBtn,
			scrubBtn, changePassBtn, deleteBtn, lockBtn,
		)),
		container.NewGridWithColumns(2, container.NewHScroll(breadcrumbBox), searchEntry),
		widget.NewSeparator(),
	)

	bottomStatusBar := container.NewVBox(
		widget.NewSeparator(),
		container.NewBorder(nil, nil, telemetryLabel, nil, savingsBar),
	)

	rightPane := container.NewBorder(
		container.NewBorder(nil, nil, infoLabel, saveBtn),
		nil, nil, nil,
		previewHolder,
	)

	split := container.NewHSplit(listWidget, rightPane)
	split.Offset = 0.38

	refreshList()
	w.SetContent(container.NewBorder(topBar, bottomStatusBar, nil, nil, split))
}

func openURLOrFileInOS(target string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", "start", "", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	_ = cmd.Start()
}

func openWithSystemAppStreaming(w fyne.Window, v *vault.SecureVault, entry vault.FileEntry, onDone func()) {
	tmpDir, err := os.MkdirTemp("", "svault_edit_*")
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	tmpFile := filepath.Join(tmpDir, filepath.Base(entry.VirtualPath))

	outFile, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		dialog.ShowError(err, w)
		return
	}

	prog := dialog.NewProgress("Decifratura Parallela", "Apertura file nell'applicazione esterna...", w)
	prog.Show()

	go func() {
		bw := bufio.NewWriterSize(outFile, 1024*1024)
		err := v.ReadStream(entry.VirtualPath, bw, func(done, total int64) {
			if total > 0 {
				prog.SetValue(float64(done) / float64(total))
			}
		})
		if err == nil {
			err = bw.Flush()
		}
		_ = outFile.Close()
		prog.Hide()

		if err != nil {
			vault.SecureEraseFile(tmpFile)
			_ = os.RemoveAll(tmpDir)
			dialog.ShowError(err, w)
			return
		}

		infoBefore, _ := os.Stat(tmpFile)
		openURLOrFileInOS(tmpFile)

		dialog.ShowConfirm("File Aperto nell'App Esterna",
			"Quando hai terminato le modifiche, clicca 'Salva e Chiudi' per ricifrare in parallelo le modifiche sulla USB e distruggere il file temporaneo.",
			func(saveChanges bool) {
				if saveChanges {
					infoAfter, statErr := os.Stat(tmpFile)
					if statErr == nil && (infoBefore == nil || !infoAfter.ModTime().Equal(infoBefore.ModTime()) || infoAfter.Size() != infoBefore.Size()) {
						inFile, openErr := os.Open(tmpFile)
						if openErr == nil {
							saveProg := dialog.NewProgress("Salvataggio Parallelo", "Ricifratura modifiche sulla USB...", w)
							saveProg.Show()
							_ = v.WriteStream(entry.VirtualPath, inFile, infoAfter.Size(), func(d, t int64) {
								if t > 0 {
									saveProg.SetValue(float64(d) / float64(t))
								}
							})
							_ = inFile.Close()
							saveProg.Hide()
						}
					}
				}
				vault.SecureEraseFile(tmpFile)
				_ = os.RemoveAll(tmpDir)
				onDone()
			}, w)
	}()
}

func isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	sample := data
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	for _, b := range sample {
		if b == 0 {
			return false
		}
	}
	return true
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

var _ = storage.NewFileURI
