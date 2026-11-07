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
	w := a.NewWindow(fmt.Sprintf("SecureUSB Explorer — SVAULT03 (%d Core) + FUSE/WinFsp + PDF/Image Viewer", runtime.NumCPU()))
	w.Resize(fyne.NewSize(1180, 720))

	showUnlockScreen(w)
	w.ShowAndRun()
}

func showUnlockScreen(w fyne.Window) {
	usbPathEntry := widget.NewEntry()
	usbPathEntry.SetPlaceHolder("Percorso della chiavetta montata (es. E:\\, /Volumes/SECURE_USB, /media/usb)")

	browseBtn := widget.NewButtonWithIcon("Sfoglia Cartella USB", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				usbPathEntry.SetText(uri.Path())
			}
		}, w)
	})

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Password crittografica (Argon2id)")

	openBtn := widget.NewButtonWithIcon("Sblocca ed Esplora", theme.LoginIcon(), func() {
		path := strings.TrimSpace(usbPathEntry.Text)
		pass := passEntry.Text
		if path == "" || pass == "" {
			dialog.ShowError(errors.New("inserire sia il percorso della USB che la password"), w)
			return
		}
		v, err := vault.InitOrOpenVault(path, pass, false)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		showExplorerScreen(w, v)
	})
	openBtn.Importance = widget.HighImportance

	initBtn := widget.NewButtonWithIcon("Inizializza Nuovo Vault (SVAULT03)", theme.ContentAddIcon(), func() {
		path := strings.TrimSpace(usbPathEntry.Text)
		pass := passEntry.Text
		if path == "" || len(pass) < 6 {
			dialog.ShowError(errors.New("seleziona il percorso USB e usa una password di almeno 6 caratteri"), w)
			return
		}
		dialog.ShowConfirm("Conferma Inizializzazione",
			"Questo creerà un nuovo Vault SVAULT03 sulla chiavetta. Procedere?",
			func(ok bool) {
				if !ok {
					return
				}
				v, err := vault.InitOrOpenVault(path, pass, true)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				showExplorerScreen(w, v)
			}, w)
	})

	devEntry := widget.NewEntry()
	devEntry.SetPlaceHolder("Dispositivo grezzo (es. E: su Windows, /dev/sdb1 su Linux, /dev/disk2 su Mac)")
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
					dialog.ShowInformation("Formattazione Completata",
						"Chiavetta formattata in exFAT! Ora seleziona la cartella montata e clicca 'Inizializza Nuovo Vault'.", w)
				}
			}, w)
	})

	card := container.NewVBox(
		widget.NewLabelWithStyle("Sblocco e Gestione Chiavetta Cifrata (Multi-Core + FUSE/WinFsp + Viewer Integrato)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, browseBtn, usbPathEntry),
		passEntry,
		container.NewGridWithColumns(2, openBtn, initBtn),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Utilità Formattazione Fisica (exFAT Cross-Platform)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		devEntry,
		formatBtn,
	)

	w.SetContent(container.NewPadded(card))
}

func showExplorerScreen(w fyne.Window, v *vault.SecureVault) {
	currentDir := "/"
	var entries []vault.FileEntry
	var selectedEntry *vault.FileEntry
	var unmountFuse func()

	pathLabel := widget.NewLabelWithStyle("Percorso: /", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	infoLabel := widget.NewLabel("Seleziona un file per visualizzarlo (Testo, Immagini PNG/JPG/GIF, PDF o Video in Streaming).")

	editor := widget.NewMultiLineEntry()
	editor.SetPlaceHolder("Editor integrato per file di testo (fino a 16 MB). Seleziona un'immagine o un PDF per aprire automaticamente il visualizzatore integrato.")
	editor.Disable()

	previewHolder := container.NewMax(editor)

	var listWidget *widget.List

	refreshList := func() {
		entries = v.ListDir(currentDir)
		selectedEntry = nil
		editor.SetText("")
		editor.Disable()
		previewHolder.Objects = []fyne.CanvasObject{editor}
		previewHolder.Refresh()
		pathLabel.SetText("Percorso: " + currentDir)
		infoLabel.SetText(fmt.Sprintf("%d elementi nella cartella corrente", len(entries)))
		if listWidget != nil {
			listWidget.UnselectAll()
			listWidget.Refresh()
		}
	}

	listWidget = widget.NewList(
		func() int { return len(entries) },
		func() fyne.CanvasObject {
			icon := widget.NewIcon(theme.FileIcon())
			name := widget.NewLabel("Nome File")
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

			baseName := filepath.Base(e.VirtualPath)
			if e.IsDir {
				icon.SetResource(theme.FolderIcon())
				name.SetText(baseName + "/")
				meta.SetText("Cartella")
			} else {
				if isImageExt(baseName) {
					icon.SetResource(theme.MediaPhotoIcon())
				} else {
					icon.SetResource(theme.DocumentIcon())
				}
				name.SetText(baseName)
				ratio := 100.0
				if e.OriginalSize > 0 {
					ratio = (float64(e.DiskSize) / float64(e.OriginalSize)) * 100
				}
				meta.SetText(fmt.Sprintf("%s (%d chunk | %.0f%%)", formatBytes(e.OriginalSize), len(e.ChunkSizes), ratio))
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
			currentDir = e.VirtualPath
			refreshList()
			return
		}

		infoLabel.SetText(fmt.Sprintf("File: %s | Reale: %s | Su disco: %s | Chunk da 4MB: %d",
			filepath.Base(e.VirtualPath), formatBytes(e.OriginalSize), formatBytes(e.DiskSize), len(e.ChunkSizes)))

		// 1. Visualizzatore Integrato per Immagini (PNG/JPG/GIF) in RAM
		if isImageExt(e.VirtualPath) {
			if imgView, err := buildImagePreview(v, e.VirtualPath); err == nil {
				editor.Disable()
				previewHolder.Objects = []fyne.CanvasObject{imgView}
				previewHolder.Refresh()
				return
			}
		}

		// 2. Visualizzatore Integrato per PDF in RAM
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
			editor.SetText(fmt.Sprintf("[File di grandi dimensioni (%s in %d chunk da 4 MB).\n• Clicca 'Stream Video al Volo' per riprodurlo subito con Random-Access O(1).\n• Oppure monta il Vault come disco FUSE/WinFsp.]",
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
			editor.SetText("[File binario — Usa 'Stream Video al Volo', 'Monta Disco FUSE' o 'Modifica con App Esterna']")
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

	newFolderBtn := widget.NewButtonWithIcon("Nuova Cartella", theme.FolderNewIcon(), func() {
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

	newFileBtn := widget.NewButtonWithIcon("Nuovo Testo", theme.DocumentCreateIcon(), func() {
		nameEntry := widget.NewEntry()
		nameEntry.SetPlaceHolder("note.txt")
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

	importBtn := widget.NewButtonWithIcon("Importa", theme.UploadIcon(), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			filePath := reader.URI().Path()
			fileName := reader.URI().Name()
			_ = reader.Close()

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
					fmt.Sprintf("Importati e cifrati %d file con successo!", count), w)
				refreshList()
			}()
		}, w)
	})

	streamPlayBtn := widget.NewButtonWithIcon("Stream Video al Volo", theme.MediaPlayIcon(), func() {
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

	// Pulsante Montaggio Disco Virtuale Nativo (FUSE / WinFsp)
	var fuseBtn *widget.Button
	fuseBtn = widget.NewButtonWithIcon("Monta Disco FUSE/WinFsp", theme.StorageIcon(), func() {
		if unmountFuse != nil {
			unmountFuse()
			unmountFuse = nil
			fuseBtn.SetText("Monta Disco FUSE/WinFsp")
			dialog.ShowInformation("Disco Smontato", "Il disco virtuale FUSE/WinFsp è stato smontato correttamente.", w)
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
			fuseBtn.SetText("Smonta Disco (" + mp + ")")
			dialog.ShowInformation("Disco Virtuale Attivo",
				fmt.Sprintf("Vault montato in %s tramite FUSE/WinFsp!\nOra puoi aprirlo direttamente nel File Explorer di sistema.", mp), w)
		}, w)
	})

	openExtBtn := widget.NewButtonWithIcon("App Esterna", theme.VisibilityIcon(), func() {
		if selectedEntry == nil || selectedEntry.IsDir {
			dialog.ShowInformation("Info", "Seleziona prima un file dalla lista.", w)
			return
		}
		openWithSystemAppStreaming(w, v, *selectedEntry, refreshList)
	})

	exportBtn := widget.NewButtonWithIcon("Esporta", theme.DownloadIcon(), func() {
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
		// Se è selezionata una cartella esporta quella, altrimenti esporta la directory corrente
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

	lockBtn := widget.NewButtonWithIcon("Blocca USB", theme.LogoutIcon(), func() {
		if unmountFuse != nil {
			unmountFuse()
			unmountFuse = nil
		}
		v.Close()
		showUnlockScreen(w)
	})

	topBar := container.NewVBox(
		container.NewHBox(upBtn, newFolderBtn, newFileBtn, importBtn, importDirBtn, streamPlayBtn, fuseBtn, openExtBtn, exportBtn, exportDirBtn, deleteBtn, lockBtn),
		container.NewBorder(nil, nil, pathLabel, nil, widget.NewLabel("")),
		widget.NewSeparator(),
	)

	rightPane := container.NewBorder(
		container.NewBorder(nil, nil, infoLabel, saveBtn),
		nil, nil, nil,
		previewHolder,
	)

	split := container.NewHSplit(listWidget, rightPane)
	split.Offset = 0.38

	refreshList()
	w.SetContent(container.NewBorder(topBar, nil, nil, nil, split))
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
