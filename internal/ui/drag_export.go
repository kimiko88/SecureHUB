package ui

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"secureusb/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// getDesktopDir individua la cartella Desktop dell'utente su Windows, Linux e macOS.
func getDesktopDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	desk := filepath.Join(home, "Desktop")
	if info, err := os.Stat(desk); err == nil && info.IsDir() {
		return desk
	}
	return home
}

// ExportEntryToTargetDir esporta un singolo file o un'intera cartella ricorsiva dentro targetParentDir
// restituendo il percorso finale creato sul filesystem ospite.
func ExportEntryToTargetDir(v *vault.SecureVault, entry vault.FileEntry, targetParentDir string, onProgress vault.ProgressFunc) (string, error) {
	if entry.IsDir {
		_, err := v.ExportDir(entry.VirtualPath, targetParentDir, onProgress)
		folderName := filepath.Base(entry.VirtualPath)
		if entry.VirtualPath == "/" || folderName == "." || folderName == "/" {
			folderName = "Vault_Export"
		}
		return filepath.Join(targetParentDir, folderName), err
	}

	destPath := filepath.Join(targetParentDir, filepath.Base(entry.VirtualPath))
	if len(entry.ChunkRefs) > 0 {
		plain, err := v.ReadDedupFile(entry.VirtualPath)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(destPath, plain, 0600); err != nil {
			return "", err
		}
		return destPath, nil
	}

	outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	bw := bufio.NewWriterSize(outFile, 1024*1024)
	rErr := v.ReadStream(entry.VirtualPath, bw, onProgress)
	if rErr == nil {
		rErr = bw.Flush()
	}
	_ = outFile.Close()
	if rErr != nil {
		_ = os.Remove(destPath)
		return "", rErr
	}
	return destPath, nil
}

// CopyFileObjectToOSClipboard carica un file o una cartella estratta negli Appunti di Sistema
// (CF_HDROP su Windows, NSPasteboard POSIX file su macOS, text/uri-list su Linux)
// così l'utente può premere direttamente Ctrl+V / Cmd+V sul Desktop o in qualsiasi cartella aperta!
func CopyFileObjectToOSClipboard(localPath string) error {
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		absPath = localPath
	}

	switch runtime.GOOS {
	case "windows":
		escaped := strings.ReplaceAll(absPath, "'", "''")
		psCmd := fmt.Sprintf("Set-Clipboard -Path '%s'", escaped)
		return exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).Run()
	case "darwin":
		escaped := strings.ReplaceAll(absPath, "\"", "\\\"")
		script := fmt.Sprintf("set the clipboard to (POSIX file \"%s\")", escaped)
		return exec.Command("osascript", "-e", script).Run()
	default:
		uri := "file://" + filepath.ToSlash(absPath) + "\r\n"
		cmd := exec.Command("xclip", "-selection", "clipboard", "-t", "text/uri-list")
		cmd.Stdin = strings.NewReader(uri)
		if err := cmd.Run(); err != nil {
			wl := exec.Command("wl-copy", "--type", "text/uri-list")
			wl.Stdin = strings.NewReader(uri)
			return wl.Run()
		}
		return nil
	}
}

// RevealInSystemFileManager apre la cartella di destinazione ed evidenzia il file/cartella appena esportato.
func RevealInSystemFileManager(localPath string) {
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		absPath = localPath
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer.exe", "/select,", absPath)
	case "darwin":
		cmd = exec.Command("open", "-R", absPath)
	default:
		cmd = exec.Command("xdg-open", filepath.Dir(absPath))
	}
	_ = cmd.Start()
}

// DraggableFileRow è una riga della lista file che supporta sia il Click (selezione)
// sia il Trascinamento (Outbound Drag & Drop verso il Desktop o fuori dai bordi della finestra).
type DraggableFileRow struct {
	widget.BaseWidget
	IconWidget *widget.Icon
	NameLabel  *widget.Label
	MetaLabel  *widget.Label
	box        *fyne.Container

	Entry          vault.FileEntry
	OnRowTapped    func(vault.FileEntry)
	OnDragStatus   func(msg string)
	OnDropOutside  func(entry vault.FileEntry, endPos fyne.Position)
	accumDelta     fyne.Position
	lastAbsPos     fyne.Position
	isDraggingItem bool
}

func NewDraggableFileRow(
	onTapped func(vault.FileEntry),
	onDragStatus func(string),
	onDropOutside func(vault.FileEntry, fyne.Position),
) *DraggableFileRow {
	r := &DraggableFileRow{
		IconWidget:    widget.NewIcon(theme.FileIcon()),
		NameLabel:     widget.NewLabelWithStyle("Nome", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		MetaLabel:     widget.NewLabel("Meta"),
		OnRowTapped:   onTapped,
		OnDragStatus:  onDragStatus,
		OnDropOutside: onDropOutside,
	}
	r.box = container.NewBorder(nil, nil, r.IconWidget, r.MetaLabel, r.NameLabel)
	r.ExtendBaseWidget(r)
	return r
}

func (r *DraggableFileRow) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(r.box)
}

func (r *DraggableFileRow) Tapped(_ *fyne.PointEvent) {
	if r.OnRowTapped != nil {
		r.OnRowTapped(r.Entry)
	}
}

func (r *DraggableFileRow) Dragged(ev *fyne.DragEvent) {
	r.isDraggingItem = true
	r.accumDelta.X += ev.Dragged.DX
	r.accumDelta.Y += ev.Dragged.DY
	r.lastAbsPos = ev.AbsolutePosition

	if r.OnDragStatus != nil {
		kind := "File"
		if r.Entry.IsDir {
			kind = "Cartella"
		}
		r.OnDragStatus(fmt.Sprintf("📤 Trascinamento %s %q — Rilascia fuori dalla finestra o sulla Dock Desktop in basso per esportare!",
			kind, filepath.Base(r.Entry.VirtualPath)))
	}
}

func (r *DraggableFileRow) DragEnd() {
	if !r.isDraggingItem {
		return
	}
	r.isDraggingItem = false
	dist := r.accumDelta.X*r.accumDelta.X + r.accumDelta.Y*r.accumDelta.Y
	r.accumDelta = fyne.Position{}

	// Se l'utente ha trascinato per almeno 45px, attiva l'esportazione Drag-Out
	if dist > 45*45 && r.OnDropOutside != nil {
		r.OnDropOutside(r.Entry, r.lastAbsPos)
	}
}

// buildOutboundExportDock crea la barra di rilascio ed esportazione rapida (Desktop / Appunti OS / Cartella).
func buildOutboundExportDock(w fyne.Window, v *vault.SecureVault, getSelected func() *vault.FileEntry, setStatus func(string)) fyne.CanvasObject {
	exportToDesktopBtn := widget.NewButtonWithIcon("🖥️ Esporta / Drop su Desktop", theme.HomeIcon(), func() {
		sel := getSelected()
		if sel == nil {
			dialog.ShowInformation("Drag & Export", "Trascina un file/cartella dalla lista verso il bordo esterno della finestra oppure selezionalo e clicca qui.", w)
			return
		}
		triggerDragOutExport(w, v, *sel, getDesktopDir(), true, setStatus)
	})
	exportToDesktopBtn.Importance = widget.HighImportance

	copyOSClipBtn := widget.NewButtonWithIcon("📋 Copia per Ctrl+V in Explorer", theme.ContentCopyIcon(), func() {
		sel := getSelected()
		if sel == nil {
			dialog.ShowInformation("Copia File OS", "Seleziona un file o una cartella da copiare negli appunti di sistema (poi premi Ctrl+V sul Desktop o in qualsiasi cartella).", w)
			return
		}
		stageDir, err := os.MkdirTemp("", "secureusb_clip_*")
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		var exportedPath string
		err = runWithBusySpinner(w, "Preparazione Oggetto File per Ctrl+V...",
			fmt.Sprintf("Decifratura di %s negli appunti di sistema...", filepath.Base(sel.VirtualPath)), func() error {
				var expErr error
				exportedPath, expErr = ExportEntryToTargetDir(v, *sel, stageDir, nil)
				if expErr != nil {
					return expErr
				}
				return CopyFileObjectToOSClipboard(exportedPath)
			})
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		setStatus(fmt.Sprintf("📋 %q copiato negli appunti di sistema! Vai sul Desktop o in una cartella e premi Ctrl+V.", filepath.Base(exportedPath)))
	})

	return container.NewHBox(exportToDesktopBtn, copyOSClipBtn)
}

func triggerDragOutExport(w fyne.Window, v *vault.SecureVault, entry vault.FileEntry, targetDir string, copyToClip bool, setStatus func(string)) {
	var outPath string
	err := runWithBusySpinner(w, "Esportazione Drag & Drop in Corso...",
		fmt.Sprintf("Decifratura multi-core di %s verso %s...", filepath.Base(entry.VirtualPath), targetDir), func() error {
			var expErr error
			outPath, expErr = ExportEntryToTargetDir(v, entry, targetDir, nil)
			if expErr == nil && copyToClip {
				_ = CopyFileObjectToOSClipboard(outPath)
			}
			return expErr
		})
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	setStatus(fmt.Sprintf("✅ Esportato con Drag-Out in %s (e copiato negli appunti per Ctrl+V)!", outPath))
	RevealInSystemFileManager(outPath)
}
