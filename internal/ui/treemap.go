package ui

import (
	"fmt"
	"image/color"
	"path/filepath"
	"strings"

	"secureusb/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

type treemapNode struct {
	entry vault.FileEntry
	x, y  float32
	w, h  float32
}

// Categorizzazione cromatica per estensione file
func classifyFileColor(path string) (string, color.NRGBA) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".mp4", ".mkv", ".mov", ".avi", ".webm", ".mp3", ".flac", ".wav":
		return "Media/Video", color.NRGBA{R: 139, G: 92, B: 246, A: 235} // Violet (#8B5CF6)
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg":
		return "Immagine", color.NRGBA{R: 16, G: 185, B: 129, A: 235} // Emerald (#10B981)
	case ".pdf", ".doc", ".docx", ".txt", ".md", ".rtf", ".odt":
		return "Documento", color.NRGBA{R: 244, G: 63, B: 94, A: 235} // Rose (#F43F5E)
	case ".go", ".rs", ".py", ".js", ".ts", ".c", ".cpp", ".h", ".json", ".sql", ".toml", ".yaml":
		return "Codice/Dati", color.NRGBA{R: 6, G: 182, B: 212, A: 235} // Cyan (#06B6D4)
	case ".zip", ".tar", ".gz", ".zst", ".7z", ".rar", ".iso", ".img", ".dmg":
		return "Archivio/ISO", color.NRGBA{R: 245, G: 158, B: 11, A: 235} // Amber (#F59E0B)
	default:
		return "Binario", color.NRGBA{R: 99, G: 102, B: 241, A: 235} // Indigo (#6366F1)
	}
}

// computeTreemapBSP suddivide ricorsivamente il rettangolo (x, y, w, h) in modo proporzionale
// ai pesi dei file usando Binary Space Partitioning bilanciato.
func computeTreemapBSP(files []vault.FileEntry, x, y, w, h float32, out *[]treemapNode) {
	if len(files) == 0 || w <= 2 || h <= 2 {
		return
	}
	if len(files) == 1 {
		*out = append(*out, treemapNode{
			entry: files[0],
			x:     x,
			y:     y,
			w:     w,
			h:     h,
		})
		return
	}

	var total int64
	for _, f := range files {
		weight := f.OriginalSize
		if weight <= 0 {
			weight = 1024
		}
		total += weight
	}

	half := total / 2
	var accum int64
	splitIdx := 1
	for i, f := range files {
		weight := f.OriginalSize
		if weight <= 0 {
			weight = 1024
		}
		accum += weight
		if accum >= half {
			splitIdx = i + 1
			break
		}
	}
	if splitIdx >= len(files) {
		splitIdx = len(files) - 1
	}

	var leftWeight int64
	for _, f := range files[:splitIdx] {
		weight := f.OriginalSize
		if weight <= 0 {
			weight = 1024
		}
		leftWeight += weight
	}

	ratio := float32(leftWeight) / float32(total)
	if ratio < 0.08 {
		ratio = 0.08
	} else if ratio > 0.92 {
		ratio = 0.92
	}

	if w >= h {
		w1 := w * ratio
		computeTreemapBSP(files[:splitIdx], x, y, w1, h, out)
		computeTreemapBSP(files[splitIdx:], x+w1, y, w-w1, h, out)
	} else {
		h1 := h * ratio
		computeTreemapBSP(files[:splitIdx], x, y, w, h1, out)
		computeTreemapBSP(files[splitIdx:], x, y+h1, w, h-h1, out)
	}
}

// TreemapCanvas è un widget Fyne interattivo che supporta Hover e Click sui blocchi.
type TreemapCanvas struct {
	widget.BaseWidget
	files     []vault.FileEntry
	nodes     []treemapNode
	hoverIdx  int
	onHover   func(info string)
	onClicked func(entry vault.FileEntry)
}

func NewTreemapCanvas(files []vault.FileEntry, onHover func(string), onClicked func(vault.FileEntry)) *TreemapCanvas {
	tc := &TreemapCanvas{
		files:     files,
		hoverIdx:  -1,
		onHover:   onHover,
		onClicked: onClicked,
	}
	tc.ExtendBaseWidget(tc)
	return tc
}

func (tc *TreemapCanvas) Tapped(ev *fyne.PointEvent) {
	pos := ev.Position
	for _, n := range tc.nodes {
		if pos.X >= n.x && pos.X <= n.x+n.w && pos.Y >= n.y && pos.Y <= n.y+n.h {
			if tc.onClicked != nil {
				tc.onClicked(n.entry)
			}
			return
		}
	}
}

func (tc *TreemapCanvas) MouseIn(ev *desktop.MouseEvent) {
	tc.MouseMoved(ev)
}

func (tc *TreemapCanvas) MouseMoved(ev *desktop.MouseEvent) {
	pos := ev.Position
	found := -1
	for i, n := range tc.nodes {
		if pos.X >= n.x && pos.X <= n.x+n.w && pos.Y >= n.y && pos.Y <= n.y+n.h {
			found = i
			break
		}
	}
	if found != tc.hoverIdx {
		tc.hoverIdx = found
		if found >= 0 && tc.onHover != nil {
			e := tc.nodes[found].entry
			cat, _ := classifyFileColor(e.VirtualPath)
			ratio := 100.0
			if e.OriginalSize > 0 {
				ratio = (float64(e.DiskSize) / float64(e.OriginalSize)) * 100
			}
			tc.onHover(fmt.Sprintf("🗺️ [%s] %s  |  Originale: %s  ➔  Su USB: %s (%.0f%%)  |  Clicca per aprire",
				cat, e.VirtualPath, formatBytes(e.OriginalSize), formatBytes(e.DiskSize), ratio))
		}
		tc.Refresh()
	}
}

func (tc *TreemapCanvas) MouseOut() {
	if tc.hoverIdx != -1 {
		tc.hoverIdx = -1
		tc.Refresh()
	}
}

func (tc *TreemapCanvas) CreateRenderer() fyne.WidgetRenderer {
	return &treemapRenderer{tc: tc}
}

type treemapRenderer struct {
	tc      *TreemapCanvas
	objects []fyne.CanvasObject
}

func (r *treemapRenderer) Layout(size fyne.Size) {
	r.tc.nodes = r.tc.nodes[:0]
	r.objects = r.objects[:0]

	if len(r.tc.files) == 0 || size.Width <= 10 || size.Height <= 10 {
		msg := canvas.NewText("Nessun file presente in questo percorso per generare la Treemap.", color.NRGBA{R: 148, G: 163, B: 184, A: 255})
		msg.TextSize = 14
		msg.Move(fyne.NewPos(20, 20))
		r.objects = append(r.objects, msg)
		return
	}

	computeTreemapBSP(r.tc.files, 0, 0, size.Width, size.Height, &r.tc.nodes)

	const pad = float32(2.0)
	for i, n := range r.tc.nodes {
		_, baseCol := classifyFileColor(n.entry.VirtualPath)
		rect := canvas.NewRectangle(baseCol)
		rect.CornerRadius = 5
		rect.StrokeColor = color.NRGBA{R: 15, G: 23, B: 42, A: 255}
		rect.StrokeWidth = 2

		if i == r.tc.hoverIdx {
			rect.StrokeColor = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
			rect.StrokeWidth = 3
		}

		rx := n.x + pad
		ry := n.y + pad
		rw := n.w - pad*2
		rh := n.h - pad*2
		if rw < 1 {
			rw = 1
		}
		if rh < 1 {
			rh = 1
		}
		rect.Move(fyne.NewPos(rx, ry))
		rect.Resize(fyne.NewSize(rw, rh))
		r.objects = append(r.objects, rect)

		// Disegna etichetta nome file e dimensione se il blocco è abbastanza capiente
		if rw > 54 && rh > 24 {
			name := filepath.Base(n.entry.VirtualPath)
			maxChars := int(rw / 7.5)
			if maxChars > 3 && len(name) > maxChars {
				name = name[:maxChars-2] + ".."
			}
			lbl := canvas.NewText(name, color.White)
			lbl.TextStyle = fyne.TextStyle{Bold: true}
			lbl.TextSize = 12
			lbl.Move(fyne.NewPos(rx+6, ry+4))
			r.objects = append(r.objects, lbl)

			if rh > 42 {
				szLbl := canvas.NewText(formatBytes(n.entry.OriginalSize), color.NRGBA{R: 226, G: 232, B: 240, A: 230})
				szLbl.TextSize = 10
				szLbl.Move(fyne.NewPos(rx+6, ry+21))
				r.objects = append(r.objects, szLbl)
			}
		}
	}
}

func (r *treemapRenderer) MinSize() fyne.Size {
	return fyne.NewSize(360, 280)
}

func (r *treemapRenderer) Refresh() {
	r.Layout(r.tc.Size())
	canvas.Refresh(r.tc)
}

func (r *treemapRenderer) Objects() []fyne.CanvasObject {
	return r.objects
}

func (r *treemapRenderer) Destroy() {}

// buildTreemapView costruisce il pannello Treemap completo di legenda colori e barra interattiva.
func buildTreemapView(
	v *vault.SecureVault,
	scopeDir string,
	onHover func(string),
	onSelectFile func(vault.FileEntry),
) fyne.CanvasObject {
	files := v.AllFiles(scopeDir)

	var totalOrig, totalDisk int64
	for _, f := range files {
		totalOrig += f.OriginalSize
		totalDisk += f.DiskSize
	}

	title := widget.NewLabelWithStyle(
		fmt.Sprintf("🗺️ Mappa Spazio Disco (Treemap): %s  —  %d file (%s reali ➔ %s su USB)",
			scopeDir, len(files), formatBytes(totalOrig), formatBytes(totalDisk)),
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true},
	)

	legend := widget.NewLabel("🟣 Media/Video   🟢 Immagini   🔴 PDF/Documenti   🔵 Codice/Dati   🟠 Archivi/ISO   🟣 Binari   (Clicca un blocco per aprirlo)")

	tCanvas := NewTreemapCanvas(files, onHover, onSelectFile)
	header := container.NewVBox(title, legend, widget.NewSeparator())

	return container.NewBorder(header, nil, nil, nil, container.NewPadded(tCanvas))
}
