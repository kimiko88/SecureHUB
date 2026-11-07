package ui

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"secureusb/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func isImageExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif"
}

func isPDFExt(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".pdf"
}

// buildImagePreview decodifica l'immagine direttamente dal VaultReadSeeker in RAM (zero file temporanei)
func buildImagePreview(v *vault.SecureVault, virtualPath string) (fyne.CanvasObject, error) {
	seeker, err := v.OpenReadSeeker(virtualPath)
	if err != nil {
		return nil, err
	}
	defer seeker.Close()

	img, format, err := image.Decode(seeker)
	if err != nil {
		return nil, fmt.Errorf("impossibile decodificare immagine: %w", err)
	}

	cImg := canvas.NewImageFromImage(img)
	cImg.FillMode = canvas.ImageFillContain
	cImg.SetMinSize(fyne.NewSize(480, 380))

	bounds := img.Bounds()
	header := widget.NewLabelWithStyle(
		fmt.Sprintf("Visualizzatore Immagini Integrato — Formato: %s | Risoluzione: %dx%d px (Zero-Temp in RAM)",
			strings.ToUpper(format), bounds.Dx(), bounds.Dy()),
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true},
	)

	return container.NewBorder(header, nil, nil, nil, container.NewPadded(cImg)), nil
}

type pdfPageData struct {
	PageNumber int
	Text       string
	Images     []image.Image
}

// buildPDFPreview legge il documento PDF direttamente dal VaultReadSeeker in RAM,
// decomprimendo gli stream /FlateDecode per il testo ed estraendo eventuali immagini /DCTDecode.
func buildPDFPreview(v *vault.SecureVault, virtualPath string) (fyne.CanvasObject, error) {
	seeker, err := v.OpenReadSeeker(virtualPath)
	if err != nil {
		return nil, err
	}
	defer seeker.Close()

	rawPDF, err := io.ReadAll(seeker)
	if err != nil {
		return nil, err
	}

	pages := parsePDFStreamsInMemory(rawPDF)
	if len(pages) == 0 {
		pages = []pdfPageData{{
			PageNumber: 1,
			Text:       "[Documento PDF caricato in RAM — Nessun flusso di testo standard rilevato o font convertiti in tracciati vettoriali.]",
		}}
	}

	currentIdx := 0
	pageTitle := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	textArea := widget.NewMultiLineEntry()
	textArea.Wrapping = fyne.TextWrapWord

	imgBox := container.NewHBox()
	imgScroll := container.NewHScroll(imgBox)
	imgScroll.Hide()

	updatePage := func() {
		p := pages[currentIdx]
		pageTitle.SetText(fmt.Sprintf("Visualizzatore PDF Integrato — Pagina %d di %d (Decodifica in RAM)", p.PageNumber, len(pages)))
		textArea.SetText(p.Text)

		imgBox.Objects = nil
		if len(p.Images) > 0 {
			for _, im := range p.Images {
				ci := canvas.NewImageFromImage(im)
				ci.FillMode = canvas.ImageFillContain
				ci.SetMinSize(fyne.NewSize(260, 200))
				imgBox.Add(ci)
			}
			imgScroll.Show()
		} else {
			imgScroll.Hide()
		}
		imgBox.Refresh()
	}

	prevBtn := widget.NewButtonWithIcon("Pagina Precedente", theme.NavigateBackIcon(), func() {
		if currentIdx > 0 {
			currentIdx--
			updatePage()
		}
	})
	nextBtn := widget.NewButtonWithIcon("Pagina Successiva", theme.NavigateNextIcon(), func() {
		if currentIdx < len(pages)-1 {
			currentIdx++
			updatePage()
		}
	})

	navBar := container.NewBorder(nil, nil, prevBtn, nextBtn, pageTitle)
	updatePage()

	return container.NewBorder(navBar, imgScroll, nil, nil, textArea), nil
}

var (
	rePDFStream  = regexp.MustCompile(`(?s)<<(.*?)>>\s*stream\r?\n(.*?)\r?\nendstream`)
	reTextParens = regexp.MustCompile(`\(([^()\\]*(?:\\.[^()\\]*)*)\)`)
)

func parsePDFStreamsInMemory(raw []byte) []pdfPageData {
	matches := rePDFStream.FindAllSubmatch(raw, -1)
	var pages []pdfPageData
	var currentText strings.Builder
	var currentImgs []image.Image
	pageCounter := 1

	for _, m := range matches {
		dict := string(m[1])
		streamBytes := m[2]

		// Se lo stream è un'immagine JPEG incorporata (/DCTDecode), la decodifica in RAM
		if strings.Contains(dict, "/DCTDecode") {
			if img, _, err := image.Decode(bytes.NewReader(streamBytes)); err == nil {
				currentImgs = append(currentImgs, img)
			}
			continue
		}

		data := streamBytes
		if strings.Contains(dict, "/FlateDecode") {
			zr, err := zlib.NewReader(bytes.NewReader(streamBytes))
			if err == nil {
				if decomp, err := io.ReadAll(zr); err == nil {
					data = decomp
				}
				_ = zr.Close()
			}
		}

		strData := string(data)
		if strings.Contains(strData, "BT") && strings.Contains(strData, "ET") {
			tokens := reTextParens.FindAllStringSubmatch(strData, -1)
			for _, tok := range tokens {
				cleaned := strings.ReplaceAll(tok[1], "\\(", "(")
				cleaned = strings.ReplaceAll(cleaned, "\\)", ")")
				cleaned = strings.ReplaceAll(cleaned, "\\n", "\n")
				currentText.WriteString(cleaned)
				currentText.WriteString(" ")
			}
			currentText.WriteString("\n")

			if currentText.Len() > 1200 {
				pages = append(pages, pdfPageData{
					PageNumber: pageCounter,
					Text:       strings.TrimSpace(currentText.String()),
					Images:     currentImgs,
				})
				pageCounter++
				currentText.Reset()
				currentImgs = nil
			}
		}
	}

	if currentText.Len() > 0 || len(currentImgs) > 0 {
		txt := strings.TrimSpace(currentText.String())
		if txt == "" {
			txt = fmt.Sprintf("[Pagina %d contenente %d immagini incorporate]", pageCounter, len(currentImgs))
		}
		pages = append(pages, pdfPageData{
			PageNumber: pageCounter,
			Text:       txt,
			Images:     currentImgs,
		})
	}
	return pages
}
