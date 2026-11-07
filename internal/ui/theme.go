package ui

import (
	"image/color"
	"math"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// SecureCyberTheme definisce un tema scuro ad alto contrasto pensato per strumenti crittografici
type SecureCyberTheme struct {
	fyne.Theme
}

func NewSecureCyberTheme() fyne.Theme {
	return &SecureCyberTheme{Theme: theme.DefaultTheme()}
}

func (t *SecureCyberTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 15, G: 23, B: 42, A: 255} // Slate 900 (#0F172A)
	case theme.ColorNameButton:
		return color.NRGBA{R: 30, G: 41, B: 59, A: 255} // Slate 800 (#1E293B)
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 22, G: 30, B: 46, A: 255}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 23, G: 34, B: 53, A: 255}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 16, G: 185, B: 129, A: 255} // Emerald 500 (#10B981)
	case theme.ColorNameFocus:
		return color.NRGBA{R: 6, G: 182, B: 212, A: 140} // Cyan Focus
	case theme.ColorNameSelection:
		return color.NRGBA{R: 16, G: 185, B: 129, A: 75}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 241, G: 245, B: 249, A: 255} // Slate 100
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 148, G: 163, B: 184, A: 255} // Slate 400
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 51, G: 65, B: 85, A: 255}
	default:
		return t.Theme.Color(name, theme.VariantDark)
	}
}

func (t *SecureCyberTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInputRadius:
		return 6
	case theme.SizeNameSelectionRadius:
		return 5
	default:
		return t.Theme.Size(name)
	}
}

// estimatePasswordEntropyBits calcola i bit di entropia della password per la barra di sicurezza
func estimatePasswordEntropyBits(pw string) float64 {
	if len(pw) == 0 {
		return 0
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	pool := 0.0
	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasSymbol {
		pool += 32
	}
	if pool == 0 {
		return 0
	}
	return float64(len(pw)) * math.Log2(pool)
}
