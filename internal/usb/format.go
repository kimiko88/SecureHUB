package usb

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// DriveInfo descrive un'unità USB o volume esterno rilevato sul sistema
type DriveInfo struct {
	MountPath string // es. "E:\\", "/media/user/USB", "/Volumes/SECURE_USB"
	Label     string // Nome leggibile per il menu a tendina
	HasVault  bool   // true se contiene già .secure_vault/index.meta
}

// DetectUSBDrives rileva automaticamente le chiavette USB e i volumi esterni montati
// su Windows, Linux e macOS, mettendo in cima quelli che contengono già un Vault SVAULT03.
func DetectUSBDrives() []DriveInfo {
	var candidates []string

	switch runtime.GOOS {
	case "windows":
		// Scansiona le lettere di unità da D: a Z: (escludendo C: di sistema)
		for c := 'D'; c <= 'Z'; c++ {
			drive := fmt.Sprintf("%c:\\", c)
			if info, err := os.Stat(drive); err == nil && info.IsDir() {
				candidates = append(candidates, drive)
			}
		}
	case "darwin":
		entries, err := os.ReadDir("/Volumes")
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if name == "Macintosh HD" || name == "Macintosh HD - Data" || strings.HasPrefix(name, ".") {
					continue
				}
				full := filepath.Join("/Volumes", name)
				// Ignora il symlink che punta a "/"
				if target, err := os.Readlink(full); err == nil && target == "/" {
					continue
				}
				candidates = append(candidates, full)
			}
		}
	default: // Linux / BSD
		candidates = append(candidates, scanLinuxMounts()...)
	}

	seen := make(map[string]bool)
	var drives []DriveInfo

	for _, path := range candidates {
		clean := filepath.Clean(path)
		if seen[clean] {
			continue
		}
		seen[clean] = true

		indexMeta := filepath.Join(clean, ".secure_vault", "index.meta")
		hasVault := false
		if st, err := os.Stat(indexMeta); err == nil && !st.IsDir() {
			hasVault = true
		}

		var label string
		if hasVault {
			label = fmt.Sprintf("🔐 %s  [Vault SVAULT03 Rilevato]", clean)
		} else {
			label = fmt.Sprintf("💾 %s  [Unità Esterna / USB]", clean)
		}

		drives = append(drives, DriveInfo{
			MountPath: clean,
			Label:     label,
			HasVault:  hasVault,
		})
	}

	// Ordina mettendo sempre in cima le chiavette che contengono già un Vault SVAULT03
	sort.Slice(drives, func(i, j int) bool {
		if drives[i].HasVault != drives[j].HasVault {
			return drives[i].HasVault
		}
		return drives[i].MountPath < drives[j].MountPath
	})

	return drives
}

func scanLinuxMounts() []string {
	var paths []string

	// 1. Legge /proc/mounts per volumi montati sotto /media, /run/media o /mnt
	if f, err := os.Open("/proc/mounts"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 3 {
				continue
			}
			mp := strings.ReplaceAll(fields[1], "\\040", " ")
			if strings.HasPrefix(mp, "/media/") ||
				strings.HasPrefix(mp, "/run/media/") ||
				strings.HasPrefix(mp, "/mnt/") {
				if info, err := os.Stat(mp); err == nil && info.IsDir() {
					paths = append(paths, mp)
				}
			}
		}
	}

	// 2. Fallback: controlla le sottocartelle di /media e /run/media
	for _, root := range []string{"/media", "/run/media", "/mnt"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			sub := filepath.Join(root, e.Name())
			if e.IsDir() {
				paths = append(paths, sub)
				if children, err := os.ReadDir(sub); err == nil {
					for _, ch := range children {
						if ch.IsDir() {
							paths = append(paths, filepath.Join(sub, ch.Name()))
						}
					}
				}
			}
		}
	}
	return paths
}

// FormatPhysicalUSB formatta fisicamente la chiavetta in exFAT su Windows, Linux e macOS.
func FormatPhysicalUSB(devicePath, label string) error {
	devicePath = strings.TrimSpace(devicePath)
	if devicePath == "" {
		return errors.New("specificare il percorso del dispositivo (es. E:, /dev/sdb1, /dev/disk2)")
	}
	if label == "" {
		label = "SECURE_USB"
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", "format", devicePath, "/FS:exFAT", "/V:"+label, "/Q", "/Y")
	case "linux":
		cmd = exec.Command("mkfs.exfat", "-n", label, devicePath)
	case "darwin":
		cmd = exec.Command("diskutil", "eraseDisk", "ExFAT", label, devicePath)
	default:
		return fmt.Errorf("sistema operativo non supportato: %s", runtime.GOOS)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("errore formattazione (%v): %s", err, string(out))
	}
	return nil
}
