package usb

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

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
