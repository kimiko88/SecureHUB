use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct UsbDriveInfo {
    pub mount_path: String,
    pub label: String,
    pub has_vault: bool,
}

/// Rileva automaticamente le chiavette USB e le unità esterne montate su Windows, Linux e macOS.
pub fn detect_usb_drives() -> Vec<UsbDriveInfo> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if cfg!(target_os = "windows") {
        for letter in b'D'..=b'Z' {
            let drive = format!("{}:\\", letter as char);
            let p = PathBuf::from(&drive);
            if p.is_dir() {
                candidates.push(p);
            }
        }
    } else if cfg!(target_os = "macos") {
        if let Ok(entries) = fs::read_dir("/Volumes") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name == "Macintosh HD" || name == "Macintosh HD - Data" || name.starts_with('.') {
                    continue;
                }
                let full = e.path();
                if let Ok(target) = fs::read_link(&full) {
                    if target == Path::new("/") {
                        continue;
                    }
                }
                candidates.push(full);
            }
        }
    } else {
        // Linux: legge /proc/mounts + scansiona /media, /run/media, /mnt
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let mp = parts[1].replace("\\040", " ");
                    if mp.starts_with("/media/")
                        || mp.starts_with("/run/media/")
                        || mp.starts_with("/mnt/")
                    {
                        let p = PathBuf::from(mp);
                        if p.is_dir() {
                            candidates.push(p);
                        }
                    }
                }
            }
        }
        for root in ["/media", "/run/media", "/mnt"] {
            if let Ok(entries) = fs::read_dir(root) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        candidates.push(p.clone());
                        if let Ok(children) = fs::read_dir(&p) {
                            for ch in children.flatten() {
                                if ch.path().is_dir() {
                                    candidates.push(ch.path());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut seen = HashSet::new();
    let mut drives = Vec::new();

    for path in candidates {
        let s = path.display().to_string();
        if !seen.insert(s.clone()) {
            continue;
        }
        let has_vault = path.join(".secure_vault").join("index.meta").is_file();
        let label = if has_vault {
            format!("🔐 {s}  [Vault SVAULT03 Rilevato]")
        } else {
            format!("💾 {s}  [Unità Esterna / USB]")
        };
        drives.push(UsbDriveInfo {
            mount_path: s,
            label,
            has_vault,
        });
    }

    drives.sort_by(|a, b| match (a.has_vault, b.has_vault) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.mount_path.cmp(&b.mount_path),
    });

    drives
}

pub fn format_physical_usb(device_path: &str, label: &str) -> io::Result<()> {
    let dev = device_path.trim();
    if dev.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Specificare il percorso del dispositivo (es. E:, /dev/sdb1, /dev/disk2)",
        ));
    }
    let vol_label = if label.trim().is_empty() {
        "SECURE_USB"
    } else {
        label.trim()
    };

    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "format", dev, "/FS:exFAT", &format!("/V:{vol_label}"), "/Q", "/Y"])
            .output()?
    } else if cfg!(target_os = "linux") {
        Command::new("mkfs.exfat")
            .args(["-n", vol_label, dev])
            .output()?
    } else if cfg!(target_os = "macos") {
        Command::new("diskutil")
            .args(["eraseDisk", "ExFAT", vol_label, dev])
            .output()?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Sistema operativo non supportato per la formattazione diretta",
        ));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Errore formattazione exFAT: {stderr} {stdout}"),
        ));
    }
    Ok(())
}
