use std::io;
use std::process::Command;

/// Formatta fisicamente la chiavetta USB in exFAT su Windows, Linux e macOS.
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
