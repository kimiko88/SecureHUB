use crate::vault::{FileEntry, SecureVault};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Individua la cartella Desktop dell'utente su Windows, Linux e macOS.
pub fn get_desktop_dir() -> PathBuf {
    let home = if cfg!(target_os = "windows") {
        env::var("USERPROFILE").ok().map(PathBuf::from)
    } else {
        env::var("HOME").ok().map(PathBuf::from)
    };

    if let Some(h) = home {
        let desk = h.join("Desktop");
        if desk.is_dir() {
            return desk;
        }
        return h;
    }
    env::temp_dir()
}

/// Esporta un singolo file o un'intera cartella ricorsiva dal Vault dentro 'target_parent_dir'.
/// Restituisce il percorso finale generato sul filesystem ospite.
pub fn export_entry_to_dir(
    vault: &SecureVault,
    entry: &FileEntry,
    target_parent_dir: &Path,
) -> io::Result<PathBuf> {
    fs::create_dir_all(target_parent_dir)?;

    if entry.is_dir {
        vault.export_dir(&entry.virtual_path, target_parent_dir)?;
        let folder_name = if entry.virtual_path == "/" {
            "Vault_Export".to_string()
        } else {
            Path::new(&entry.virtual_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Vault_Export".to_string())
        };
        return Ok(target_parent_dir.join(folder_name));
    }

    let file_name = Path::new(&entry.virtual_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "exported.bin".to_string());
    let dest_path = target_parent_dir.join(file_name);

    if !entry.chunk_refs.is_empty() {
        let bytes = vault.read_dedup_file(&entry.virtual_path)?;
        fs::write(&dest_path, &bytes)?;
    } else {
        let out_file = File::create(&dest_path)?;
        vault.read_stream(
            &entry.virtual_path,
            BufWriter::with_capacity(1024 * 1024, out_file),
        )?;
    }

    Ok(dest_path)
}

/// Carica il file o la cartella estratta negli Appunti di Sistema come oggetto File nativo
/// ('CF_HDROP' su Windows, 'POSIX file' su macOS, 'text/uri-list' su Linux) per incollarlo con Ctrl+V.
pub fn copy_file_object_to_os_clipboard(local_path: &Path) -> io::Result<()> {
    let abs = fs::canonicalize(local_path).unwrap_or_else(|_| local_path.to_path_buf());
    let display = abs.display().to_string();
    let clean_path = display.strip_prefix(r"\\?\").unwrap_or(&display);

    if cfg!(target_os = "windows") {
        let escaped = clean_path.replace('\'', "''");
        let ps_cmd = format!("Set-Clipboard -Path '{escaped}'");
        let status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .status()?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Set-Clipboard di PowerShell non riuscito",
            ));
        }
    } else if cfg!(target_os = "macos") {
        let escaped = clean_path.replace('"', "\\\"");
        let script = format!("set the clipboard to (POSIX file \"{escaped}\")");
        let _ = Command::new("osascript").args(["-e", &script]).status()?;
    } else {
        let uri = format!("file://{}\r\n", clean_path.replace('\\', "/"));
        if let Ok(mut child) = Command::new("xclip")
            .args(["-selection", "clipboard", "-t", "text/uri-list"])
            .stdin(Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(uri.as_bytes());
            }
            let _ = child.wait();
        }
    }
    Ok(())
}

/// Apre il File Explorer del sistema operativo evidenziando il file o la cartella appena esportati.
pub fn reveal_in_os_file_manager(local_path: &Path) {
    let abs = fs::canonicalize(local_path).unwrap_or_else(|_| local_path.to_path_buf());
    let display = abs.display().to_string();
    let clean = display.strip_prefix(r"\\?\").unwrap_or(&display);

    if cfg!(target_os = "windows") {
        let _ = Command::new("explorer.exe")
            .arg(format!("/select,{clean}"))
            .spawn();
    } else if cfg!(target_os = "macos") {
        let _ = Command::new("open").args(["-R", clean]).spawn();
    } else if let Some(parent) = Path::new(clean).parent() {
        let _ = Command::new("xdg-open").arg(parent).spawn();
    }
}
