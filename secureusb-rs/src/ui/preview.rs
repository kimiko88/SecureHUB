use crate::vault::SecureVault;
use eframe::egui;
use std::io::Read;
use std::path::Path;

pub fn is_image_ext(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some("png" | "jpg" | "jpeg" | "gif")
    )
}

pub fn is_pdf_ext(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some("pdf")
    )
}

/// Decodifica un'immagine PNG/JPEG/GIF direttamente in RAM da VaultReadSeeker (zero file temporanei)
pub fn load_image_texture_in_ram(
    ctx: &egui::Context,
    vault: &SecureVault,
    virtual_path: &str,
) -> Result<(egui::TextureHandle, (usize, usize)), String> {
    let mut seeker = vault
        .open_read_seeker(virtual_path)
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::with_capacity(seeker.size() as usize);
    seeker.read_to_end(&mut raw).map_err(|e| e.to_string())?;

    let img = image::load_from_memory(&raw).map_err(|e| e.to_string())?;
    let rgba = img.to_rgba8();
    let dims = (rgba.width() as usize, rgba.height() as usize);
    let color_img = egui::ColorImage::from_rgba_unmultiplied([dims.0, dims.1], rgba.as_raw());
    let tex = ctx.load_texture(virtual_path, color_img, egui::TextureOptions::LINEAR);
    Ok((tex, dims))
}

/// Estrae il testo di tutte le pagine di un PDF direttamente in RAM da VaultReadSeeker
pub fn extract_pdf_pages_in_ram(
    vault: &SecureVault,
    virtual_path: &str,
) -> Result<Vec<String>, String> {
    let mut seeker = vault
        .open_read_seeker(virtual_path)
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::with_capacity(seeker.size() as usize);
    seeker.read_to_end(&mut raw).map_err(|e| e.to_string())?;

    let doc = lopdf::Document::load_mem(&raw).map_err(|e| format!("Errore parsing PDF: {e}"))?;
    let pages = doc.get_pages();
    let mut out = Vec::new();

    for (page_num, _) in pages {
        let text = doc
            .extract_text(&[page_num])
            .unwrap_or_else(|_| format!("[Pagina {page_num} senza testo estraibile]"));
        out.push(text);
    }

    if out.is_empty() {
        out.push("[Documento PDF decodificato in RAM — Nessuna pagina testuale rilevata]".to_string());
    }
    Ok(out)
}
