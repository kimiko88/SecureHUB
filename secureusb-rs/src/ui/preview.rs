use crate::vault::SecureVault;
use eframe::egui::{self, Color32, FontId, Pos2, Rect, Rounding, Stroke, Vec2};
use flate2::read::{DeflateDecoder, ZlibDecoder};
use std::env;
use std::fs;
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

/// Legge i byte decifrati di qualsiasi file nel Vault (sia standard SVAULT03 sia deduplicato BLAKE3)
pub fn read_vault_bytes(vault: &SecureVault, virtual_path: &str) -> Result<Vec<u8>, String> {
    if let Some(entry) = vault.stat(virtual_path) {
        if !entry.chunk_refs.is_empty() {
            return vault
                .read_dedup_file(virtual_path)
                .map_err(|e| e.to_string());
        }
    }
    vault.read_file(virtual_path).map_err(|e| e.to_string())
}

/// Decodifica un'immagine PNG/JPEG/GIF direttamente in RAM
pub fn load_image_texture_in_ram(
    ctx: &egui::Context,
    vault: &SecureVault,
    virtual_path: &str,
) -> Result<(egui::TextureHandle, (usize, usize)), String> {
    let raw = read_vault_bytes(vault, virtual_path)?;
    let img = image::load_from_memory(&raw).map_err(|e| e.to_string())?;
    let rgba = img.to_rgba8();
    let dims = (rgba.width() as usize, rgba.height() as usize);
    let color_img = egui::ColorImage::from_rgba_unmultiplied([dims.0, dims.1], rgba.as_raw());
    let tex = ctx.load_texture(virtual_path, color_img, egui::TextureOptions::LINEAR);
    Ok((tex, dims))
}

// ============================================================================
// MOTORE PDF MULTI-STADIO IN RAM (Con Sidebar Pagine, FlateDecode, TJ e Immagini)
// ============================================================================

#[derive(Clone)]
pub struct PdfPageData {
    pub page_num: usize,
    pub title: String,
    pub text: String,
    pub char_count: usize,
}

pub struct PdfDocumentInRam {
    pub pages: Vec<PdfPageData>,
    pub embedded_images: Vec<(egui::TextureHandle, (usize, usize))>,
    pub raw_size: usize,
}

/// Estrae tutte le pagine di un PDF in RAM combinando:
/// 1) Il parser strutturato 'lopdf' (con decodifica degli stream di pagina)
/// 2) Un decompressore raw '/FlateDecode' (Zlib/Deflate) + parser 'BT..ET' / 'Tj' / 'TJ' / '<HEX>'
/// 3) Un estrattore di immagini JPEG ('/DCTDecode') incorporate nelle pagine
pub fn load_pdf_document_in_ram(
    ctx: &egui::Context,
    vault: &SecureVault,
    virtual_path: &str,
) -> Result<PdfDocumentInRam, String> {
    let raw = read_vault_bytes(vault, virtual_path)?;
    let raw_size = raw.len();
    let mut pages: Vec<PdfPageData> = Vec::new();

    // STADIO 1: Parser strutturato lopdf per pagina
    if let Ok(doc) = lopdf::Document::load_mem(&raw) {
        let page_map = doc.get_pages();
        for (&page_num, &page_id) in &page_map {
            let mut page_text = doc.extract_text(&[page_num]).unwrap_or_default();

            // Se extract_text restituisce vuoto (es. font custom o operatori TJ nidificati),
            // decodifica direttamente il content stream della pagina
            if page_text.trim().is_empty() {
                if let Ok(content_bytes) = doc.get_page_content(page_id) {
                    page_text = extract_text_from_pdf_ops(&content_bytes);
                }
            }

            let trimmed = page_text.trim().to_string();
            if !trimmed.is_empty() {
                let first_line = trimmed
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("Pagina PDF")
                    .chars()
                    .take(36)
                    .collect::<String>();
                pages.push(PdfPageData {
                    page_num: page_num as usize,
                    title: format!("Pag. {} — {}", page_num, first_line),
                    char_count: trimmed.chars().count(),
                    text: trimmed,
                });
            } else {
                pages.push(PdfPageData {
                    page_num: page_num as usize,
                    title: format!("Pag. {} (Grafica / Vettoriale)", page_num),
                    char_count: 0,
                    text: String::new(),
                });
            }
        }
    }

    // STADIO 2 & 3: Scansione diretta di tutti gli stream /FlateDecode e /DCTDecode
    let (fallback_chunks, embedded_images) = scan_raw_pdf_streams(ctx, virtual_path, &raw);

    // Se lopdf non ha trovato pagine (es. PDF 1.5+ con XRefStm compresso) o le pagine erano vuote,
    // popola o arricchisce le pagine con i blocchi estratti dallo scanner FlateDecode
    let all_empty = pages.iter().all(|p| p.text.is_empty());
    if pages.is_empty() || all_empty {
        if !fallback_chunks.is_empty() {
            pages.clear();
            for (idx, chunk_txt) in fallback_chunks.into_iter().enumerate() {
                let page_no = idx + 1;
                let preview_line = chunk_txt
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("Contenuto Pagina")
                    .chars()
                    .take(36)
                    .collect::<String>();
                pages.push(PdfPageData {
                    page_num: page_no,
                    title: format!("Pag. {page_no} — {preview_line}"),
                    char_count: chunk_txt.chars().count(),
                    text: chunk_txt,
                });
            }
        }
    }

    // Se un PDF contiene esclusivamente scansioni/immagini o tracciati vettoriali senza testo
    if pages.is_empty() {
        pages.push(PdfPageData {
            page_num: 1,
            title: "Pag. 1 — Documento Grafico / Scansione".to_string(),
            char_count: 0,
            text: format!(
                "[Documento PDF caricato correttamente in RAM ({} byte).\n\
                 Questo PDF contiene {} immagini incorporate o tracciati vettoriali.\n\
                 Puoi visualizzare le immagini qui sotto oppure cliccare '🚀 Apri nel Lettore PDF di Sistema' in alto a destra.]",
                raw_size,
                embedded_images.len()
            ),
        });
    } else {
        for p in &mut pages {
            if p.text.is_empty() {
                p.text = format!(
                    "[Pagina {} — Contenuto grafico/vettoriale o font incorporato.\n\
                     Clicca '🚀 Apri nel Lettore PDF di Sistema' per il rendering tipografico completo.]",
                    p.page_num
                );
            }
        }
    }

    Ok(PdfDocumentInRam {
        pages,
        embedded_images,
        raw_size,
    })
}

/// Esporta temporaneamente il PDF e lo apre nel visualizzatore PDF nativo del sistema operativo
pub fn open_pdf_in_system_viewer(vault: &SecureVault, virtual_path: &str) -> Result<(), String> {
    let raw = read_vault_bytes(vault, virtual_path)?;
    let file_name = Path::new(virtual_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "document.pdf".to_string());
    let tmp_dir = env::temp_dir().join("secureusb_pdf_view");
    fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    let tmp_file = tmp_dir.join(file_name);
    fs::write(&tmp_file, &raw).map_err(|e| e.to_string())?;
    open::that(&tmp_file).map_err(|e| e.to_string())
}

fn scan_raw_pdf_streams(
    ctx: &egui::Context,
    virtual_path: &str,
    raw: &[u8],
) -> (Vec<String>, Vec<(egui::TextureHandle, (usize, usize))>) {
    let mut text_pages = Vec::new();
    let mut images = Vec::new();
    let mut current_page_text = String::new();

    let mut pos = 0usize;
    let mut img_counter = 0usize;

    while let Some(rel_stream) = find_subslice(&raw[pos..], b"stream") {
        let stream_kw = pos + rel_stream;
        // Assicura che non sia la fine di "endstream"
        if stream_kw >= 3 && &raw[stream_kw - 3..stream_kw] == b"end" {
            pos = stream_kw + 6;
            continue;
        }

        let dict_start = stream_kw.saturating_sub(320);
        let dict_str = String::from_utf8_lossy(&raw[dict_start..stream_kw]);

        let mut data_start = stream_kw + 6;
        if data_start < raw.len() && raw[data_start] == b'\r' {
            data_start += 1;
        }
        if data_start < raw.len() && raw[data_start] == b'\n' {
            data_start += 1;
        } else {
            pos = stream_kw + 6;
            continue;
        }

        let Some(rel_end) = find_subslice(&raw[data_start..], b"endstream") else {
            break;
        };
        let mut data_end = data_start + rel_end;
        while data_end > data_start
            && (raw[data_end - 1] == b'\n' || raw[data_end - 1] == b'\r')
        {
            data_end -= 1;
        }

        let stream_bytes = &raw[data_start..data_end];
        pos = data_start + rel_end + 9;

        // 1. Se è un'immagine JPEG incorporata (/DCTDecode), la decodifica in RAM
        if dict_str.contains("/DCTDecode") && images.len() < 16 {
            if let Ok(img) = image::load_from_memory(stream_bytes) {
                let rgba = img.to_rgba8();
                let dims = (rgba.width() as usize, rgba.height() as usize);
                if dims.0 >= 24 && dims.1 >= 24 {
                    let cimg =
                        egui::ColorImage::from_rgba_unmultiplied([dims.0, dims.1], rgba.as_raw());
                    let tex = ctx.load_texture(
                        format!("{virtual_path}_pdf_img_{img_counter}"),
                        cimg,
                        egui::TextureOptions::LINEAR,
                    );
                    images.push((tex, dims));
                    img_counter += 1;
                }
            }
            continue;
        }

        // 2. Decomprime /FlateDecode con Zlib o Deflate raw
        let decompressed = if dict_str.contains("/FlateDecode") {
            let mut out = Vec::new();
            if ZlibDecoder::new(stream_bytes).read_to_end(&mut out).is_ok() && !out.is_empty() {
                out
            } else {
                out.clear();
                if DeflateDecoder::new(stream_bytes)
                    .read_to_end(&mut out)
                    .is_ok()
                {
                    out
                } else {
                    continue;
                }
            }
        } else {
            stream_bytes.to_vec()
        };

        let extracted = extract_text_from_pdf_ops(&decompressed);
        if !extracted.trim().is_empty() {
            if !current_page_text.is_empty() {
                current_page_text.push_str("\n\n");
            }
            current_page_text.push_str(extracted.trim());

            if current_page_text.len() >= 1400 {
                text_pages.push(std::mem::take(&mut current_page_text));
            }
        }
    }

    if !current_page_text.trim().is_empty() {
        text_pages.push(current_page_text);
    }

    (text_pages, images)
}

/// Interpreta gli operatori di testo PDF ('(...)', array 'TJ [(...)]' e stringhe hex '<...>')
fn extract_text_from_pdf_ops(content: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    let len = content.len();

    while i < len {
        match content[i] {
            b'(' => {
                i += 1;
                let mut depth = 1usize;
                let mut token = Vec::new();
                while i < len && depth > 0 {
                    let b = content[i];
                    if b == b'\\' && i + 1 < len {
                        i += 1;
                        match content[i] {
                            b'n' => token.push(b'\n'),
                            b'r' => token.push(b'\r'),
                            b't' => token.push(b'\t'),
                            b'(' => token.push(b'('),
                            b')' => token.push(b')'),
                            b'\\' => token.push(b'\\'),
                            other => token.push(other),
                        }
                    } else if b == b'(' {
                        depth += 1;
                        token.push(b);
                    } else if b == b')' {
                        depth -= 1;
                        if depth > 0 {
                            token.push(b);
                        }
                    } else {
                        token.push(b);
                    }
                    i += 1;
                }
                let s = String::from_utf8_lossy(&token);
                if s.chars().any(|c| c.is_alphanumeric() || c.is_ascii_punctuation()) {
                    out.push_str(&s);
                }
            }
            b'T' if i + 1 < len => {
                let next = content[i + 1];
                if next == b'D' || next == b'd' || next == b'*' || next == b'\'' {
                    out.push('\n');
                } else if next == b'J' || next == b'j' {
                    out.push(' ');
                }
                i += 1;
            }
            b'E' if i + 1 < len && content[i + 1] == b'T' => {
                out.push('\n');
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    // Pulisce righe multiple vuote
    let mut cleaned = String::new();
    for line in out.lines() {
        let t = line.trim();
        if !t.is_empty() {
            cleaned.push_str(t);
            cleaned.push('\n');
        }
    }
    cleaned
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ============================================================================
// ISPETTORE VISUALE HEX O(1) + MAPPA TERMICA DELL'ENTROPIA DI SHANNON
// ============================================================================

#[derive(Clone)]
pub struct HexEntropyState {
    pub path: String,
    pub total_size: u64,
    pub current_offset: u64,
    pub window_bytes: Vec<u8>,
    pub entropy_bands: Vec<f32>, // 64 bande di entropia (0.0 .. 8.0 bit/byte)
    pub global_entropy: f32,
    pub ascii_pct: f32,
    pub null_pct: f32,
    pub high_bit_pct: f32,
}

pub fn load_hex_entropy_window(
    vault: &SecureVault,
    virtual_path: &str,
    offset: u64,
) -> Result<HexEntropyState, String> {
    let entry = vault
        .stat(virtual_path)
        .ok_or_else(|| "File non trovato".to_string())?;
    let total_size = entry.original_size;
    let clamped_offset = if total_size > 0 {
        offset.min(total_size.saturating_sub(1)) & !0x0F // Allinea a 16 byte
    } else {
        0
    };

    let mut window = vec![0u8; 4096.min(total_size.saturating_sub(clamped_offset) as usize)];
    if !window.is_empty() {
        if !entry.chunk_refs.is_empty() {
            let all = vault
                .read_dedup_file(virtual_path)
                .map_err(|e| e.to_string())?;
            let start = clamped_offset as usize;
            let end = (start + window.len()).min(all.len());
            window.truncate(end.saturating_sub(start));
            window.copy_from_slice(&all[start..end]);
        } else {
            let mut seeker = vault
                .open_read_seeker(virtual_path)
                .map_err(|e| e.to_string())?;
            let n = seeker
                .read_at(&mut window, clamped_offset)
                .map_err(|e| e.to_string())?;
            window.truncate(n);
        }
    }

    let global_entropy = compute_shannon_entropy(&window);
    let mut bands = Vec::with_capacity(64);
    if !window.is_empty() {
        let step = (window.len() / 64).max(16);
        for chunk in window.chunks(step).take(64) {
            bands.push(compute_shannon_entropy(chunk));
        }
    }

    let mut ascii_cnt = 0usize;
    let mut null_cnt = 0usize;
    let mut high_cnt = 0usize;
    for &b in &window {
        if b == 0 {
            null_cnt += 1;
        } else if (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
            ascii_cnt += 1;
        } else if b >= 0x80 {
            high_cnt += 1;
        }
    }
    let denom = (window.len().max(1)) as f32;

    Ok(HexEntropyState {
        path: virtual_path.to_string(),
        total_size,
        current_offset: clamped_offset,
        window_bytes: window,
        entropy_bands: bands,
        global_entropy,
        ascii_pct: (ascii_cnt as f32 / denom) * 100.0,
        null_pct: (null_cnt as f32 / denom) * 100.0,
        high_bit_pct: (high_cnt as f32 / denom) * 100.0,
    })
}

pub fn compute_shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let inv = 1.0f32 / (data.len() as f32);
    let mut h = 0.0f32;
    for &c in &counts {
        if c > 0 {
            let p = (c as f32) * inv;
            h -= p * p.log2();
        }
    }
    h
}

pub fn entropy_to_color(h: f32) -> Color32 {
    if h < 3.0 {
        Color32::from_rgb(16, 185, 129) // Verde Smeraldo: Bassa entropia / testo / padding
    } else if h < 5.5 {
        Color32::from_rgb(6, 182, 212) // Ciano: Codice sorgente / strutturato
    } else if h < 7.2 {
        Color32::from_rgb(245, 158, 11) // Ambra: Dati compressi / misti
    } else {
        Color32::from_rgb(244, 63, 94) // Rosso/Rosa: Altissima entropia (Cifrato / Media compresso)
    }
}

/// Disegna la Mappa Termica dell'Entropia di Shannon e il Dump Esadecimale + ASCII interattivo
pub fn draw_hex_entropy_inspector(
    ui: &mut egui::Ui,
    state: &HexEntropyState,
) -> Option<u64> {
    let mut new_offset: Option<u64> = None;

    // 1. Barra di Navigazione Offset O(1) + Statistiche Byte
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.strong(format!(
                "🔬 Offset: 0x{:08X} ({} / {} B)",
                state.current_offset, state.current_offset, state.total_size
            ));
            if ui.button("⏮ Inizio (0x0)").clicked() && state.current_offset > 0 {
                new_offset = Some(0);
            }
            if ui.button("◀ -4 KB").clicked() && state.current_offset > 0 {
                new_offset = Some(state.current_offset.saturating_sub(4096));
            }
            if ui.button("+4 KB ▶").clicked()
                && state.current_offset + 4096 < state.total_size
            {
                new_offset = Some(state.current_offset + 4096);
            }
            if ui.button("+4 MB (Chunk Succ) ⏭").clicked()
                && state.current_offset + (4 * 1024 * 1024) < state.total_size
            {
                new_offset = Some(state.current_offset + (4 * 1024 * 1024));
            }

            ui.separator();
            ui.colored_label(
                entropy_to_color(state.global_entropy),
                format!("🌡️ Entropia Finestra: {:.2} / 8.00 bit/byte", state.global_entropy),
            );
            ui.label(format!(
                "|  ASCII: {:.0}%  •  Null (0x00): {:.0}%  •  High-Bit: {:.0}%",
                state.ascii_pct, state.null_pct, state.high_bit_pct
            ));
        });

        // 2. Mappa Termica (Thermal Ribbon) a 64 bande
        ui.add_space(4.0);
        let ribbon_w = ui.available_width();
        let (ribbon_rect, _) =
            ui.allocate_exact_size(Vec2::new(ribbon_w, 26.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(ribbon_rect, Rounding::same(4.0), Color32::from_rgb(9, 14, 26));

        let n_bands = state.entropy_bands.len().max(1);
        let band_w = ribbon_rect.width() / (n_bands as f32);
        for (idx, &h) in state.entropy_bands.iter().enumerate() {
            let x0 = ribbon_rect.min.x + (idx as f32) * band_w;
            let bar_h = (h / 8.0).clamp(0.08, 1.0) * (ribbon_rect.height() - 4.0);
            let r = Rect::from_min_max(
                Pos2::new(x0 + 1.0, ribbon_rect.max.y - 2.0 - bar_h),
                Pos2::new(x0 + band_w - 1.0, ribbon_rect.max.y - 2.0),
            );
            painter.rect_filled(r, Rounding::same(2.0), entropy_to_color(h));
        }
        painter.rect_stroke(
            ribbon_rect,
            Rounding::same(4.0),
            Stroke::new(1.0, Color32::from_rgb(51, 65, 85)),
        );
    });

    ui.add_space(4.0);

    // 3. Tabella Esadecimale + ASCII a tutta altezza
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (row_idx, chunk) in state.window_bytes.chunks(16).enumerate() {
                let row_addr = state.current_offset + (row_idx as u64) * 16;
                let mut hex_part = String::with_capacity(52);
                let mut ascii_part = String::with_capacity(18);

                for i in 0..16 {
                    if i == 8 {
                        hex_part.push(' ');
                    }
                    if i < chunk.len() {
                        let b = chunk[i];
                        hex_part.push_str(&format!("{b:02X} "));
                        if (0x20..=0x7E).contains(&b) {
                            ascii_part.push(b as char);
                        } else {
                            ascii_part.push('·');
                        }
                    } else {
                        hex_part.push_str("   ");
                        ascii_part.push(' ');
                    }
                }

                ui.horizontal(|ui| {
                    ui.colored_label(
                        Color32::from_rgb(6, 182, 212),
                        egui::RichText::new(format!("{row_addr:08X}  ")). font(FontId::monospace(13.0)),
                    );
                    ui.label(
                        egui::RichText::new(hex_part)
                            .font(FontId::monospace(13.0))
                            .color(Color32::from_rgb(226, 232, 240)),
                    );
                    ui.colored_label(
                        Color32::from_rgb(16, 185, 129),
                        egui::RichText::new(format!(" |{ascii_part}|")).font(FontId::monospace(13.0)),
                    );
                });
            }
        });

    new_offset
}
