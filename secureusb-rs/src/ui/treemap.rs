use crate::vault::FileEntry;
use eframe::egui::{self, Color32, FontId, Pos2, Rect, Rounding, Sense, Stroke, Vec2};
use std::path::Path;

struct TreemapRect {
    entry: FileEntry,
    rect: Rect,
}

pub fn classify_file_color(path: &str) -> (&'static str, Color32) {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "mp4" | "mkv" | "mov" | "avi" | "webm" | "mp3" | "flac" | "wav" => {
            ("Media/Video", Color32::from_rgb(139, 92, 246)) // Violet
        }
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "svg" => {
            ("Immagine", Color32::from_rgb(16, 185, 129)) // Emerald
        }
        "pdf" | "doc" | "docx" | "txt" | "md" | "rtf" | "odt" => {
            ("Documento", Color32::from_rgb(244, 63, 94)) // Rose
        }
        "go" | "rs" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "json" | "sql" | "toml" | "yaml" => {
            ("Codice/Dati", Color32::from_rgb(6, 182, 212)) // Cyan
        }
        "zip" | "tar" | "gz" | "zst" | "7z" | "rar" | "iso" | "img" => {
            ("Archivio/ISO", Color32::from_rgb(245, 158, 11)) // Amber
        }
        _ => ("Binario", Color32::from_rgb(99, 102, 241)), // Indigo
    }
}

fn compute_bsp_treemap(files: &[FileEntry], bounds: Rect, out: &mut Vec<TreemapRect>) {
    if files.is_empty() || bounds.width() <= 2.0 || bounds.height() <= 2.0 {
        return;
    }
    if files.len() == 1 {
        out.push(TreemapRect {
            entry: files[0].clone(),
            rect: bounds,
        });
        return;
    }

    let total: u64 = files
        .iter()
        .map(|f| f.original_size.max(1024))
        .sum();
    let half = total / 2;

    let mut accum = 0u64;
    let mut split_idx = 1usize;
    for (i, f) in files.iter().enumerate() {
        accum += f.original_size.max(1024);
        if accum >= half {
            split_idx = (i + 1).min(files.len() - 1);
            break;
        }
    }

    let left_weight: u64 = files[..split_idx]
        .iter()
        .map(|f| f.original_size.max(1024))
        .sum();
    let ratio = ((left_weight as f32) / (total as f32)).clamp(0.08, 0.92);

    if bounds.width() >= bounds.height() {
        let split_x = bounds.min.x + bounds.width() * ratio;
        let left_rect = Rect::from_min_max(bounds.min, Pos2::new(split_x, bounds.max.y));
        let right_rect = Rect::from_min_max(Pos2::new(split_x, bounds.min.y), bounds.max);
        compute_bsp_treemap(&files[..split_idx], left_rect, out);
        compute_bsp_treemap(&files[split_idx..], right_rect, out);
    } else {
        let split_y = bounds.min.y + bounds.height() * ratio;
        let top_rect = Rect::from_min_max(bounds.min, Pos2::new(bounds.max.x, split_y));
        let bottom_rect = Rect::from_min_max(Pos2::new(bounds.min.x, split_y), bounds.max);
        compute_bsp_treemap(&files[..split_idx], top_rect, out);
        compute_bsp_treemap(&files[split_idx..], bottom_rect, out);
    }
}

fn format_bytes_short(b: u64) -> String {
    const UNIT: u64 = 1024;
    if b < UNIT {
        return format!("{b} B");
    }
    let mut div = UNIT;
    let mut exp = 0usize;
    let mut n = b / UNIT;
    while n >= UNIT && exp < 5 {
        div *= UNIT;
        exp += 1;
        n /= UNIT;
    }
    let suffix = ["KB", "MB", "GB", "TB", "PB", "EB"][exp];
    format!("{:.1} {}", (b as f64) / (div as f64), suffix)
}

/// Disegna la Treemap interattiva occupando il 100% di 'ui.available_size()'.
/// Restituisce 'Some(FileEntry)' se l'utente clicca su un blocco.
pub fn draw_interactive_treemap(
    ui: &mut egui::Ui,
    scope_dir: &str,
    files: &[FileEntry],
) -> Option<FileEntry> {
    let total_orig: u64 = files.iter().map(|f| f.original_size).sum();
    let total_disk: u64 = files.iter().map(|f| f.disk_size).sum();

    ui.horizontal_wrapped(|ui| {
        ui.heading(format!("🗺️ Treemap Spazio Disco ({scope_dir})"));
        ui.separator();
        ui.label(format!(
            "{} file  •  Reale: {}  ➔  Su USB: {}",
            files.len(),
            format_bytes_short(total_orig),
            format_bytes_short(total_disk)
        ));
        ui.separator();
        ui.colored_label(Color32::from_rgb(139, 92, 246), "■ Video/Media");
        ui.colored_label(Color32::from_rgb(16, 185, 129), "■ Immagini");
        ui.colored_label(Color32::from_rgb(244, 63, 94), "■ PDF/Doc");
        ui.colored_label(Color32::from_rgb(6, 182, 212), "■ Codice/Dati");
        ui.colored_label(Color32::from_rgb(245, 158, 11), "■ Archivi/ISO");
        ui.colored_label(Color32::from_rgb(99, 102, 241), "■ Binari");
    });
    ui.separator();

    let avail = ui.available_size();
    if files.is_empty() {
        ui.allocate_space(Vec2::new(avail.x, avail.y.max(40.0) * 0.35));
        ui.vertical_centered(|ui| {
            ui.heading("📂 Nessun file presente in questo percorso");
            ui.label("Importa file o cartelle (o trascinali qui con Drag & Drop) per visualizzare la mappa interattiva dello spazio.");
        });
        return None;
    }

    let canvas_size = Vec2::new(avail.x.max(200.0), avail.y.max(180.0));
    let (response, painter) = ui.allocate_painter(canvas_size, Sense::click());
    let canvas_rect = response.rect;

    let mut nodes = Vec::with_capacity(files.len());
    compute_bsp_treemap(files, canvas_rect, &mut nodes);

    let pointer_pos = response.hover_pos();
    let mut hovered_node: Option<&TreemapRect> = None;
    let mut clicked_entry: Option<FileEntry> = None;

    for node in &nodes {
        let inner = node.rect.shrink(2.0);
        if inner.width() <= 0.5 || inner.height() <= 0.5 {
            continue;
        }

        let is_hovered = pointer_pos.map_or(false, |p| inner.contains(p));
        let (_, base_color) = classify_file_color(&node.entry.virtual_path);

        let fill = if is_hovered {
            Color32::from_rgb(
                base_color.r().saturating_add(28),
                base_color.g().saturating_add(28),
                base_color.b().saturating_add(28),
            )
        } else {
            base_color
        };

        let stroke = if is_hovered {
            Stroke::new(2.5_f32, Color32::WHITE)
        } else {
            Stroke::new(1.5_f32, Color32::from_rgb(15, 23, 42))
        };

        painter.rect(inner, Rounding::same(6.0), fill, stroke);

        if inner.width() > 52.0 && inner.height() > 24.0 {
            let file_name = Path::new(&node.entry.virtual_path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| node.entry.virtual_path.clone());

            let clipped = painter.with_clip_rect(inner.shrink(4.0));
            clipped.text(
                inner.min + Vec2::new(6.0, 5.0),
                egui::Align2::LEFT_TOP,
                &file_name,
                FontId::proportional(13.0),
                Color32::WHITE,
            );

            if inner.height() > 42.0 {
                let pct = if total_orig > 0 {
                    (node.entry.original_size as f64 / total_orig as f64) * 100.0
                } else {
                    100.0
                };
                clipped.text(
                    inner.min + Vec2::new(6.0, 22.0),
                    egui::Align2::LEFT_TOP,
                    format!("{} ({:.1}%)", format_bytes_short(node.entry.original_size), pct),
                    FontId::proportional(11.0),
                    Color32::from_rgb(241, 245, 249),
                );
            }
        }

        if is_hovered {
            hovered_node = Some(node);
            if response.clicked() {
                clicked_entry = Some(node.entry.clone());
            }
        }
    }

    if let Some(h) = hovered_node {
        let (cat, _) = classify_file_color(&h.entry.virtual_path);
        let ratio = if h.entry.original_size > 0 {
            (h.entry.disk_size as f64 / h.entry.original_size as f64) * 100.0
        } else {
            100.0
        };
        response.on_hover_ui_at_pointer(|ui| {
            ui.strong(format!("📄 {}", h.entry.virtual_path));
            ui.label(format!("Categoria: {cat}"));
            ui.label(format!(
                "Dimensione Reale: {}  ➔  Su USB: {} ({:.1}%)",
                format_bytes_short(h.entry.original_size),
                format_bytes_short(h.entry.disk_size),
                ratio
            ));
            ui.label(format!("Chunk da 4 MB: {}", h.entry.chunk_sizes.len()));
            ui.colored_label(
                Color32::from_rgb(16, 185, 129),
                "🖱️ Clicca per aprire immediatamente il file in RAM",
            );
        });
    }

    clicked_entry
}
