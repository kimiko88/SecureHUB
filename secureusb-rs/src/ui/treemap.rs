use crate::vault::FileEntry;
use eframe::egui::{self, Color32, FontId, Pos2, Rect, Rounding, Sense, Stroke, Vec2};
use std::f32::consts::TAU;
use std::path::Path;

struct TreemapRect {
    entry: FileEntry,
    rect: Rect,
}

pub const CATEGORY_NAMES: [&str; 6] = [
    "Video/Media",
    "Immagini",
    "PDF/Doc",
    "Codice/Dati",
    "Archivi/ISO",
    "Binari",
];

pub const CATEGORY_COLORS: [Color32; 6] = [
    Color32::from_rgb(139, 92, 246), // Violet
    Color32::from_rgb(16, 185, 129), // Emerald
    Color32::from_rgb(244, 63, 94),  // Rose
    Color32::from_rgb(6, 182, 212),  // Cyan
    Color32::from_rgb(245, 158, 11), // Amber
    Color32::from_rgb(99, 102, 241), // Indigo
];

pub fn classify_file_category_idx(path: &str) -> usize {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "mp4" | "mkv" | "mov" | "avi" | "webm" | "mp3" | "flac" | "wav" => 0,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "svg" => 1,
        "pdf" | "doc" | "docx" | "txt" | "md" | "rtf" | "odt" => 2,
        "go" | "rs" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "json" | "sql" | "toml" | "yaml" => 3,
        "zip" | "tar" | "gz" | "zst" | "7z" | "rar" | "iso" | "img" => 4,
        _ => 5,
    }
}

pub fn classify_file_color(path: &str) -> (&'static str, Color32) {
    let idx = classify_file_category_idx(path);
    (CATEGORY_NAMES[idx], CATEGORY_COLORS[idx])
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

    let total: u64 = files.iter().map(|f| f.original_size.max(1024)).sum();
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

/// Disegna il Grafico ad Anello (Donut Chart) delle categorie e la Sparkline Velocità MB/s
fn draw_donut_and_sparkline_strip(
    ui: &mut egui::Ui,
    files: &[FileEntry],
    throughput_history: &[f32],
) {
    let mut cat_bytes = [0u64; 6];
    let mut total_orig = 0u64;
    let mut total_disk = 0u64;
    for f in files {
        let idx = classify_file_category_idx(&f.virtual_path);
        cat_bytes[idx] += f.original_size.max(1);
        total_orig += f.original_size;
        total_disk += f.disk_size;
    }

    let strip_h = 112.0;
    ui.columns(2, |cols| {
        // 1. DONUT CHART DELLE CATEGORIE
        egui::Frame::group(cols[0].style()).show(&mut cols[0], |ui| {
            ui.set_min_height(strip_h);
            ui.horizontal(|ui| {
                let (donut_rect, _) =
                    ui.allocate_exact_size(Vec2::new(98.0, 98.0), Sense::hover());
                let painter = ui.painter();
                let center = donut_rect.center();
                let outer_r = 44.0;
                let inner_r = 25.0;
                let ring_r = (outer_r + inner_r) * 0.5;
                let stroke_w = outer_r - inner_r;

                if total_orig == 0 {
                    painter.circle_stroke(
                        center,
                        ring_r,
                        Stroke::new(stroke_w, Color32::from_rgb(30, 41, 59)),
                    );
                } else {
                    let mut start_angle = -TAU * 0.25;
                    for i in 0..6 {
                        if cat_bytes[i] == 0 {
                            continue;
                        }
                        let frac = (cat_bytes[i] as f32) / (total_orig.max(1) as f32);
                        let sweep = (frac * TAU).max(0.04);
                        let steps = ((sweep * 24.0) as usize).clamp(4, 48);
                        let mut pts = Vec::with_capacity(steps + 1);
                        for s in 0..=steps {
                            let a = start_angle + sweep * (s as f32 / steps as f32);
                            pts.push(Pos2::new(
                                center.x + ring_r * a.cos(),
                                center.y + ring_r * a.sin(),
                            ));
                        }
                        painter.add(egui::Shape::line(
                            pts,
                            Stroke::new(stroke_w, CATEGORY_COLORS[i]),
                        ));
                        start_angle += sweep;
                    }
                }

                let saved_pct = if total_orig > 0 && total_orig > total_disk {
                    ((total_orig - total_disk) as f32 / total_orig as f32) * 100.0
                } else {
                    0.0
                };
                painter.text(
                    center,
                    egui::Align2::CENTER_CENTER,
                    format!("-{saved_pct:.0}%"),
                    FontId::proportional(13.0),
                    Color32::WHITE,
                );

                // Legenda percentuali a fianco dell'anello
                ui.vertical(|ui| {
                    ui.strong("🍩 Ripartizione Spazio (Donut Chart)");
                    for i in 0..6 {
                        if cat_bytes[i] > 0 || total_orig == 0 {
                            let pct = if total_orig > 0 {
                                (cat_bytes[i] as f32 / total_orig as f32) * 100.0
                            } else {
                                0.0
                            };
                            ui.horizontal(|ui| {
                                ui.colored_label(CATEGORY_COLORS[i], "●");
                                ui.label(format!(
                                    "{}: {} ({:.0}%)",
                                    CATEGORY_NAMES[i],
                                    format_bytes_short(cat_bytes[i]),
                                    pct
                                ));
                            });
                        }
                    }
                });
            });
        });

        // 2. SPARKLINE VELOCITÀ MULTI-CORE (MB/s)
        egui::Frame::group(cols[1].style()).show(&mut cols[1], |ui| {
            ui.set_min_height(strip_h);
            let peak = throughput_history
                .iter()
                .copied()
                .fold(0.0f32, f32::max)
                .max(100.0);
            let current_mbps = throughput_history.last().copied().unwrap_or(0.0);

            ui.horizontal(|ui| {
                ui.strong("⚡ Throughput Pipeline Multi-Core (Sparkline)");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.colored_label(
                        Color32::from_rgb(16, 185, 129),
                        format!("Attuale: {current_mbps:.0} MB/s  (Picco: {peak:.0} MB/s)"),
                    );
                });
            });

            let avail_w = ui.available_width();
            let (spark_rect, _) =
                ui.allocate_exact_size(Vec2::new(avail_w, 68.0), Sense::hover());
            let painter = ui.painter();
            painter.rect_filled(spark_rect, Rounding::same(6.0), Color32::from_rgb(9, 14, 26));

            if throughput_history.len() >= 2 {
                let n = throughput_history.len();
                let dx = spark_rect.width() / ((n - 1) as f32);
                let mut pts = Vec::with_capacity(n);
                for (i, &val) in throughput_history.iter().enumerate() {
                    let norm = (val / peak).clamp(0.05, 0.95);
                    let x = spark_rect.min.x + (i as f32) * dx;
                    let y = spark_rect.max.y - norm * spark_rect.height();
                    pts.push(Pos2::new(x, y));
                }
                painter.add(egui::Shape::line(
                    pts,
                    Stroke::new(2.2, Color32::from_rgb(6, 182, 212)),
                ));
            }
            painter.rect_stroke(
                spark_rect,
                Rounding::same(6.0),
                Stroke::new(1.0, Color32::from_rgb(51, 65, 85)),
            );
        });
    });
}

/// Disegna la Dashboard completa (Donut Chart + Sparkline MB/s + Treemap Interattiva)
pub fn draw_interactive_treemap(
    ui: &mut egui::Ui,
    scope_dir: &str,
    files: &[FileEntry],
    throughput_history: &[f32],
) -> Option<FileEntry> {
    draw_donut_and_sparkline_strip(ui, files, throughput_history);
    ui.add_space(4.0);

    let avail = ui.available_size();
    if files.is_empty() {
        ui.allocate_space(Vec2::new(avail.x, (avail.y * 0.35).max(20.0)));
        ui.vertical_centered(|ui| {
            ui.heading(format!("📂 Cartella '{scope_dir}' vuota"));
            ui.label("Importa file, usa la vista '🪟 Dual-Pane (PC ⟷ USB)' o rilascia file con Drag & Drop per popolare il grafico.");
        });
        return None;
    }

    let canvas_size = Vec2::new(avail.x.max(200.0), avail.y.max(140.0));
    let (response, painter) = ui.allocate_painter(canvas_size, Sense::click());
    let canvas_rect = response.rect;

    let mut nodes = Vec::with_capacity(files.len());
    compute_bsp_treemap(files, canvas_rect, &mut nodes);

    let pointer_pos = response.hover_pos();
    let mut hovered_node: Option<&TreemapRect> = None;
    let mut clicked_entry: Option<FileEntry> = None;
    let total_orig: u64 = files.iter().map(|f| f.original_size).sum();

    for node in &nodes {
        let inner = node.rect.shrink(2.0);
        if inner.width() <= 0.5 || inner.height() <= 0.5 {
            continue;
        }

        let is_hovered = pointer_pos.map_or(false, |p| inner.contains(p));
        let (_, base_color) = classify_file_color(&node.entry.virtual_path);

        let fill = if is_hovered {
            Color32::from_rgb(
                base_color.r().saturating_add(30),
                base_color.g().saturating_add(30),
                base_color.b().saturating_add(30),
            )
        } else {
            base_color
        };

        let stroke = if is_hovered {
            Stroke::new(2.5, Color32::WHITE)
        } else {
            Stroke::new(1.5, Color32::from_rgb(15, 23, 42))
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
            ui.colored_label(
                Color32::from_rgb(16, 185, 129),
                "🖱️ Clicca per aprire immediatamente il file in RAM (Testo, PDF, Immagine o Hex Inspector)",
            );
        });
    }

    clicked_entry
}
