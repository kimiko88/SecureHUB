pub mod preview;

use crate::usb::{detect_usb_drives, format_physical_usb, UsbDriveInfo};
use crate::vault::{
    should_ignore_entry, FileEntry, SecureVault, VaultStats, MAX_TEXT_PREVIEW_SIZE,
};
use eframe::egui;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn run_app() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1260.0, 760.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "🔐 SecureUSB Explorer (Rust) — SVAULT03 • Auto-USB • KeyWrap • Rayon SIMD",
        options,
        Box::new(|cc| {
            apply_cyber_dark_theme(&cc.egui_ctx);
            Ok(Box::new(SecureUsbApp::new()))
        }),
    )
}

fn apply_cyber_dark_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(15, 23, 42); // Slate 900
    visuals.window_fill = egui::Color32::from_rgb(30, 41, 59); // Slate 800
    visuals.extreme_bg_color = egui::Color32::from_rgb(10, 15, 28);
    visuals.selection.bg_fill = egui::Color32::from_rgb(16, 185, 129); // Emerald accent
    visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    ctx.set_visuals(visuals);
}

enum PreviewState {
    None,
    Text { path: String, content: String },
    Image {
        path: String,
        texture: egui::TextureHandle,
        dims: (usize, usize),
    },
    Pdf {
        path: String,
        pages: Vec<String>,
        current_page: usize,
    },
    LargeFile { path: String, size: u64, chunks: usize },
}

impl Default for PreviewState {
    fn default() -> Self {
        Self::None
    }
}

struct SecureUsbApp {
    detected_drives: Vec<UsbDriveInfo>,
    last_usb_scan: Instant,
    usb_path: String,
    password: String,
    raw_device: String,
    status_msg: String,
    vault: Option<Arc<SecureVault>>,
    current_dir: String,
    search_query: String,
    entries: Vec<FileEntry>,
    stats: VaultStats,
    selected_path: Option<String>,
    selected_is_dir: bool,
    preview: PreviewState,
    new_item_name: String,
    show_pwd_modal: bool,
    old_pwd_input: String,
    new_pwd_input: String,
}

impl SecureUsbApp {
    fn new() -> Self {
        let drives = detect_usb_drives();
        let initial_path = drives
            .first()
            .map(|d| d.mount_path.clone())
            .unwrap_or_default();
        Self {
            detected_drives: drives,
            last_usb_scan: Instant::now(),
            usb_path: initial_path,
            password: String::new(),
            raw_device: String::new(),
            status_msg: String::new(),
            vault: None,
            current_dir: "/".to_string(),
            search_query: String::new(),
            entries: Vec::new(),
            stats: VaultStats::default(),
            selected_path: None,
            selected_is_dir: false,
            preview: PreviewState::None,
            new_item_name: String::new(),
            show_pwd_modal: false,
            old_pwd_input: String::new(),
            new_pwd_input: String::new(),
        }
    }

    fn refresh_dir(&mut self) {
        if let Some(v) = &self.vault {
            if self.current_dir.is_empty() {
                self.current_dir = "/".to_string();
            }
            self.stats = v.stats();
            if self.search_query.trim().is_empty() {
                self.entries = v.list_dir(&self.current_dir);
            } else {
                self.entries = v.search(&self.search_query);
            }
        }
    }

    fn select_entry(&mut self, ctx: &egui::Context, entry: &FileEntry) {
        self.selected_path = Some(entry.virtual_path.clone());
        self.selected_is_dir = entry.is_dir;

        if entry.is_dir {
            self.search_query.clear();
            self.current_dir = entry.virtual_path.clone();
            self.preview = PreviewState::None;
            self.refresh_dir();
            return;
        }

        let Some(v) = &self.vault else { return };

        if preview::is_image_ext(&entry.virtual_path) {
            if let Ok((tex, dims)) = preview::load_image_texture_in_ram(ctx, v, &entry.virtual_path) {
                self.preview = PreviewState::Image {
                    path: entry.virtual_path.clone(),
                    texture: tex,
                    dims,
                };
                return;
            }
        }

        if preview::is_pdf_ext(&entry.virtual_path) && entry.original_size <= 64 * 1024 * 1024 {
            if let Ok(pages) = preview::extract_pdf_pages_in_ram(v, &entry.virtual_path) {
                self.preview = PreviewState::Pdf {
                    path: entry.virtual_path.clone(),
                    pages,
                    current_page: 0,
                };
                return;
            }
        }

        if entry.original_size > MAX_TEXT_PREVIEW_SIZE {
            self.preview = PreviewState::LargeFile {
                path: entry.virtual_path.clone(),
                size: entry.original_size,
                chunks: entry.chunk_sizes.len(),
            };
            return;
        }

        if let Ok(bytes) = v.read_file(&entry.virtual_path) {
            if let Ok(txt) = String::from_utf8(bytes) {
                self.preview = PreviewState::Text {
                    path: entry.virtual_path.clone(),
                    content: txt,
                };
            } else {
                self.preview = PreviewState::LargeFile {
                    path: entry.virtual_path.clone(),
                    size: entry.original_size,
                    chunks: entry.chunk_sizes.len(),
                };
            }
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }

        if self.vault.is_none() {
            if let Some(first_path) = dropped.first().and_then(|d| d.path.as_ref()) {
                self.usb_path = first_path.display().to_string();
            }
            return;
        }

        let Some(v) = self.vault.clone() else { return };
        let cur_dir = if self.current_dir.is_empty() {
            "/".to_string()
        } else {
            self.current_dir.clone()
        };

        let mut total_imported = 0usize;
        for df in dropped {
            let Some(path) = df.path else { continue };
            if should_ignore_entry(&path) {
                continue;
            }
            if path.is_dir() {
                match v.import_dir(&path, &cur_dir) {
                    Ok(cnt) => total_imported += cnt,
                    Err(e) => self.status_msg = format!("Errore Drag & Drop cartella: {e}"),
                }
            } else if path.is_file() {
                if let Ok(f) = File::open(&path) {
                    let fname = path.file_name().unwrap_or_default().to_string_lossy();
                    let target = format!("{cur_dir}/{fname}");
                    match v.write_stream(&target, f) {
                        Ok(()) => total_imported += 1,
                        Err(e) => self.status_msg = format!("Errore Drag & Drop file: {e}"),
                    }
                }
            }
        }

        self.status_msg = format!(
            "✅ Drag & Drop: {total_imported} file cifrati in '{cur_dir}'!"
        );
        self.refresh_dir();
    }
}

fn estimate_entropy_bits(pw: &str) -> f32 {
    if pw.is_empty() {
        return 0.0;
    }
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut sym = false;
    for ch in pw.chars() {
        if ch.is_ascii_lowercase() {
            lower = true;
        } else if ch.is_ascii_uppercase() {
            upper = true;
        } else if ch.is_ascii_digit() {
            digit = true;
        } else {
            sym = true;
        }
    }
    let mut pool = 0.0f32;
    if lower {
        pool += 26.0;
    }
    if upper {
        pool += 26.0;
    }
    if digit {
        pool += 10.0;
    }
    if sym {
        pool += 32.0;
    }
    (pw.chars().count() as f32) * pool.log2()
}

fn format_bytes(b: u64) -> String {
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

impl eframe::App for SecureUsbApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_dropped_files(ctx);

        // Hot-Plug polling & Watchdog anti-rimozione USB ogni 2.5 secondi
        if self.last_usb_scan.elapsed() >= Duration::from_millis(2500) {
            self.last_usb_scan = Instant::now();
            if let Some(v) = &self.vault {
                if !v.is_mount_alive() {
                    self.vault = None; // Zeroize immediato della MasterKey in RAM!
                    self.entries.clear();
                    self.preview = PreviewState::None;
                    self.status_msg = "🔒 Blocco di emergenza: chiavetta USB rimossa, chiave azzerata in RAM!".to_string();
                }
            } else {
                self.detected_drives = detect_usb_drives();
                if self.usb_path.is_empty() {
                    if let Some(first) = self.detected_drives.first() {
                        self.usb_path = first.mount_path.clone();
                    }
                }
            }
        }

        let is_hovering_files = !ctx.input(|i| i.raw.hovered_files.is_empty());
        if is_hovering_files {
            egui::Area::new(egui::Id::new("drag_drop_banner"))
                .fixed_pos(egui::pos2(320.0, 260.0))
                .show(ctx, |ui| {
                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                        ui.heading("📥 Rilascia qui file o cartelle per importarli in SVAULT03");
                        ui.label("I file temporanei (.DS_Store, Thumbs.db, desktop.ini, *.tmp) vengono filtrati in automatico.");
                    });
                });
        }

        // Schermata di Sblocco con Auto-Detection USB
        if self.vault.is_none() {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("🔐 Sblocco e Gestione Chiavetta Cifrata (Rust SVAULT03)");
                ui.label("Rilevamento Automatico USB • Argon2id • XChaCha20-Poly1305 In-Place SIMD • Zstd Adattivo");
                ui.add_space(10.0);

                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong("🔌 Unità USB Rilevate:");
                        egui::ComboBox::from_id_salt("usb_selector")
                            .selected_text(if self.usb_path.is_empty() {
                                "Seleziona chiavetta USB..."
                            } else {
                                &self.usb_path
                            })
                            .width(420.0)
                            .show_ui(ui, |ui| {
                                for d in &self.detected_drives {
                                    if ui
                                        .selectable_label(self.usb_path == d.mount_path, &d.label)
                                        .clicked()
                                    {
                                        self.usb_path = d.mount_path.clone();
                                    }
                                }
                            });

                        if ui.button("🔄 Aggiorna USB").clicked() {
                            self.detected_drives = detect_usb_drives();
                            if let Some(first) = self.detected_drives.first() {
                                self.usb_path = first.mount_path.clone();
                            }
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Percorso USB:");
                        ui.add(egui::TextEdit::singleline(&mut self.usb_path).desired_width(420.0));
                        if ui.button("📂 Sfoglia...").clicked() {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                self.usb_path = folder.display().to_string();
                            }
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Password Master:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .password(true)
                                .desired_width(320.0),
                        );
                        let bits = estimate_entropy_bits(&self.password);
                        ui.add(
                            egui::ProgressBar::new((bits / 128.0).clamp(0.0, 1.0))
                                .text(format!("Entropia: {bits:.0} bit"))
                                .desired_width(180.0),
                        );
                    });

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔓 Sblocca Vault Esistente").clicked() {
                            match SecureVault::init_or_open(&self.usb_path, &self.password, false) {
                                Ok(v) => {
                                    self.vault = Some(v);
                                    self.current_dir = "/".to_string();
                                    self.password.clear();
                                    self.refresh_dir();
                                }
                                Err(e) => self.status_msg = format!("Errore: {e}"),
                            }
                        }
                        if ui.button("✨ Inizializza Nuovo Vault (SVAULT03)").clicked() {
                            match SecureVault::init_or_open(&self.usb_path, &self.password, true) {
                                Ok(v) => {
                                    self.vault = Some(v);
                                    self.current_dir = "/".to_string();
                                    self.password.clear();
                                    self.refresh_dir();
                                }
                                Err(e) => self.status_msg = format!("Errore: {e}"),
                            }
                        }
                    });
                });

                ui.add_space(12.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.heading("🛠️ Formattazione Hardware USB in exFAT (Windows / Linux / macOS)");
                    ui.horizontal(|ui| {
                        ui.label("Dispositivo (es. E:, /dev/sdb1, /dev/disk2):");
                        ui.text_edit_singleline(&mut self.raw_device);
                        if ui.button("Formatta in exFAT").clicked() {
                            match format_physical_usb(&self.raw_device, "SECURE_USB") {
                                Ok(()) => {
                                    self.detected_drives = detect_usb_drives();
                                    self.status_msg = "✅ Formattazione exFAT completata!".to_string();
                                }
                                Err(e) => self.status_msg = format!("Errore formattazione: {e}"),
                            }
                        }
                    });
                });

                if !self.status_msg.is_empty() {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::LIGHT_GREEN, &self.status_msg);
                }
            });
            return;
        }

        // Finestra Modale per Cambio Password Istantaneo (Key Wrapping)
        if self.show_pwd_modal {
            egui::Window::new("🔑 Cambio Password Istantaneo (Key Wrapping)")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("La Data Encryption Key (DEK) verrà ri-avvolta senza ricifrare i file:");
                    ui.horizontal(|ui| {
                        ui.label("Password Attuale:");
                        ui.add(egui::TextEdit::singleline(&mut self.old_pwd_input).password(true));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Nuova Password:");
                        ui.add(egui::TextEdit::singleline(&mut self.new_pwd_input).password(true));
                    });
                    ui.horizontal(|ui| {
                        if ui.button("✅ Aggiorna Password").clicked() {
                            if let Some(v) = &self.vault {
                                match v.change_password(&self.old_pwd_input, &self.new_pwd_input) {
                                    Ok(()) => {
                                        self.status_msg = "✅ Password aggiornata istantaneamente tramite Key Wrapping!".to_string();
                                        self.show_pwd_modal = false;
                                    }
                                    Err(e) => self.status_msg = format!("❌ Errore cambio password: {e}"),
                                }
                            }
                            self.old_pwd_input.clear();
                            self.new_pwd_input.clear();
                        }
                        if ui.button("Annulla").clicked() {
                            self.old_pwd_input.clear();
                            self.new_pwd_input.clear();
                            self.show_pwd_modal = false;
                        }
                    });
                });
        }

        // Barra Superiore (Azioni + Breadcrumbs Interattivi + Ricerca Istantanea RAM)
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("⬆ Su").clicked() && self.current_dir != "/" {
                    let parent = Path::new(&self.current_dir)
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    self.current_dir = if parent.is_empty() { "/".to_string() } else { parent };
                    self.refresh_dir();
                }

                ui.add(egui::TextEdit::singleline(&mut self.new_item_name).hint_text("Nome nuovo...").desired_width(110.0));
                if ui.button("📁 +Cartella").clicked() && !self.new_item_name.trim().is_empty() {
                    if let Some(v) = self.vault.clone() {
                        let target = format!("{}/{}", self.current_dir, self.new_item_name.trim());
                        let _ = v.create_dir(&target);
                        self.new_item_name.clear();
                        self.refresh_dir();
                    }
                }
                if ui.button("📄 +Testo").clicked() && !self.new_item_name.trim().is_empty() {
                    if let Some(v) = self.vault.clone() {
                        let target = format!("{}/{}", self.current_dir, self.new_item_name.trim());
                        let _ = v.write_file(&target, b"");
                        self.new_item_name.clear();
                        self.refresh_dir();
                    }
                }

                if ui.button("📥 Importa File").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        if !should_ignore_entry(&path) {
                            if let (Some(v), Ok(f)) = (self.vault.clone(), File::open(&path)) {
                                let fname = path.file_name().unwrap_or_default().to_string_lossy();
                                let target = format!("{}/{}", self.current_dir, fname);
                                if let Err(e) = v.write_stream(&target, f) {
                                    self.status_msg = format!("Errore import: {e}");
                                }
                                self.refresh_dir();
                            }
                        }
                    }
                }

                if ui.button("📁📥 Importa Cartella").clicked() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        if let Some(v) = self.vault.clone() {
                            match v.import_dir(&folder, &self.current_dir) {
                                Ok(count) => {
                                    self.status_msg = format!("✅ Importati {count} file dalla cartella!");
                                    self.refresh_dir();
                                }
                                Err(e) => self.status_msg = format!("Errore import cartella: {e}"),
                            }
                        }
                    }
                }

                if ui.button("▶ Stream Video O(1)").clicked() {
                    if let (Some(v), Some(sel)) = (&self.vault, &self.selected_path) {
                        if let Ok(url) = v.get_stream_url(sel) {
                            let _ = open::that(url);
                        }
                    }
                }

                if ui.button("📤 Esporta File").clicked() {
                    if let (Some(v), Some(sel)) = (&self.vault, &self.selected_path) {
                        if !self.selected_is_dir {
                            if let Some(dest) = rfd::FileDialog::new().save_file() {
                                if let Ok(out) = File::create(dest) {
                                    let _ = v.read_stream(sel, BufWriter::new(out));
                                }
                            }
                        }
                    }
                }

                if ui.button("📁📤 Esporta Cartella").clicked() {
                    if let Some(dest_folder) = rfd::FileDialog::new().pick_folder() {
                        if let Some(v) = self.vault.clone() {
                            let target_dir = if self.selected_is_dir {
                                self.selected_path.clone().unwrap_or_else(|| self.current_dir.clone())
                            } else {
                                self.current_dir.clone()
                            };
                            match v.export_dir(&target_dir, &dest_folder) {
                                Ok(count) => {
                                    self.status_msg = format!(
                                        "✅ Esportati {count} file da '{target_dir}' in '{}'!",
                                        dest_folder.display()
                                    );
                                }
                                Err(e) => self.status_msg = format!("Errore export cartella: {e}"),
                            }
                        }
                    }
                }

                if ui.button("🛡️ Scrub Poly1305").clicked() {
                    if let Some(v) = self.vault.clone() {
                        let rep = v.scrub_integrity();
                        if rep.corrupted_files.is_empty() {
                            self.status_msg = format!(
                                "✅ Integrità 100%: {} file ({} chunk, {}) verificati senza errori!",
                                rep.total_files,
                                rep.verified_chunks,
                                format_bytes(rep.verified_bytes)
                            );
                        } else {
                            self.status_msg = format!(
                                "❌ Rilevati {} file corrotti: {:?}",
                                rep.corrupted_files.len(),
                                rep.corrupted_files
                            );
                        }
                    }
                }

                if ui.button("🔑 Password").clicked() {
                    self.show_pwd_modal = true;
                }

                if ui.button("🗑 Elimina").clicked() {
                    if let (Some(v), Some(sel)) = (self.vault.clone(), self.selected_path.clone()) {
                        let _ = v.delete(&sel);
                        self.selected_path = None;
                        self.preview = PreviewState::None;
                        self.refresh_dir();
                    }
                }

                if ui.button("🔒 Blocca").clicked() {
                    self.vault = None;
                    self.entries.clear();
                    self.preview = PreviewState::None;
                }
            });

            ui.separator();

            // Barra Breadcrumb Interattiva + Barra di Ricerca Istantanea in RAM
            let mut jump_dir: Option<String> = None;
            ui.horizontal(|ui| {
                if ui.button("🏠 / Root").clicked() {
                    jump_dir = Some("/".to_string());
                }
                if self.current_dir != "/" {
                    let mut accum = String::new();
                    for seg in self.current_dir.trim_matches('/').split('/') {
                        accum.push('/');
                        accum.push_str(seg);
                        let target = accum.clone();
                        ui.label("❯");
                        if ui.button(seg).clicked() {
                            jump_dir = Some(target);
                        }
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !self.search_query.is_empty() && ui.button("✖").clicked() {
                        self.search_query.clear();
                        self.refresh_dir();
                    }
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.search_query)
                            .hint_text("🔍 Cerca istantaneamente in RAM...")
                            .desired_width(260.0),
                    );
                    if resp.changed() {
                        self.refresh_dir();
                    }
                });
            });

            if let Some(jd) = jump_dir {
                self.search_query.clear();
                self.current_dir = jd;
                self.refresh_dir();
            }
        });

        // Barra Telemetrica Inferiore (Statistiche Spazio e Risparmio Compressione Zstd)
        egui::TopBottomPanel::bottom("telemetry_footer").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let saved = self.stats.original_size.saturating_sub(self.stats.disk_size);
                let pct = if self.stats.original_size > 0 {
                    (saved as f32 / self.stats.original_size as f32) * 100.0
                } else {
                    0.0
                };
                ui.label(format!(
                    "📊 Vault: {} File, {} Cartelle ({} Chunk 4MB)  |  Reale: {}  ➔  Su USB (Zstd+AEAD): {}",
                    self.stats.total_files,
                    self.stats.total_folders,
                    self.stats.total_chunks,
                    format_bytes(self.stats.original_size),
                    format_bytes(self.stats.disk_size),
                ));
                ui.add(
                    egui::ProgressBar::new((pct / 100.0).clamp(0.0, 1.0))
                        .text(format!("Risparmio Zstd: {pct:.1}%"))
                        .desired_width(180.0),
                );
                if !self.status_msg.is_empty() {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, &self.status_msg);
                }
            });
        });

        egui::SidePanel::left("file_list")
            .resizable(true)
            .default_width(410.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let entries_clone = self.entries.clone();
                    let is_searching = !self.search_query.trim().is_empty();
                    for e in entries_clone {
                        let name = if is_searching {
                            e.virtual_path.clone()
                        } else {
                            Path::new(&e.virtual_path)
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_else(|| e.virtual_path.clone())
                        };
                        let label = if e.is_dir {
                            format!("📁 {name}/")
                        } else {
                            let ratio = if e.original_size > 0 {
                                (e.disk_size as f64 / e.original_size as f64) * 100.0
                            } else {
                                100.0
                            };
                            format!(
                                "📄 {name}  ({} ➔ {} | {:.0}%)",
                                format_bytes(e.original_size),
                                format_bytes(e.disk_size),
                                ratio
                            )
                        };
                        let is_sel = self.selected_path.as_deref() == Some(&e.virtual_path);
                        if ui.selectable_label(is_sel, label).clicked() {
                            self.select_entry(ctx, &e);
                        }
                    }
                });
            });

        let mut save_target: Option<(String, Vec<u8>)> = None;

        egui::CentralPanel::default().show(ctx, |ui| match &mut self.preview {
            PreviewState::None => {
                ui.label("Seleziona un file dalla lista o trascina file/cartelle dal computer dentro questa finestra.");
            }
            PreviewState::Text { path, content } => {
                ui.horizontal(|ui| {
                    ui.heading(format!("📝 Editor Testo in RAM: {path}"));
                    if ui.button("💾 Salva Modifiche").clicked() {
                        save_target = Some((path.clone(), content.as_bytes().to_vec()));
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(content)
                            .desired_width(f32::INFINITY)
                            .desired_rows(28),
                    );
                });
            }
            PreviewState::Image {
                path,
                texture,
                dims,
            } => {
                ui.heading(format!(
                    "🖼️ Visualizzatore Immagini RAM (Zero-Temp): {path} ({}x{} px)",
                    dims.0, dims.1
                ));
                ui.separator();
                ui.image((texture.id(), ui.available_size()));
            }
            PreviewState::Pdf {
                path,
                pages,
                current_page,
            } => {
                ui.horizontal(|ui| {
                    ui.heading(format!(
                        "📕 Visualizzatore PDF RAM: {path} (Pagina {} di {})",
                        *current_page + 1,
                        pages.len()
                    ));
                    if ui.button("◀ Prec").clicked() && *current_page > 0 {
                        *current_page -= 1;
                    }
                    if ui.button("Succ ▶").clicked() && *current_page + 1 < pages.len() {
                        *current_page += 1;
                    }
                });
                ui.separator();
                let mut page_txt = pages[*current_page].clone();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut page_txt)
                            .desired_width(f32::INFINITY)
                            .desired_rows(28),
                    );
                });
            }
            PreviewState::LargeFile { path, size, chunks } => {
                ui.heading(format!("🎬 File Multimediale / Grande: {path}"));
                ui.label(format!(
                    "Dimensione: {} suddivisi in {chunks} chunk indipendenti da 4 MB.",
                    format_bytes(*size)
                ));
                ui.label("Clicca '▶ Stream Video O(1)' nella barra superiore per riprodurlo immediatamente senza file temporanei.");
            }
        });

        if let Some((path, data)) = save_target {
            if let Some(v) = &self.vault {
                let _ = v.write_file(&path, &data);
                self.status_msg = format!("✅ Salvato {path} in SVAULT03!");
            }
            self.refresh_dir();
        }
    }
}
