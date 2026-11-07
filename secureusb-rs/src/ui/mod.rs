pub mod preview;

use crate::usb::{detect_usb_drives, format_physical_usb, UsbDriveInfo};
use crate::vault::{
    should_ignore_entry, FileEntry, SecureVault, VaultStats, MAX_TEXT_PREVIEW_SIZE,
};
use eframe::egui;
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub fn run_app() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 760.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "🔐 SecureUSB Explorer (Rust) — SVAULT03 • Dual-Vault • BLAKE3 Dedup • Reed-Solomon ECC",
        options,
        Box::new(|cc| {
            apply_cyber_dark_theme(&cc.egui_ctx);
            Ok(Box::new(SecureUsbApp::new()))
        }),
    )
}

fn apply_cyber_dark_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(15, 23, 42);
    visuals.window_fill = egui::Color32::from_rgb(30, 41, 59);
    visuals.extreme_bg_color = egui::Color32::from_rgb(10, 15, 28);
    visuals.selection.bg_fill = egui::Color32::from_rgb(16, 185, 129);
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, egui::Color32::WHITE);
    ctx.set_visuals(visuals);
}

enum BgTaskOutcome {
    Unlocked(io::Result<Arc<SecureVault>>),
    Message(String),
}

use std::io;

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
    show_shadow_modal: bool,
    shadow_pwd_input: String,
    busy_title: Option<String>,
    busy_rx: Option<Receiver<BgTaskOutcome>>,
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
            show_shadow_modal: false,
            shadow_pwd_input: String::new(),
            busy_title: None,
            busy_rx: None,
        }
    }

    fn spawn_busy_task<F>(&mut self, title: impl Into<String>, task: F)
    where
        F: FnOnce() -> BgTaskOutcome + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        self.busy_title = Some(title.into());
        self.busy_rx = Some(rx);
        thread::spawn(move || {
            let _ = tx.send(task());
        });
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

        let read_res = if !entry.chunk_refs.is_empty() {
            v.read_dedup_file(&entry.virtual_path)
        } else {
            v.read_file(&entry.virtual_path)
        };

        if let Ok(bytes) = read_res {
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
        // 1. Controlla se un'operazione asincrona con Spinner è terminata
        if let Some(rx) = &self.busy_rx {
            if let Ok(outcome) = rx.try_recv() {
                self.busy_title = None;
                self.busy_rx = None;
                match outcome {
                    BgTaskOutcome::Unlocked(Ok(v)) => {
                        let mode = if v.is_shadow_session() {
                            "🕵️ Sessione SHADOW VAULT (Nascosta) sbloccata!"
                        } else {
                            "✅ Sessione Vault Primario sbloccata!"
                        };
                        self.status_msg = mode.to_string();
                        self.vault = Some(v);
                        self.current_dir = "/".to_string();
                        self.password.clear();
                        self.refresh_dir();
                    }
                    BgTaskOutcome::Unlocked(Err(e)) => {
                        self.status_msg = format!("❌ Errore: {e}");
                    }
                    BgTaskOutcome::Message(msg) => {
                        self.status_msg = msg;
                        self.refresh_dir();
                    }
                }
            } else {
                ctx.request_repaint();
            }
        }

        // 2. Disegna il Modal di Caricamento con Spinner quando busy_title è attivo
        if let Some(title) = &self.busy_title {
            egui::Window::new("⏳ Operazione Crittografica in Corso")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.heading(title);
                    });
                    ui.label("Elaborazione Multi-Core (Argon2id / BLAKE3 / Reed-Solomon GF(256) / XChaCha20)...");
                });
        }

        if self.last_usb_scan.elapsed() >= Duration::from_millis(2500) {
            self.last_usb_scan = Instant::now();
            if let Some(v) = &self.vault {
                if !v.is_mount_alive() {
                    self.vault = None;
                    self.entries.clear();
                    self.preview = PreviewState::None;
                    self.status_msg = "🔒 Chiavetta USB rimossa: chiave azzerata in RAM!".to_string();
                }
            } else {
                self.detected_drives = detect_usb_drives();
            }
        }

        if self.vault.is_none() {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("🔐 Sblocco e Gestione Chiavetta Cifrata (SVAULT03 + Shadow Vault + ECC)");
                ui.label("Inserisci la Password Primaria per aprire il Vault standard oppure la Password Segreta per aprire lo Shadow Vault.");
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
                        ui.label("Password (Primaria o Shadow):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .password(true)
                                .desired_width(320.0),
                        );
                    });

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔓 Sblocca Vault (Auto-Slot + ECC Heal)").clicked() && self.busy_rx.is_none() {
                            let path = self.usb_path.clone();
                            let pass = self.password.clone();
                            self.spawn_busy_task("Sblocco Vault e Verifica Reed-Solomon ECC...", move || {
                                BgTaskOutcome::Unlocked(SecureVault::init_or_open(path, &pass, false))
                            });
                        }
                        if ui.button("✨ Inizializza Nuovo Vault Dual-Slot").clicked() && self.busy_rx.is_none() {
                            let path = self.usb_path.clone();
                            let pass = self.password.clone();
                            self.spawn_busy_task("Inizializzazione Dual-Slot + Shadow Index + Parità ECC...", move || {
                                BgTaskOutcome::Unlocked(SecureVault::init_or_open(path, &pass, true))
                            });
                        }
                    });
                });

                ui.add_space(12.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.heading("🛠️ Formattazione Hardware USB in exFAT");
                    ui.horizontal(|ui| {
                        ui.label("Dispositivo (es. E:, /dev/sdb1, /dev/disk2):");
                        ui.text_edit_singleline(&mut self.raw_device);
                        if ui.button("Formatta in exFAT").clicked() {
                            match format_physical_usb(&self.raw_device, "SECURE_USB") {
                                Ok(()) => self.status_msg = "✅ Formattazione exFAT completata!".to_string(),
                                Err(e) => self.status_msg = format!("Errore: {e}"),
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

        if self.show_shadow_modal {
            egui::Window::new("🕵️ Plausible Deniability — Configura Secondo Vault Nascosto")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Imposta una seconda password segreta per attivare lo Slot 1 e index.shadow:");
                    ui.horizontal(|ui| {
                        ui.label("Password Segreta Shadow:");
                        ui.add(egui::TextEdit::singleline(&mut self.shadow_pwd_input).password(true));
                    });
                    ui.horizontal(|ui| {
                        if ui.button("✅ Attiva Shadow Vault").clicked() && self.busy_rx.is_none() {
                            if let Some(v) = self.vault.clone() {
                                let spw = self.shadow_pwd_input.clone();
                                self.show_shadow_modal = false;
                                self.shadow_pwd_input.clear();
                                self.spawn_busy_task("Configurazione Shadow Vault (Slot 1 + ECC)...", move || {
                                    match v.configure_shadow_vault(&spw) {
                                        Ok(()) => BgTaskOutcome::Message("🕵️ Shadow Vault configurato con successo!".to_string()),
                                        Err(e) => BgTaskOutcome::Message(format!("❌ Errore Shadow Vault: {e}")),
                                    }
                                });
                            }
                        }
                        if ui.button("Annulla").clicked() {
                            self.shadow_pwd_input.clear();
                            self.show_shadow_modal = false;
                        }
                    });
                });
        }

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

                ui.add(egui::TextEdit::singleline(&mut self.new_item_name).hint_text("Nome nuovo...").desired_width(105.0));
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

                if ui.button("📥 Importa Dedup (BLAKE3)").clicked() && self.busy_rx.is_none() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        if !should_ignore_entry(&path) {
                            if let (Some(v), Ok(f)) = (self.vault.clone(), File::open(&path)) {
                                let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                let target = format!("{}/{}", self.current_dir, fname);
                                self.spawn_busy_task(format!("Deduplicazione BLAKE3 e Cifratura di {fname}..."), move || {
                                    match v.write_stream_dedup(&target, f) {
                                        Ok(hits) => BgTaskOutcome::Message(format!("✅ Importato {fname} ({hits} chunk da 4MB deduplicati con BLAKE3)!")),
                                        Err(e) => BgTaskOutcome::Message(format!("❌ Errore import: {e}")),
                                    }
                                });
                            }
                        }
                    }
                }

                if ui.button("📁📥 Importa Cartella").clicked() && self.busy_rx.is_none() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        if let Some(v) = self.vault.clone() {
                            let cur = self.current_dir.clone();
                            self.spawn_busy_task("Importazione Ricorsiva Cartella Multi-Core...", move || {
                                match v.import_dir(&folder, &cur) {
                                    Ok(cnt) => BgTaskOutcome::Message(format!("✅ Importati {cnt} file dalla cartella!")),
                                    Err(e) => BgTaskOutcome::Message(format!("❌ Errore: {e}")),
                                }
                            });
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

                if ui.button("🕵️ Shadow Vault").clicked() {
                    self.show_shadow_modal = true;
                }

                if ui.button("🛡️ Scrub Poly1305").clicked() && self.busy_rx.is_none() {
                    if let Some(v) = self.vault.clone() {
                        self.spawn_busy_task("Verifica Integrità Globale Poly1305 + Reed-Solomon...", move || {
                            let rep = v.scrub_integrity();
                            if rep.corrupted_files.is_empty() {
                                BgTaskOutcome::Message(format!(
                                    "✅ Integrità 100%: {} file ({} chunk) verificati!",
                                    rep.total_files, rep.verified_chunks
                                ))
                            } else {
                                BgTaskOutcome::Message(format!("❌ Corrotti: {:?}", rep.corrupted_files))
                            }
                        });
                    }
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
            ui.horizontal(|ui| {
                let mode_badge = if self
                    .vault
                    .as_ref()
                    .map(|v| v.is_shadow_session())
                    .unwrap_or(false)
                {
                    "🕵️ [SHADOW VAULT ATTIVO]"
                } else {
                    "🔐 [VAULT PRIMARIO]"
                };
                ui.strong(mode_badge);
                ui.label(format!("Percorso: {}", self.current_dir));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.search_query)
                            .hint_text("🔍 Cerca istantaneamente in RAM...")
                            .desired_width(250.0),
                    );
                    if resp.changed() {
                        self.refresh_dir();
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("telemetry_footer").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "📊 File: {} | Cartelle: {} | Reale: {} ➔ Su USB: {} | ECC Reed-Solomon GF(256) Attivo",
                    self.stats.total_files,
                    self.stats.total_folders,
                    format_bytes(self.stats.original_size),
                    format_bytes(self.stats.disk_size),
                ));
                if !self.status_msg.is_empty() {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, &self.status_msg);
                }
            });
        });

        egui::SidePanel::left("file_list")
            .resizable(true)
            .default_width(400.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let entries_clone = self.entries.clone();
                    for e in entries_clone {
                        let name = Path::new(&e.virtual_path)
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| e.virtual_path.clone());
                        let label = if e.is_dir {
                            format!("📁 {name}/")
                        } else {
                            format!("📄 {name} ({} ➔ {})", format_bytes(e.original_size), format_bytes(e.disk_size))
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
                ui.label("Seleziona un file dalla lista o usa 'Importa Dedup (BLAKE3)' / 'Shadow Vault'.");
            }
            PreviewState::Text { path, content } => {
                ui.horizontal(|ui| {
                    ui.heading(format!("📝 Editor Testo: {path}"));
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
            PreviewState::Image { path, texture, dims } => {
                ui.heading(format!("🖼️ Immagine RAM: {path} ({}x{} px)", dims.0, dims.1));
                ui.image((texture.id(), ui.available_size()));
            }
            PreviewState::Pdf { path, pages, current_page } => {
                ui.horizontal(|ui| {
                    ui.heading(format!("📕 PDF RAM: {path} (Pag. {}/{})", *current_page + 1, pages.len()));
                    if ui.button("◀").clicked() && *current_page > 0 {
                        *current_page -= 1;
                    }
                    if ui.button("▶").clicked() && *current_page + 1 < pages.len() {
                        *current_page += 1;
                    }
                });
                let mut page_txt = pages[*current_page].clone();
                ui.add(egui::TextEdit::multiline(&mut page_txt).desired_width(f32::INFINITY).desired_rows(28));
            }
            PreviewState::LargeFile { path, size, chunks } => {
                ui.heading(format!("🎬 File Multimediale: {path} ({}, {chunks} chunk)", format_bytes(*size)));
            }
        });

        if let Some((path, data)) = save_target {
            if let Some(v) = &self.vault {
                let _ = v.write_file(&path, &data);
            }
            self.refresh_dir();
        }
    }
}
