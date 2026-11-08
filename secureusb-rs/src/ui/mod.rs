pub mod preview;
pub mod treemap;

use crate::usb::{detect_usb_drives, format_physical_usb, UsbDriveInfo};
use crate::vault::{
    should_ignore_entry, FileEntry, SecureVault, VaultStats, MAX_TEXT_PREVIEW_SIZE,
};
use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub fn run_app() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1340.0, 800.0])
            .with_min_inner_size([960.0, 620.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "🔐 SecureUSB Explorer (Rust) — SVAULT03 • Interactive Treemap • Dual-Vault • BLAKE3 • ECC",
        options,
        Box::new(|cc| {
            apply_cyber_dark_theme(&cc.egui_ctx);
            Ok(Box::new(SecureUsbApp::new()))
        }),
    )
}

fn apply_cyber_dark_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 7.0);
    style.spacing.window_margin = egui::Margin::same(12.0);
    style.spacing.button_padding = Vec2::new(10.0, 6.0);
    ctx.set_style(style);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Color32::from_rgb(15, 23, 42); // Slate 900
    visuals.window_fill = Color32::from_rgb(30, 41, 59); // Slate 800
    visuals.extreme_bg_color = Color32::from_rgb(9, 14, 26);
    visuals.selection.bg_fill = Color32::from_rgb(16, 185, 129); // Emerald 500
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, Color32::WHITE);
    ctx.set_visuals(visuals);
}

enum BgTaskOutcome {
    Unlocked(io::Result<Arc<SecureVault>>),
    Message(String),
}

enum PreviewState {
    Treemap,
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
        Self::Treemap
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
    treemap_files: Vec<FileEntry>,
    stats: VaultStats,
    selected_path: Option<String>,
    selected_is_dir: bool,
    preview: PreviewState,
    new_item_name: String,
    show_pwd_modal: bool,
    old_pwd_input: String,
    new_pwd_input: String,
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
            treemap_files: Vec::new(),
            stats: VaultStats::default(),
            selected_path: None,
            selected_is_dir: false,
            preview: PreviewState::Treemap,
            new_item_name: String::new(),
            show_pwd_modal: false,
            old_pwd_input: String::new(),
            new_pwd_input: String::new(),
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
            self.treemap_files = v.all_files(&self.current_dir);
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
            self.preview = PreviewState::Treemap;
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

        self.status_msg = format!("✅ Drag & Drop: {total_imported} file cifrati in '{cur_dir}'!");
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
                        self.preview = PreviewState::Treemap;
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
                    self.treemap_files.clear();
                    self.preview = PreviewState::Treemap;
                    self.status_msg = "🔒 Chiavetta USB rimossa: chiave azzerata in RAM!".to_string();
                }
            } else {
                self.detected_drives = detect_usb_drives();
            }
        }

        // ====================================================================
        // SCHERMATA DI SBLOCCO FULL-WINDOW (Occupazione 100% Orizzontale e Verticale)
        // ====================================================================
        if self.vault.is_none() {
            egui::TopBottomPanel::top("unlock_header").show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.heading(RichText::new("🔐 SecureUSB Explorer — Architettura SVAULT03 / SVKEY04").size(22.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            Color32::from_rgb(16, 185, 129),
                            format!("⚡ {} Core Rayon SIMD Attivi", rayon::current_num_threads()),
                        );
                    });
                });
                ui.label("Rilevamento Automatico USB Hot-Plug • Plausible Deniability (Dual-Vault) • Deduplicazione BLAKE3 • Parità Reed-Solomon GF(256)");
                ui.add_space(4.0);
            });

            egui::TopBottomPanel::bottom("unlock_footer").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("🛡️ Protezione Chiavi RAM: ZeroizeOnDrop + mlock attivi  |  Trascina una cartella USB nella finestra per selezionarla.");
                    if !self.status_msg.is_empty() {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.colored_label(Color32::LIGHT_GREEN, &self.status_msg);
                        });
                    }
                });
            });

            egui::CentralPanel::default().show(ctx, |ui| {
                let avail_h = ui.available_height();
                ui.columns(2, |cols| {
                    // COLONNA SINISTRA (100% Altezza): Sblocco & Inizializzazione Dual-Slot
                    egui::Frame::group(cols[0].style())
                        .inner_margin(egui::Margin::same(16.0))
                        .show(&mut cols[0], |ui| {
                            ui.set_min_height(avail_h - 16.0);
                            let col_w = ui.available_width();

                            ui.heading("🔓 1. Sblocco o Creazione Vault Cifrato");
                            ui.label("Seleziona la chiavetta rilevata automaticamente oppure inserisci il percorso:");
                            ui.add_space(10.0);

                            ui.horizontal(|ui| {
                                egui::ComboBox::from_id_salt("usb_selector")
                                    .selected_text(if self.usb_path.is_empty() {
                                        "🔌 Seleziona unità USB rilevata..."
                                    } else {
                                        &self.usb_path
                                    })
                                    .width((col_w - 130.0).max(180.0))
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

                                if ui.button("🔄 Aggiorna").clicked() {
                                    self.detected_drives = detect_usb_drives();
                                }
                            });

                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.usb_path)
                                        .hint_text("Percorso montato (es. E:\\, /Volumes/USB, /media/usb)")
                                        .desired_width((col_w - 110.0).max(180.0)),
                                );
                                if ui.button("📂 Sfoglia").clicked() {
                                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                        self.usb_path = folder.display().to_string();
                                    }
                                }
                            });

                            ui.add_space(14.0);
                            ui.strong("🔑 Password Crittografica (Primaria o Shadow):");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.password)
                                    .password(true)
                                    .hint_text("Inserisci la password per sbloccare Slot 0 (Primario) o Slot 1 (Shadow)...")
                                    .desired_width(col_w),
                            );

                            let bits = estimate_entropy_bits(&self.password);
                            ui.add(
                                egui::ProgressBar::new((bits / 128.0).clamp(0.0, 1.0))
                                    .text(format!("Entropia Password: {bits:.0} bit (Target: 80+ bit)"))
                                    .desired_width(col_w),
                            );

                            ui.add_space(18.0);
                            ui.columns(2, |btn_cols| {
                                let bw = btn_cols[0].available_width();
                                if btn_cols[0]
                                    .add_sized(
                                        [bw, 42.0],
                                        egui::Button::new(RichText::new("🔓 Sblocca Vault (Auto-Slot)").strong()),
                                    )
                                    .clicked()
                                    && self.busy_rx.is_none()
                                {
                                    let path = self.usb_path.clone();
                                    let pass = self.password.clone();
                                    self.spawn_busy_task(
                                        "Sblocco Vault e Verifica Reed-Solomon ECC...",
                                        move || BgTaskOutcome::Unlocked(SecureVault::init_or_open(path, &pass, false)),
                                    );
                                }

                                let bw2 = btn_cols[1].available_width();
                                if btn_cols[1]
                                    .add_sized(
                                        [bw2, 42.0],
                                        egui::Button::new("✨ Inizializza Nuovo Vault"),
                                    )
                                    .clicked()
                                    && self.busy_rx.is_none()
                                {
                                    let path = self.usb_path.clone();
                                    let pass = self.password.clone();
                                    self.spawn_busy_task(
                                        "Inizializzazione Dual-Slot + Shadow Index + Parità ECC...",
                                        move || BgTaskOutcome::Unlocked(SecureVault::init_or_open(path, &pass, true)),
                                    );
                                }
                            });
                        });

                    // COLONNA DESTRA (100% Altezza): Formattatore exFAT + Stato Architettura
                    egui::Frame::group(cols[1].style())
                        .inner_margin(egui::Margin::same(16.0))
                        .show(&mut cols[1], |ui| {
                            ui.set_min_height(avail_h - 16.0);
                            let col_w = ui.available_width();

                            ui.heading("🛠️ 2. Formattazione Fisica USB (exFAT)");
                            ui.label("Prepara una chiavetta grezza per renderla compatibile con Windows, Linux e macOS senza limiti di 4 GB:");
                            ui.add_space(10.0);

                            ui.add(
                                egui::TextEdit::singleline(&mut self.raw_device)
                                    .hint_text("Identificativo disco (es. E: su Windows, /dev/sdb1 su Linux, /dev/disk2 su Mac)")
                                    .desired_width(col_w),
                            );
                            ui.add_space(8.0);
                            if ui
                                .add_sized([col_w, 38.0], egui::Button::new("⚡ Formatta Dispositivo in exFAT"))
                                .clicked()
                            {
                                match format_physical_usb(&self.raw_device, "SECURE_USB") {
                                    Ok(()) => {
                                        self.detected_drives = detect_usb_drives();
                                        self.status_msg = "✅ Formattazione exFAT completata!".to_string();
                                    }
                                    Err(e) => self.status_msg = format!("❌ Errore: {e}"),
                                }
                            }

                            ui.add_space(20.0);
                            ui.separator();
                            ui.heading("🧬 Specifiche di Sicurezza Attive");
                            ui.add_space(6.0);
                            ui.label("• KDF: Argon2id (64 MiB RAM, 3 iterazioni, 4 thread)");
                            ui.label("• Cifratura AEAD: XChaCha20-Poly1305 In-Place (256-bit DEK, 192-bit Nonce)");
                            ui.label("• Compressione: Zstandard Adattivo con finestra da 4 MB");
                            ui.label("• Deduplicazione: BLAKE3 Keyed Hash sui chunk da 4 MB");
                            ui.label("• Anti Bit-Rot: Parità Reed-Solomon GF(2^8) 8+4 Shard Cauchy");
                            ui.label("• Plausible Deniability: Doppio Slot SVKEY04 (index.meta / index.shadow)");
                            ui.label("• Visualizzazione: Treemap Interattiva + Viewer Immagini/PDF in RAM");
                        });
                });
            });
            return;
        }

        // ====================================================================
        // MODALI CAMBIO PASSWORD E SHADOW VAULT
        // ====================================================================
        if self.show_pwd_modal {
            egui::Window::new("🔑 Cambio Password Istantaneo (Key Wrapping)")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("La Data Encryption Key (DEK) verrà ri-avvolta senza ricifrare i file:");
                    ui.add(egui::TextEdit::singleline(&mut self.old_pwd_input).password(true).hint_text("Password Attuale"));
                    ui.add(egui::TextEdit::singleline(&mut self.new_pwd_input).password(true).hint_text("Nuova Password"));
                    ui.horizontal(|ui| {
                        if ui.button("✅ Aggiorna Password").clicked() {
                            if let Some(v) = &self.vault {
                                match v.change_password(&self.old_pwd_input, &self.new_pwd_input) {
                                    Ok(()) => {
                                        self.status_msg = "✅ Password aggiornata istantaneamente!".to_string();
                                        self.show_pwd_modal = false;
                                    }
                                    Err(e) => self.status_msg = format!("❌ Errore: {e}"),
                                }
                            }
                            self.old_pwd_input.clear();
                            self.new_pwd_input.clear();
                        }
                        if ui.button("Annulla").clicked() {
                            self.show_pwd_modal = false;
                        }
                    });
                });
        }

        if self.show_shadow_modal {
            egui::Window::new("🕵️ Plausible Deniability — Configura Secondo Vault Nascosto")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Imposta una seconda password segreta per attivare lo Slot 1 e index.shadow:");
                    ui.add(egui::TextEdit::singleline(&mut self.shadow_pwd_input).password(true).hint_text("Password Segreta Shadow"));
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

        // ====================================================================
        // EXPLORER FULL-WINDOW: TOP BAR, FOOTER, SIDE PANEL & CENTRAL PANEL
        // ====================================================================
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("⬆ Su").clicked() && self.current_dir != "/" {
                    let parent = Path::new(&self.current_dir)
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    self.current_dir = if parent.is_empty() { "/".to_string() } else { parent };
                    self.preview = PreviewState::Treemap;
                    self.refresh_dir();
                }

                if ui
                    .button(RichText::new("🗺️ Treemap Spazio").strong())
                    .clicked()
                {
                    self.selected_path = None;
                    self.preview = PreviewState::Treemap;
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

                if ui.button("📥 Importa File").clicked() && self.busy_rx.is_none() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        if !should_ignore_entry(&path) {
                            if let (Some(v), Ok(f)) = (self.vault.clone(), File::open(&path)) {
                                let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                let target = format!("{}/{}", self.current_dir, fname);
                                self.spawn_busy_task(format!("Compressione e Cifratura Multi-Core di {fname}..."), move || {
                                    match v.write_stream(&target, f) {
                                        Ok(()) => BgTaskOutcome::Message(format!("✅ Importato {fname}!")),
                                        Err(e) => BgTaskOutcome::Message(format!("❌ Errore: {e}")),
                                    }
                                });
                            }
                        }
                    }
                }

                if ui.button("🧬 Importa Dedup (BLAKE3)").clicked() && self.busy_rx.is_none() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        if !should_ignore_entry(&path) {
                            if let (Some(v), Ok(f)) = (self.vault.clone(), File::open(&path)) {
                                let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                let target = format!("{}/{}", self.current_dir, fname);
                                self.spawn_busy_task(format!("Deduplicazione BLAKE3 di {fname}..."), move || {
                                    match v.write_stream_dedup(&target, f) {
                                        Ok(hits) => BgTaskOutcome::Message(format!("✅ Importato {fname} ({hits} chunk da 4MB deduplicati)!")),
                                        Err(e) => BgTaskOutcome::Message(format!("❌ Errore: {e}")),
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
                            let _ = v.export_dir(&target_dir, &dest_folder);
                            self.status_msg = format!("✅ Cartella '{target_dir}' esportata!");
                        }
                    }
                }

                if ui.button("🔑 Password").clicked() {
                    self.show_pwd_modal = true;
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
                        self.preview = PreviewState::Treemap;
                        self.refresh_dir();
                    }
                }

                if ui.button("🔒 Blocca").clicked() {
                    self.vault = None;
                    self.entries.clear();
                    self.treemap_files.clear();
                    self.preview = PreviewState::Treemap;
                }
            });

            ui.separator();

            let mut jump_dir: Option<String> = None;
            ui.horizontal(|ui| {
                let mode_badge = if self
                    .vault
                    .as_ref()
                    .map(|v| v.is_shadow_session())
                    .unwrap_or(false)
                {
                    "🕵️ [SHADOW VAULT]"
                } else {
                    "🔐 [PRIMARIO]"
                };
                ui.colored_label(Color32::from_rgb(16, 185, 129), mode_badge);

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
                            .desired_width(280.0),
                    );
                    if resp.changed() {
                        self.refresh_dir();
                    }
                });
            });

            if let Some(jd) = jump_dir {
                self.search_query.clear();
                self.current_dir = jd;
                self.preview = PreviewState::Treemap;
                self.refresh_dir();
            }
        });

        egui::TopBottomPanel::bottom("telemetry_footer").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let saved = self.stats.original_size.saturating_sub(self.stats.disk_size);
                let pct = if self.stats.original_size > 0 {
                    (saved as f32 / self.stats.original_size as f32) * 100.0
                } else {
                    0.0
                };
                ui.label(format!(
                    "📊 Vault: {} File, {} Cartelle ({} Chunk 4MB)  |  Reale: {}  ➔  Su USB: {}",
                    self.stats.total_files,
                    self.stats.total_folders,
                    self.stats.total_chunks,
                    format_bytes(self.stats.original_size),
                    format_bytes(self.stats.disk_size),
                ));
                ui.add(
                    egui::ProgressBar::new((pct / 100.0).clamp(0.0, 1.0))
                        .text(format!("Risparmio Zstd+Dedup: {pct:.1}%"))
                        .desired_width(200.0),
                );
                if !self.status_msg.is_empty() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(Color32::LIGHT_GREEN, &self.status_msg);
                    });
                }
            });
        });

        // Pannello Laterale Sinistro: auto_shrink([false, false]) + righe a tutta larghezza
        egui::SidePanel::left("file_list")
            .resizable(true)
            .default_width(390.0)
            .width_range(260.0..=640.0)
            .show(ctx, |ui| {
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let entries_clone = self.entries.clone();
                        let row_w = ui.available_width();
                        for e in entries_clone {
                            let name = Path::new(&e.virtual_path)
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_else(|| e.virtual_path.clone());
                            let label = if e.is_dir {
                                format!("📁 {name}/")
                            } else {
                                format!(
                                    "📄 {name}  ({} ➔ {})",
                                    format_bytes(e.original_size),
                                    format_bytes(e.disk_size)
                                )
                            };
                            let is_sel = self.selected_path.as_deref() == Some(&e.virtual_path);
                            if ui
                                .add_sized(
                                    [row_w, 26.0],
                                    egui::SelectableLabel::new(is_sel, label),
                                )
                                .clicked()
                            {
                                self.select_entry(ctx, &e);
                            }
                        }
                    });
            });

        // Pannello Centrale: occupa il 100% dello spazio rimanente (Treemap o Editor/Viewer a pieno schermo)
        let mut save_target: Option<(String, Vec<u8>)> = None;
        let mut treemap_clicked: Option<FileEntry> = None;
        let mut return_to_treemap = false;

        egui::CentralPanel::default().show(ctx, |ui| match &mut self.preview {
            PreviewState::Treemap => {
                if let Some(clicked) =
                    treemap::draw_interactive_treemap(ui, &self.current_dir, &self.treemap_files)
                {
                    treemap_clicked = Some(clicked);
                }
            }
            PreviewState::Text { path, content } => {
                ui.horizontal(|ui| {
                    ui.heading(format!("📝 Editor Testo in RAM: {path}"));
                    if ui.button("💾 Salva Modifiche").clicked() {
                        save_target = Some((path.clone(), content.as_bytes().to_vec()));
                    }
                    if ui.button("🗺️ Torna alla Treemap").clicked() {
                        return_to_treemap = true;
                    }
                });
                ui.separator();
                let avail = ui.available_size();
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_sized(
                            avail,
                            egui::TextEdit::multiline(content).code_editor(),
                        );
                    });
            }
            PreviewState::Image {
                path,
                texture,
                dims,
            } => {
                ui.horizontal(|ui| {
                    ui.heading(format!(
                        "🖼️ Visualizzatore Immagini RAM (Zero-Temp): {path} ({}x{} px)",
                        dims.0, dims.1
                    ));
                    if ui.button("🗺️ Torna alla Treemap").clicked() {
                        return_to_treemap = true;
                    }
                });
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
                    if ui.button("🗺️ Torna alla Treemap").clicked() {
                        return_to_treemap = true;
                    }
                });
                ui.separator();
                let avail = ui.available_size();
                let mut page_txt = pages[*current_page].clone();
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_sized(avail, egui::TextEdit::multiline(&mut page_txt));
                    });
            }
            PreviewState::LargeFile { path, size, chunks } => {
                ui.horizontal(|ui| {
                    ui.heading(format!("🎬 File Multimediale / Binario: {path}"));
                    if ui.button("🗺️ Torna alla Treemap").clicked() {
                        return_to_treemap = true;
                    }
                });
                ui.separator();
                ui.label(format!(
                    "Dimensione: {} ({chunks} chunk indipendenti da 4 MB).",
                    format_bytes(*size)
                ));
                ui.label("Clicca '▶ Stream Video O(1)' nella barra superiore per riprodurlo subito.");
            }
        });

        if return_to_treemap {
            self.preview = PreviewState::Treemap;
        }

        if let Some(entry) = treemap_clicked {
            self.select_entry(ctx, &entry);
        }

        if let Some((path, data)) = save_target {
            if let Some(v) = &self.vault {
                let _ = v.write_file(&path, &data);
                self.status_msg = format!("✅ Salvato {path}!");
            }
            self.refresh_dir();
        }
    }
}
