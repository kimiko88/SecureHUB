pub mod preview;

use crate::usb::format_physical_usb;
use crate::vault::{should_ignore_entry, FileEntry, SecureVault, MAX_TEXT_PREVIEW_SIZE};
use eframe::egui;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::sync::Arc;

pub fn run_app() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 720.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "SecureUSB Explorer (Rust) — Zeroize + Rayon + SIMD + Drag & Drop",
        options,
        Box::new(|_cc| Ok(Box::new(SecureUsbApp::default()))),
    )
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

#[derive(Default)]
struct SecureUsbApp {
    usb_path: String,
    password: String,
    raw_device: String,
    status_msg: String,
    vault: Option<Arc<SecureVault>>,
    current_dir: String,
    entries: Vec<FileEntry>,
    selected_path: Option<String>,
    selected_is_dir: bool,
    preview: PreviewState,
    new_item_name: String,
}

impl SecureUsbApp {
    fn refresh_dir(&mut self) {
        if let Some(v) = &self.vault {
            if self.current_dir.is_empty() {
                self.current_dir = "/".to_string();
            }
            self.entries = v.list_dir(&self.current_dir);
        }
    }

    fn select_entry(&mut self, ctx: &egui::Context, entry: &FileEntry) {
        self.selected_path = Some(entry.virtual_path.clone());
        self.selected_is_dir = entry.is_dir;

        if entry.is_dir {
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

        // Se siamo nella schermata di sblocco, imposta la cartella trascinata come percorso USB
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
            "Drag & Drop completato: {total_imported} file cifrati in '{cur_dir}' (file temporanei esclusi)!"
        );
        self.refresh_dir();
    }
}

impl eframe::App for SecureUsbApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Elabora eventuali file/cartelle rilasciati con Drag & Drop
        self.handle_dropped_files(ctx);

        // 2. Mostra un overlay visivo quando l'utente trascina file sopra la finestra
        let is_hovering_files = !ctx.input(|i| i.raw.hovered_files.is_empty());
        if is_hovering_files {
            egui::Area::new(egui::Id::new("drag_drop_banner"))
                .fixed_pos(egui::pos2(300.0, 260.0))
                .show(ctx, |ui| {
                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                        ui.heading("📥 Rilascia qui file o cartelle per importarli in SVAULT03");
                        ui.label("I file temporanei (.DS_Store, Thumbs.db, desktop.ini, *.tmp) verranno esclusi automaticamente.");
                    });
                });
        }

        if self.vault.is_none() {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Sblocco e Gestione Chiavetta Cifrata (Rust SVAULT03 — Drag & Drop Attivo)");
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.label("Percorso USB:");
                    ui.text_edit_singleline(&mut self.usb_path);
                    if ui.button("Sfoglia...").clicked() {
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.usb_path = folder.display().to_string();
                        }
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Password (Argon2id):");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                });

                ui.horizontal(|ui| {
                    if ui.button("Sblocca Vault Esistente").clicked() {
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
                    if ui.button("Inizializza Nuovo Vault (SVAULT03)").clicked() {
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

                ui.separator();
                ui.heading("Formattazione Hardware USB in exFAT (Windows / Linux / macOS)");
                ui.horizontal(|ui| {
                    ui.label("Dispositivo (es. E:, /dev/sdb1, /dev/disk2):");
                    ui.text_edit_singleline(&mut self.raw_device);
                    if ui.button("Formatta in exFAT").clicked() {
                        match format_physical_usb(&self.raw_device, "SECURE_USB") {
                            Ok(()) => self.status_msg = "Formattazione exFAT completata!".to_string(),
                            Err(e) => self.status_msg = format!("Errore formattazione: {e}"),
                        }
                    }
                });

                if !self.status_msg.is_empty() {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::LIGHT_GREEN, &self.status_msg);
                }
            });
            return;
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

                ui.text_edit_singleline(&mut self.new_item_name);
                if ui.button("📁 +Cartella").clicked() && !self.new_item_name.trim().is_empty() {
                    if let Some(v) = self.vault.clone() {
                        let target = format!("{}/{}", self.current_dir, self.new_item_name.trim());
                        let _ = v.create_dir(&target);
                        self.new_item_name.clear();
                        self.refresh_dir();
                    }
                }
                if ui.button("📄 +File Testo").clicked() && !self.new_item_name.trim().is_empty() {
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
                                    self.status_msg = format!("Importati {count} file dalla cartella (file spazzatura esclusi)!");
                                    self.refresh_dir();
                                }
                                Err(e) => self.status_msg = format!("Errore import cartella: {e}"),
                            }
                        }
                    }
                }

                if ui.button("▶ Stream Video (O(1) Seek)").clicked() {
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
                                        "Esportati {count} file da '{target_dir}' in '{}'!",
                                        dest_folder.display()
                                    );
                                }
                                Err(e) => self.status_msg = format!("Errore export cartella: {e}"),
                            }
                        }
                    }
                }

                if ui.button("🗑 Elimina (Shred)").clicked() {
                    if let (Some(v), Some(sel)) = (self.vault.clone(), self.selected_path.clone()) {
                        let _ = v.delete(&sel);
                        self.selected_path = None;
                        self.preview = PreviewState::None;
                        self.refresh_dir();
                    }
                }

                if ui.button("🔒 Blocca (Zeroize Key)").clicked() {
                    self.vault = None;
                    self.entries.clear();
                    self.preview = PreviewState::None;
                }
            });
            ui.horizontal(|ui| {
                ui.label(format!("Percorso attivo: {}  |  [Trascina file o cartelle nella finestra per importarli]", self.current_dir));
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
                            format!("📄 {name} ({} B | {} chunk)", e.original_size, e.chunk_sizes.len())
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
                ui.label("Seleziona un file dalla lista o trascina file/cartelle dal tuo computer dentro questa finestra.");
            }
            PreviewState::Text { path, content } => {
                ui.horizontal(|ui| {
                    ui.heading(format!("Editor Testo: {path}"));
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
                    "Visualizzatore Immagini RAM (Zero-Temp): {path} ({}x{} px)",
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
                        "Visualizzatore PDF RAM: {path} (Pagina {} di {})",
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
                ui.heading(format!("File Multimediale / Binario: {path}"));
                ui.label(format!(
                    "Dimensione: {size} byte suddivisi in {chunks} chunk indipendenti da 4 MB."
                ));
                ui.label("Usa 'Stream Video (O(1) Seek)' nella barra in alto per riprodurlo istantaneamente.");
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
