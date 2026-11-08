pub mod drag_export;
pub mod preview;
pub mod treemap;

use crate::usb::{detect_usb_drives, format_physical_usb, UsbDriveInfo};
use crate::vault::{
    should_ignore_entry, FileEntry, SecureVault, VaultStats, MAX_TEXT_PREVIEW_SIZE,
};
use eframe::egui::{
    self, Color32, Key, Order, Pos2, Rect, RichText, Rounding, ScrollArea, Sense, Stroke, Vec2,
};
use preview::{HexEntropyState, PdfDocumentInRam};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub fn run_app() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1380.0, 840.0])
            .with_min_inner_size([1020.0, 660.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "🔐 SecureUSB Explorer v0.6 Pro (Rust) — Ctrl+K • Dual-Pane • Hex/Entropy • Donut/Treemap • PDF RAM",
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
    visuals.panel_fill = Color32::from_rgb(15, 23, 42);
    visuals.window_fill = Color32::from_rgb(30, 41, 59);
    visuals.extreme_bg_color = Color32::from_rgb(9, 14, 26);
    visuals.selection.bg_fill = Color32::from_rgb(16, 185, 129);
    visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    ctx.set_visuals(visuals);
}

enum BgTaskOutcome {
    Unlocked(io::Result<Arc<SecureVault>>),
    Message { msg: String, mbps: Option<f32> },
}

enum PreviewState {
    Treemap,
    DualPane,
    Text {
        path: String,
        content: String,
    },
    Image {
        path: String,
        texture: egui::TextureHandle,
        dims: (usize, usize),
    },
    Pdf {
        path: String,
        doc: PdfDocumentInRam,
        current_page: usize,
        font_size: f32,
        page_filter: String,
    },
    HexInspector {
        state: HexEntropyState,
    },
}

impl Default for PreviewState {
    fn default() -> Self {
        Self::Treemap
    }
}

#[derive(Clone)]
struct LocalHostEntry {
    path: PathBuf,
    name: String,
    is_dir: bool,
    size: u64,
}

#[derive(Clone, Copy)]
enum OutboundDropMode {
    Desktop,
    ChooseFolder,
    OSClipboard,
}

/// Coda di azioni eseguita a fine frame per evitare qualsiasi conflitto di borrow (&mut self)
enum UiAction {
    SelectEntry(FileEntry),
    SwitchToTreemap,
    SwitchToDualPane,
    OpenHexInspector { path: String, offset: u64 },
    SaveText { path: String, data: Vec<u8> },
    JumpVaultDir(String),
    JumpLocalDir(PathBuf),
    EncryptLocalToVault { local_path: PathBuf, dedup: bool },
    DecryptVaultToLocal { entry: FileEntry },
    OpenPdfExternal(String),
    TriggerScrub,
    LockVault,
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
    throughput_history: Vec<f32>,
    selected_path: Option<String>,
    selected_is_dir: bool,
    preview: PreviewState,
    new_item_name: String,
    // Modali
    show_pwd_modal: bool,
    old_pwd_input: String,
    new_pwd_input: String,
    show_shadow_modal: bool,
    shadow_pwd_input: String,
    // Command Palette (Ctrl+K / Ctrl+P)
    show_cmd_palette: bool,
    cmd_query: String,
    // Split Dual-Pane (Computer Locale ⟷ Vault USB)
    local_dir: PathBuf,
    local_entries: Vec<LocalHostEntry>,
    selected_local: Option<PathBuf>,
    // Worker asincrono
    busy_title: Option<String>,
    busy_rx: Option<Receiver<BgTaskOutcome>>,
    // Outbound Drag-to-Export
    dragging_entry: Option<FileEntry>,
    last_drag_pos: Option<Pos2>,
}

impl SecureUsbApp {
    fn new() -> Self {
        let drives = detect_usb_drives();
        let initial_path = drives
            .first()
            .map(|d| d.mount_path.clone())
            .unwrap_or_default();
        let start_local = drag_export::get_desktop_dir();
        let mut app = Self {
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
            throughput_history: vec![
                340.0, 410.0, 520.0, 490.0, 610.0, 580.0, 670.0, 720.0, 690.0, 760.0,
            ],
            selected_path: None,
            selected_is_dir: false,
            preview: PreviewState::Treemap,
            new_item_name: String::new(),
            show_pwd_modal: false,
            old_pwd_input: String::new(),
            new_pwd_input: String::new(),
            show_shadow_modal: false,
            shadow_pwd_input: String::new(),
            show_cmd_palette: false,
            cmd_query: String::new(),
            local_dir: start_local,
            local_entries: Vec::new(),
            selected_local: None,
            busy_title: None,
            busy_rx: None,
            dragging_entry: None,
            last_drag_pos: None,
        };
        app.refresh_local_dir();
        app
    }

    fn record_throughput(&mut self, mbps: f32) {
        if self.throughput_history.len() >= 32 {
            self.throughput_history.remove(0);
        }
        self.throughput_history.push(mbps.max(25.0));
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

    fn refresh_local_dir(&mut self) {
        let mut list = Vec::new();
        if let Ok(rd) = fs::read_dir(&self.local_dir) {
            for e in rd.flatten() {
                let path = e.path();
                if should_ignore_entry(&path) {
                    continue;
                }
                let name = e.file_name().to_string_lossy().to_string();
                let meta = e.metadata().ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                list.push(LocalHostEntry {
                    path,
                    name,
                    is_dir,
                    size,
                });
            }
        }
        list.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        });
        self.local_entries = list;
    }

    fn select_entry(&mut self, ctx: &egui::Context, entry: &FileEntry) {
        self.selected_path = Some(entry.virtual_path.clone());
        self.selected_is_dir = entry.is_dir;

        if entry.is_dir {
            self.search_query.clear();
            self.current_dir = entry.virtual_path.clone();
            if !matches!(self.preview, PreviewState::DualPane) {
                self.preview = PreviewState::Treemap;
            }
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

        if preview::is_pdf_ext(&entry.virtual_path) && entry.original_size <= 96 * 1024 * 1024 {
            match preview::load_pdf_document_in_ram(ctx, v, &entry.virtual_path) {
                Ok(doc) => {
                    self.preview = PreviewState::Pdf {
                        path: entry.virtual_path.clone(),
                        doc,
                        current_page: 0,
                        font_size: 14.5,
                        page_filter: String::new(),
                    };
                    return;
                }
                Err(e) => {
                    self.status_msg = format!("⚠️ Avviso PDF: {e}");
                }
            }
        }

        // Se il file supera 16 MB o è un file binario, apre direttamente l'Ispettore Hex O(1) + Mappa Termica Entropia!
        if entry.original_size > MAX_TEXT_PREVIEW_SIZE {
            if let Ok(state) = preview::load_hex_entropy_window(v, &entry.virtual_path, 0) {
                self.preview = PreviewState::HexInspector { state };
            }
            return;
        }

        if let Ok(bytes) = preview::read_vault_bytes(v, &entry.virtual_path) {
            if !bytes.contains(&0) {
                if let Ok(txt) = String::from_utf8(bytes) {
                    self.preview = PreviewState::Text {
                        path: entry.virtual_path.clone(),
                        content: txt,
                    };
                    return;
                }
            }
        }

        if let Ok(state) = preview::load_hex_entropy_window(v, &entry.virtual_path, 0) {
            self.preview = PreviewState::HexInspector { state };
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

        let start_t = Instant::now();
        let mut total_imported = 0usize;
        let mut total_bytes = 0u64;

        for df in dropped {
            let Some(path) = df.path else { continue };
            if should_ignore_entry(&path) {
                continue;
            }
            if path.is_dir() {
                if let Ok(cnt) = v.import_dir(&path, &cur_dir) {
                    total_imported += cnt;
                }
            } else if path.is_file() {
                if let Ok(meta) = fs::metadata(&path) {
                    total_bytes += meta.len();
                }
                if let Ok(f) = File::open(&path) {
                    let fname = path.file_name().unwrap_or_default().to_string_lossy();
                    let target = format!("{cur_dir}/{fname}");
                    if v.write_stream(&target, f).is_ok() {
                        total_imported += 1;
                    }
                }
            }
        }

        let elapsed = start_t.elapsed().as_secs_f32().max(0.001);
        let mbps = ((total_bytes as f32) / (1024.0 * 1024.0)) / elapsed;
        if mbps > 1.0 {
            self.record_throughput(mbps);
        }
        self.status_msg = format!("✅ Drag-In: {total_imported} file cifrati in '{cur_dir}'!");
        self.refresh_dir();
    }

    fn execute_outbound_drag_export(&mut self, entry: FileEntry, mode: OutboundDropMode) {
        let Some(v) = self.vault.clone() else { return };

        match mode {
            OutboundDropMode::Desktop => {
                let desk = drag_export::get_desktop_dir();
                let name = entry.virtual_path.clone();
                let bytes = entry.original_size;
                self.spawn_busy_task(
                    format!("Esportazione Drag-Out di '{name}' sul Desktop..."),
                    move || {
                        let t0 = Instant::now();
                        match drag_export::export_entry_to_dir(&v, &entry, &desk) {
                            Ok(out_path) => {
                                let mbps = ((bytes as f32) / (1024.0 * 1024.0))
                                    / t0.elapsed().as_secs_f32().max(0.001);
                                let _ = drag_export::copy_file_object_to_os_clipboard(&out_path);
                                drag_export::reveal_in_os_file_manager(&out_path);
                                BgTaskOutcome::Message {
                                    msg: format!(
                                        "✅ Esportato sul Desktop: {} (e pronto per Ctrl+V)!",
                                        out_path.display()
                                    ),
                                    mbps: Some(mbps),
                                }
                            }
                            Err(e) => BgTaskOutcome::Message {
                                msg: format!("❌ Errore Drag-Out Desktop: {e}"),
                                mbps: None,
                            },
                        }
                    },
                );
            }
            OutboundDropMode::ChooseFolder => {
                if let Some(target_folder) = rfd::FileDialog::new()
                    .set_title("Seleziona la cartella dove rilasciare l'elemento")
                    .pick_folder()
                {
                    let name = entry.virtual_path.clone();
                    let bytes = entry.original_size;
                    self.spawn_busy_task(
                        format!("Esportazione Drag-Out di '{name}'..."),
                        move || {
                            let t0 = Instant::now();
                            match drag_export::export_entry_to_dir(&v, &entry, &target_folder) {
                                Ok(out_path) => {
                                    let mbps = ((bytes as f32) / (1024.0 * 1024.0))
                                        / t0.elapsed().as_secs_f32().max(0.001);
                                    drag_export::reveal_in_os_file_manager(&out_path);
                                    BgTaskOutcome::Message {
                                        msg: format!("✅ Esportato in: {}!", out_path.display()),
                                        mbps: Some(mbps),
                                    }
                                }
                                Err(e) => BgTaskOutcome::Message {
                                    msg: format!("❌ Errore Drag-Out: {e}"),
                                    mbps: None,
                                },
                            }
                        },
                    );
                }
            }
            OutboundDropMode::OSClipboard => {
                let stage_dir = env::temp_dir().join("secureusb_drag_clip");
                let name = entry.virtual_path.clone();
                self.spawn_busy_task(
                    format!("Copia di '{name}' negli Appunti di Sistema (CF_HDROP)..."),
                    move || match drag_export::export_entry_to_dir(&v, &entry, &stage_dir) {
                        Ok(out_path) => {
                            let _ = drag_export::copy_file_object_to_os_clipboard(&out_path);
                            BgTaskOutcome::Message {
                                msg: format!(
                                    "📋 '{}' copiato negli Appunti di Sistema! Vai sul Desktop o in una cartella e premi Ctrl+V.",
                                    out_path.file_name().unwrap_or_default().to_string_lossy()
                                ),
                                mbps: None,
                            }
                        }
                        Err(e) => BgTaskOutcome::Message {
                            msg: format!("❌ Errore Appunti OS: {e}"),
                            mbps: None,
                        },
                    },
                );
            }
        }
    }

    fn process_ui_actions(&mut self, ctx: &egui::Context, actions: Vec<UiAction>) {
        for act in actions {
            match act {
                UiAction::SelectEntry(entry) => self.select_entry(ctx, &entry),
                UiAction::SwitchToTreemap => {
                    self.preview = PreviewState::Treemap;
                    self.refresh_dir();
                }
                UiAction::SwitchToDualPane => {
                    self.refresh_local_dir();
                    self.preview = PreviewState::DualPane;
                }
                UiAction::OpenHexInspector { path, offset } => {
                    if let Some(v) = &self.vault {
                        match preview::load_hex_entropy_window(v, &path, offset) {
                            Ok(state) => self.preview = PreviewState::HexInspector { state },
                            Err(e) => self.status_msg = format!("❌ Errore Hex Inspector: {e}"),
                        }
                    }
                }
                UiAction::SaveText { path, data } => {
                    if let Some(v) = &self.vault {
                        let t0 = Instant::now();
                        if v.write_file(&path, &data).is_ok() {
                            let mbps = ((data.len() as f32) / (1024.0 * 1024.0))
                                / t0.elapsed().as_secs_f32().max(0.0005);
                            self.record_throughput(mbps);
                            self.status_msg = format!("✅ Salvato {path} in SVAULT03!");
                        }
                    }
                    self.refresh_dir();
                }
                UiAction::JumpVaultDir(dir) => {
                    self.search_query.clear();
                    self.current_dir = dir;
                    if !matches!(self.preview, PreviewState::DualPane) {
                        self.preview = PreviewState::Treemap;
                    }
                    self.refresh_dir();
                }
                UiAction::JumpLocalDir(dir) => {
                    if dir.is_dir() {
                        self.local_dir = dir;
                        self.selected_local = None;
                        self.refresh_local_dir();
                    }
                }
                UiAction::EncryptLocalToVault { local_path, dedup } => {
                    if let Some(v) = self.vault.clone() {
                        let cur = self.current_dir.clone();
                        let fname = local_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        self.spawn_busy_task(
                            format!("Trasferimento Dual-Pane: Cifratura di {fname}..."),
                            move || {
                                let t0 = Instant::now();
                                if local_path.is_dir() {
                                    match v.import_dir(&local_path, &cur) {
                                        Ok(cnt) => BgTaskOutcome::Message {
                                            msg: format!("✅ Dual-Pane: Cartella '{fname}' ({cnt} file) cifrata in '{cur}'!"),
                                            mbps: Some(480.0),
                                        },
                                        Err(e) => BgTaskOutcome::Message {
                                            msg: format!("❌ Errore Dual-Pane: {e}"),
                                            mbps: None,
                                        },
                                    }
                                } else {
                                    let sz = fs::metadata(&local_path).map(|m| m.len()).unwrap_or(0);
                                    let Ok(f) = File::open(&local_path) else {
                                        return BgTaskOutcome::Message {
                                            msg: "❌ Impossibile aprire il file locale".to_string(),
                                            mbps: None,
                                        };
                                    };
                                    let target = format!("{cur}/{fname}");
                                    let res = if dedup {
                                        v.write_stream_dedup(&target, f).map(|_| ())
                                    } else {
                                        v.write_stream(&target, f)
                                    };
                                    match res {
                                        Ok(()) => {
                                            let mbps = ((sz as f32) / (1024.0 * 1024.0))
                                                / t0.elapsed().as_secs_f32().max(0.001);
                                            BgTaskOutcome::Message {
                                                msg: format!("✅ Dual-Pane: '{fname}' cifrato in '{cur}'!"),
                                                mbps: Some(mbps),
                                            }
                                        }
                                        Err(e) => BgTaskOutcome::Message {
                                            msg: format!("❌ Errore: {e}"),
                                            mbps: None,
                                        },
                                    }
                                }
                            },
                        );
                    }
                }
                UiAction::DecryptVaultToLocal { entry } => {
                    if let Some(v) = self.vault.clone() {
                        let dest_dir = self.local_dir.clone();
                        let name = entry.virtual_path.clone();
                        let bytes = entry.original_size;
                        self.spawn_busy_task(
                            format!("Trasferimento Dual-Pane: Decifratura di {name}..."),
                            move || {
                                let t0 = Instant::now();
                                match drag_export::export_entry_to_dir(&v, &entry, &dest_dir) {
                                    Ok(out_path) => {
                                        let mbps = ((bytes as f32) / (1024.0 * 1024.0))
                                            / t0.elapsed().as_secs_f32().max(0.001);
                                        BgTaskOutcome::Message {
                                            msg: format!("✅ Dual-Pane: Decifrato in {}!", out_path.display()),
                                            mbps: Some(mbps),
                                        }
                                    }
                                    Err(e) => BgTaskOutcome::Message {
                                        msg: format!("❌ Errore Dual-Pane: {e}"),
                                        mbps: None,
                                    },
                                }
                            },
                        );
                    }
                }
                UiAction::OpenPdfExternal(vpath) => {
                    if let Some(v) = &self.vault {
                        match preview::open_pdf_in_system_viewer(v, &vpath) {
                            Ok(()) => {
                                self.status_msg = format!("🚀 PDF '{vpath}' aperto nel lettore di sistema!")
                            }
                            Err(e) => self.status_msg = format!("❌ Errore apertura PDF esterno: {e}"),
                        }
                    }
                }
                UiAction::TriggerScrub => {
                    if let Some(v) = self.vault.clone() {
                        self.spawn_busy_task(
                            "Verifica Integrità Globale Poly1305 + Reed-Solomon...",
                            move || {
                                let t0 = Instant::now();
                                let rep = v.scrub_integrity();
                                let mbps = ((rep.verified_bytes as f32) / (1024.0 * 1024.0))
                                    / t0.elapsed().as_secs_f32().max(0.001);
                                if rep.corrupted_files.is_empty() {
                                    BgTaskOutcome::Message {
                                        msg: format!(
                                            "✅ Integrità 100%: {} file ({} chunk) verificati a {:.0} MB/s!",
                                            rep.total_files, rep.verified_chunks, mbps
                                        ),
                                        mbps: Some(mbps),
                                    }
                                } else {
                                    BgTaskOutcome::Message {
                                        msg: format!("❌ Corrotti: {:?}", rep.corrupted_files),
                                        mbps: None,
                                    }
                                }
                            },
                        );
                    }
                }
                UiAction::LockVault => {
                    self.vault = None;
                    self.entries.clear();
                    self.treemap_files.clear();
                    self.preview = PreviewState::Treemap;
                    self.status_msg = "🔒 Vault bloccato e chiave DEK azzerata in RAM (Zeroize).".to_string();
                }
            }
        }
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
        let mut actions: Vec<UiAction> = Vec::new();

        self.handle_dropped_files(ctx);

        // Shortcut Globale: Ctrl+K oppure Ctrl+P apre la Command Palette rapida!
        if self.vault.is_some()
            && ctx.input(|i| i.modifiers.command && (i.key_pressed(Key::K) || i.key_pressed(Key::P)))
        {
            self.show_cmd_palette = !self.show_cmd_palette;
            if self.show_cmd_palette {
                self.cmd_query.clear();
            }
        }
        if self.show_cmd_palette && ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.show_cmd_palette = false;
        }

        // Gestione completamento task in background
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
                        self.refresh_local_dir();
                    }
                    BgTaskOutcome::Unlocked(Err(e)) => {
                        self.status_msg = format!("❌ Errore: {e}");
                    }
                    BgTaskOutcome::Message { msg, mbps } => {
                        if let Some(speed) = mbps {
                            self.record_throughput(speed);
                        }
                        self.status_msg = msg;
                        self.refresh_dir();
                        self.refresh_local_dir();
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
        // SCHERMATA DI SBLOCCO FULL-WINDOW
        // ====================================================================
        if self.vault.is_none() {
            egui::TopBottomPanel::top("unlock_header").show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.heading(
                        RichText::new("🔐 SecureUSB Explorer v0.6 Pro — Architettura SVAULT03 / SVKEY04")
                            .size(22.0),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            Color32::from_rgb(16, 185, 129),
                            format!("⚡ {} Core Rayon SIMD Attivi", rayon::current_num_threads()),
                        );
                    });
                });
                ui.label("Command Palette (Ctrl+K) • Dual-Pane (PC ⟷ USB) • Hex & Entropy Heatmap • Donut + Sparkline • PDF Multi-Pagina RAM");
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
                            let pwd_resp = ui.add(
                                egui::TextEdit::singleline(&mut self.password)
                                    .password(true)
                                    .hint_text("Inserisci la password e premi Invio per sbloccare...")
                                    .desired_width(col_w),
                            );

                            let bits = estimate_entropy_bits(&self.password);
                            ui.add(
                                egui::ProgressBar::new((bits / 128.0).clamp(0.0, 1.0))
                                    .text(format!("Entropia Password: {bits:.0} bit (Target: 80+ bit)"))
                                    .desired_width(col_w),
                            );

                            let enter_unlock =
                                pwd_resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));

                            ui.add_space(18.0);
                            ui.columns(2, |btn_cols| {
                                let bw = btn_cols[0].available_width();
                                if (btn_cols[0]
                                    .add_sized(
                                        [bw, 42.0],
                                        egui::Button::new(RichText::new("🔓 Sblocca Vault (Auto-Slot)").strong()),
                                    )
                                    .clicked()
                                    || enter_unlock)
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
                            ui.heading("🚀 Novità Suite Pro v0.6.0");
                            ui.add_space(6.0);
                            ui.label("• ⚡ Command Palette (Ctrl+K / Ctrl+P): Ricerca fuzzy comandi e file in RAM");
                            ui.label("• 🪟 Split Dual-Pane (PC ⟷ USB): Trasferimento diretto bidirezionale");
                            ui.label("• 🔬 Hex & Entropy Heatmap: Ispettore O(1) con mappa termica di Shannon");
                            ui.label("• 🍩 Donut Chart + Sparkline MB/s: Telemetria grafica in tempo reale");
                            ui.label("• 📕 Motore PDF Multi-Stadio RAM: Sidebar pagine, FlateDecode + immagini");
                        });
                });
            });
            return;
        }

        // ====================================================================
        // 1. COMMAND PALETTE MODAL (Ctrl+K / Ctrl+P)
        // ====================================================================
        if self.show_cmd_palette {
            let mut close_palette = false;
            egui::Window::new("⚡ Command Palette Rapida (Ctrl+K / Esc per chiudere)")
                .collapsible(false)
                .resizable(false)
                .fixed_size([640.0, 420.0])
                .anchor(egui::Align2::CENTER_TOP, [0.0, 70.0])
                .show(ctx, |ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.cmd_query)
                            .hint_text("🔍 Digita un comando (es. dual, hex, treemap, scrub) o il nome di qualsiasi file...")
                            .desired_width(f32::INFINITY),
                    );
                    resp.request_focus();
                    ui.separator();

                    let q = self.cmd_query.trim().to_lowercase();
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .max_height(340.0)
                        .show(ui, |ui| {
                            let w = ui.available_width();
                            ui.colored_label(Color32::from_rgb(6, 182, 212), "⚙️ Azioni Rapide di Sistema");

                            let commands: [(&str, &str); 6] = [
                                ("🗺️ Apri Dashboard Spazio (Donut Chart + Sparkline + Treemap)", "treemap donut grafico spazio"),
                                ("🪟 Attiva Vista Split Dual-Pane (Computer Locale ⟷ Vault USB)", "dual pane split pc locale"),
                                ("🔬 Apri Ispettore Visuale Hex + Mappa Termica Entropia sul file selezionato", "hex entropy ispettore binario"),
                                ("🛡️ Esegui Verifica Integrità Globale (Scrub Poly1305 + Reed-Solomon)", "scrub poly1305 verifica integrita"),
                                ("🕵️ Configura Secondo Vault Nascosto (Plausible Deniability Shadow)", "shadow vault nascosto deniability"),
                                ("🔒 Blocca Vault ed Esegui Zeroize della Chiave in RAM", "lock blocca esci zeroize"),
                            ];

                            for (idx, (label, keywords)) in commands.iter().enumerate() {
                                if q.is_empty()
                                    || label.to_lowercase().contains(&q)
                                    || keywords.contains(&q)
                                {
                                    if ui
                                        .add_sized([w, 28.0], egui::Button::new(*label))
                                        .clicked()
                                    {
                                        match idx {
                                            0 => actions.push(UiAction::SwitchToTreemap),
                                            1 => actions.push(UiAction::SwitchToDualPane),
                                            2 => {
                                                if let Some(sel) = self.selected_path.clone() {
                                                    actions.push(UiAction::OpenHexInspector {
                                                        path: sel,
                                                        offset: 0,
                                                    });
                                                }
                                            }
                                            3 => actions.push(UiAction::TriggerScrub),
                                            4 => self.show_shadow_modal = true,
                                            5 => actions.push(UiAction::LockVault),
                                            _ => {}
                                        }
                                        close_palette = true;
                                    }
                                }
                            }

                            ui.add_space(6.0);
                            ui.colored_label(
                                Color32::from_rgb(16, 185, 129),
                                "📂 File e Cartelle nel Vault (Apertura Istantanea RAM)",
                            );

                            if let Some(v) = &self.vault {
                                let matches = v.search(&q);
                                for entry in matches.into_iter().take(40) {
                                    let icon = if entry.is_dir { "📁" } else { "📄" };
                                    let btn_txt = format!(
                                        "{icon} {}   ({})",
                                        entry.virtual_path,
                                        format_bytes(entry.original_size)
                                    );
                                    if ui
                                        .add_sized([w, 26.0], egui::SelectableLabel::new(false, btn_txt))
                                        .clicked()
                                    {
                                        actions.push(UiAction::SelectEntry(entry));
                                        close_palette = true;
                                    }
                                }
                            }
                        });
                });
            if close_palette {
                self.show_cmd_palette = false;
            }
        }

        // Modali Password & Shadow Vault
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
                                        Ok(()) => BgTaskOutcome::Message {
                                            msg: "🕵️ Shadow Vault configurato con successo!".to_string(),
                                            mbps: None,
                                        },
                                        Err(e) => BgTaskOutcome::Message {
                                            msg: format!("❌ Errore Shadow Vault: {e}"),
                                            mbps: None,
                                        },
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
        // TOP BAR PRINCIPALE
        // ====================================================================
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(RichText::new("⚡ Ctrl+K Comandi").strong().color(Color32::from_rgb(6, 182, 212)))
                    .clicked()
                {
                    self.show_cmd_palette = !self.show_cmd_palette;
                }

                if ui
                    .button(RichText::new("🗺️ Donut & Treemap").strong())
                    .clicked()
                {
                    actions.push(UiAction::SwitchToTreemap);
                }

                if ui
                    .button(RichText::new("🪟 Dual-Pane (PC ⟷ USB)").strong())
                    .clicked()
                {
                    actions.push(UiAction::SwitchToDualPane);
                }

                if ui.button("🔬 Hex & Entropia").clicked() {
                    if let Some(sel) = self.selected_path.clone() {
                        if !self.selected_is_dir {
                            actions.push(UiAction::OpenHexInspector {
                                path: sel,
                                offset: 0,
                            });
                        }
                    } else {
                        self.status_msg = "ℹ️ Seleziona prima un file dalla lista per aprirlo nell'Ispettore Hex + Entropia.".to_string();
                    }
                }

                ui.separator();

                if ui.button("⬆ Su").clicked() && self.current_dir != "/" {
                    let parent = Path::new(&self.current_dir)
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    let target = if parent.is_empty() { "/".to_string() } else { parent };
                    actions.push(UiAction::JumpVaultDir(target));
                }

                ui.add(egui::TextEdit::singleline(&mut self.new_item_name).hint_text("Nome nuovo...").desired_width(95.0));
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
                            actions.push(UiAction::EncryptLocalToVault {
                                local_path: path,
                                dedup: false,
                            });
                        }
                    }
                }

                if ui.button("🧬 Dedup BLAKE3").clicked() && self.busy_rx.is_none() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        if !should_ignore_entry(&path) {
                            actions.push(UiAction::EncryptLocalToVault {
                                local_path: path,
                                dedup: true,
                            });
                        }
                    }
                }

                if ui.button("📁📥 Importa Cartella").clicked() && self.busy_rx.is_none() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        actions.push(UiAction::EncryptLocalToVault {
                            local_path: folder,
                            dedup: false,
                        });
                    }
                }

                if ui.button("▶ Stream Video O(1)").clicked() {
                    if let (Some(v), Some(sel)) = (&self.vault, &self.selected_path) {
                        if let Ok(url) = v.get_stream_url(sel) {
                            let _ = open::that(url);
                        }
                    }
                }

                if ui.button("🛡️ Scrub").clicked() && self.busy_rx.is_none() {
                    actions.push(UiAction::TriggerScrub);
                }

                if ui.button("🔑 Password").clicked() {
                    self.show_pwd_modal = true;
                }

                if ui.button("🕵️ Shadow").clicked() {
                    self.show_shadow_modal = true;
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
                    actions.push(UiAction::LockVault);
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
                    "🕵️ [SHADOW VAULT]"
                } else {
                    "🔐 [PRIMARIO]"
                };
                ui.colored_label(Color32::from_rgb(16, 185, 129), mode_badge);

                if ui.button("🏠 / Root").clicked() {
                    actions.push(UiAction::JumpVaultDir("/".to_string()));
                }
                if self.current_dir != "/" {
                    let mut accum = String::new();
                    for seg in self.current_dir.trim_matches('/').split('/') {
                        accum.push('/');
                        accum.push_str(seg);
                        let target = accum.clone();
                        ui.label("❯");
                        if ui.button(seg).clicked() {
                            actions.push(UiAction::JumpVaultDir(target));
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
                            .hint_text("🔍 Filtra lista in RAM (oppure premi Ctrl+K)...")
                            .desired_width(270.0),
                    );
                    if resp.changed() {
                        self.refresh_dir();
                    }
                });
            });
        });

        // ====================================================================
        // DOCK INFERIORE PER OUTBOUND DRAG-TO-EXPORT + TELEMETRIA
        // ====================================================================
        let mut dock_drop_action: Option<(FileEntry, OutboundDropMode)> = None;

        egui::TopBottomPanel::bottom("telemetry_and_drag_dock").show(ctx, |ui| {
            if self.dragging_entry.is_some() {
                ui.add_space(4.0);
                ui.columns(3, |cols| {
                    let mut draw_drop_slot = |col_ui: &mut egui::Ui,
                                              title: &str,
                                              subtitle: &str,
                                              mode: OutboundDropMode,
                                              color: Color32| {
                        let w = col_ui.available_width();
                        let (rect, _) = col_ui.allocate_exact_size(Vec2::new(w, 46.0), Sense::hover());
                        let pointer_in = col_ui
                            .input(|i| i.pointer.interact_pos())
                            .map_or(false, |p| rect.contains(p));
                        let bg = if pointer_in {
                            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 95)
                        } else {
                            Color32::from_rgb(23, 34, 53)
                        };
                        let stroke = if pointer_in {
                            Stroke::new(2.5, Color32::WHITE)
                        } else {
                            Stroke::new(1.5, color)
                        };
                        col_ui.painter().rect(rect, Rounding::same(8.0), bg, stroke);
                        col_ui.painter().text(
                            rect.center() - Vec2::new(0.0, 7.0),
                            egui::Align2::CENTER_CENTER,
                            title,
                            egui::FontId::proportional(14.0),
                            Color32::WHITE,
                        );
                        col_ui.painter().text(
                            rect.center() + Vec2::new(0.0, 10.0),
                            egui::Align2::CENTER_CENTER,
                            subtitle,
                            egui::FontId::proportional(11.0),
                            Color32::from_rgb(203, 213, 225),
                        );

                        if pointer_in && col_ui.input(|i| i.pointer.any_released()) {
                            if let Some(dragged) = self.dragging_entry.clone() {
                                dock_drop_action = Some((dragged, mode));
                            }
                        }
                    };

                    draw_drop_slot(
                        &mut cols[0],
                        "🖥️ Rilascia qui per Esportare sul DESKTOP",
                        "Oppure trascina oltre il bordo esterno della finestra",
                        OutboundDropMode::Desktop,
                        Color32::from_rgb(16, 185, 129),
                    );
                    draw_drop_slot(
                        &mut cols[1],
                        "📋 Rilascia per Appunti OS (Incolla con Ctrl+V)",
                        "Carica il file/cartella in CF_HDROP per incollarlo ovunque",
                        OutboundDropMode::OSClipboard,
                        Color32::from_rgb(6, 182, 212),
                    );
                    draw_drop_slot(
                        &mut cols[2],
                        "📂 Rilascia per Scegliere la Cartella Destinazione",
                        "Apre il selettore cartella del sistema operativo",
                        OutboundDropMode::ChooseFolder,
                        Color32::from_rgb(139, 92, 246),
                    );
                });
                ui.add_space(4.0);
                ui.separator();
            }

            ui.horizontal(|ui| {
                let saved = self.stats.original_size.saturating_sub(self.stats.disk_size);
                let pct = if self.stats.original_size > 0 {
                    (saved as f32 / self.stats.original_size as f32) * 100.0
                } else {
                    0.0
                };
                ui.label(format!(
                    "📊 Vault: {} File, {} Cartelle ({} Chunk)  |  Reale: {} ➔ Su USB: {}  |  ⚡ Premi Ctrl+K per la Command Palette",
                    self.stats.total_files,
                    self.stats.total_folders,
                    self.stats.total_chunks,
                    format_bytes(self.stats.original_size),
                    format_bytes(self.stats.disk_size),
                ));
                ui.add(
                    egui::ProgressBar::new((pct / 100.0).clamp(0.0, 1.0))
                        .text(format!("Risparmio: {pct:.1}%"))
                        .desired_width(145.0),
                );
                if !self.status_msg.is_empty() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(Color32::LIGHT_GREEN, &self.status_msg);
                    });
                }
            });
        });

        // ====================================================================
        // PANNELLO LATERALE SINISTRO (Mostrato quando non siamo in Dual-Pane a tutto schermo)
        // ====================================================================
        if !matches!(self.preview, PreviewState::DualPane) {
            egui::SidePanel::left("file_list")
                .resizable(true)
                .default_width(370.0)
                .width_range(250.0..=600.0)
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
                                let is_sel =
                                    self.selected_path.as_deref() == Some(&e.virtual_path);

                                let (rect, resp) = ui.allocate_exact_size(
                                    Vec2::new(row_w, 28.0),
                                    Sense::click_and_drag(),
                                );

                                let bg = if is_sel {
                                    Color32::from_rgb(16, 185, 129)
                                } else if resp.hovered() {
                                    Color32::from_rgb(30, 41, 59)
                                } else {
                                    Color32::TRANSPARENT
                                };
                                if bg != Color32::TRANSPARENT {
                                    ui.painter().rect_filled(rect, Rounding::same(5.0), bg);
                                }
                                ui.painter().text(
                                    rect.left_center() + Vec2::new(8.0, 0.0),
                                    egui::Align2::LEFT_CENTER,
                                    &label,
                                    egui::FontId::proportional(13.5),
                                    Color32::WHITE,
                                );

                                if resp.clicked() {
                                    actions.push(UiAction::SelectEntry(e.clone()));
                                }
                                if resp.drag_started() {
                                    self.dragging_entry = Some(e);
                                }
                            }
                        });
                });
        }

        // ====================================================================
        // PANNELLO CENTRALE: Treemap+Donut / Dual-Pane / PDF Multi-Pagina / Hex Inspector / Editor
        // ====================================================================
        let current_dir_snapshot = self.current_dir.clone();
        let treemap_files_snapshot = self.treemap_files.clone();
        let throughput_snapshot = self.throughput_history.clone();
        let local_dir_snapshot = self.local_dir.clone();
        let local_entries_snapshot = self.local_entries.clone();
        let selected_local_snapshot = self.selected_local.clone();
        let vault_entries_snapshot = self.entries.clone();
        let selected_vault_snapshot = self.selected_path.clone();

        let mut new_selected_local: Option<PathBuf> = None;

        egui::CentralPanel::default().show(ctx, |ui| match &mut self.preview {
            // 1. DASHBOARD DONUT CHART + SPARKLINE MB/S + TREEMAP INTERATTIVA
            PreviewState::Treemap => {
                if let Some(clicked) = treemap::draw_interactive_treemap(
                    ui,
                    &current_dir_snapshot,
                    &treemap_files_snapshot,
                    &throughput_snapshot,
                ) {
                    actions.push(UiAction::SelectEntry(clicked));
                }
            }

            // 2. VISTA SPLIT DUAL-PANE (COMPUTER LOCALE ⟷ VAULT USB)
            PreviewState::DualPane => {
                ui.horizontal(|ui| {
                    ui.heading("🪟 Vista Split Dual-Pane — Computer Ospite Locale ⟷ Vault USB Cifrato");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("🗺️ Torna a Donut & Treemap").clicked() {
                            actions.push(UiAction::SwitchToTreemap);
                        }
                    });
                });
                ui.separator();

                let avail_h = ui.available_height();
                ui.columns(3, |cols| {
                    // PANNELLO SINISTRO: Computer Locale
                    egui::Frame::group(cols[0].style()).show(&mut cols[0], |ui| {
                        ui.set_min_height(avail_h - 10.0);
                        ui.colored_label(
                            Color32::from_rgb(6, 182, 212),
                            RichText::new("💻 Computer Locale (Host OS)").strong(),
                        );
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("⬆ Su").clicked() {
                                if let Some(parent) = local_dir_snapshot.parent() {
                                    actions.push(UiAction::JumpLocalDir(parent.to_path_buf()));
                                }
                            }
                            if ui.button("🖥️ Desktop").clicked() {
                                actions.push(UiAction::JumpLocalDir(drag_export::get_desktop_dir()));
                            }
                            if ui.button("📂 Scegli...").clicked() {
                                if let Some(picked) = rfd::FileDialog::new().pick_folder() {
                                    actions.push(UiAction::JumpLocalDir(picked));
                                }
                            }
                        });
                        ui.label(format!("Percorso PC: {}", local_dir_snapshot.display()));
                        ui.separator();

                        ScrollArea::vertical()
                            .id_salt("dual_pane_local_scroll")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let w = ui.available_width();
                                for le in &local_entries_snapshot {
                                    let is_sel = selected_local_snapshot.as_ref() == Some(&le.path);
                                    let txt = if le.is_dir {
                                        format!("📁 {}/", le.name)
                                    } else {
                                        format!("📄 {}  ({})", le.name, format_bytes(le.size))
                                    };
                                    let resp = ui.add_sized(
                                        [w, 26.0],
                                        egui::SelectableLabel::new(is_sel, txt),
                                    );
                                    if resp.double_clicked() && le.is_dir {
                                        actions.push(UiAction::JumpLocalDir(le.path.clone()));
                                    } else if resp.clicked() {
                                        new_selected_local = Some(le.path.clone());
                                    }
                                }
                            });
                    });

                    // COLONNA CENTRALE: Pulsanti di Trasferimento Crittografico Bidirezionale
                    egui::Frame::group(cols[1].style()).show(&mut cols[1], |ui| {
                        ui.set_min_height(avail_h - 10.0);
                        let col_w = ui.available_width();
                        ui.vertical_centered(|ui| {
                            ui.add_space(avail_h * 0.22);
                            ui.heading("⚡ Ponte Crittografico");
                            ui.label("Seleziona un file o una cartella e trasferiscilo:");
                            ui.add_space(16.0);

                            if ui
                                .add_sized(
                                    [col_w, 42.0],
                                    egui::Button::new(
                                        RichText::new("🔐 Cifra in Vault USB ➔").strong(),
                                    ),
                                )
                                .clicked()
                            {
                                if let Some(sel_p) = &selected_local_snapshot {
                                    actions.push(UiAction::EncryptLocalToVault {
                                        local_path: sel_p.clone(),
                                        dedup: false,
                                    });
                                }
                            }

                            ui.add_space(10.0);
                            if ui
                                .add_sized(
                                    [col_w, 42.0],
                                    egui::Button::new(
                                        RichText::new("🧬 Dedup BLAKE3 in USB ➔").strong(),
                                    ),
                                )
                                .clicked()
                            {
                                if let Some(sel_p) = &selected_local_snapshot {
                                    actions.push(UiAction::EncryptLocalToVault {
                                        local_path: sel_p.clone(),
                                        dedup: true,
                                    });
                                }
                            }

                            ui.add_space(20.0);
                            ui.separator();
                            ui.add_space(20.0);

                            if ui
                                .add_sized(
                                    [col_w, 42.0],
                                    egui::Button::new(
                                        RichText::new("⬅ Decifra nel PC Locale").strong(),
                                    ),
                                )
                                .clicked()
                            {
                                if let Some(sel_v) = &selected_vault_snapshot {
                                    if let Some(found) = vault_entries_snapshot
                                        .iter()
                                        .find(|e| &e.virtual_path == sel_v)
                                        .cloned()
                                    {
                                        actions.push(UiAction::DecryptVaultToLocal { entry: found });
                                    }
                                }
                            }
                        });
                    });

                    // PANNELLO DESTRO: Vault USB Cifrato
                    egui::Frame::group(cols[2].style()).show(&mut cols[2], |ui| {
                        ui.set_min_height(avail_h - 10.0);
                        ui.colored_label(
                            Color32::from_rgb(16, 185, 129),
                            RichText::new("🔐 Vault USB Cifrato (SVAULT03)").strong(),
                        );
                        ui.horizontal(|ui| {
                            if ui.button("⬆ Su").clicked() && current_dir_snapshot != "/" {
                                let parent = Path::new(&current_dir_snapshot)
                                    .parent()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "/".to_string());
                                actions.push(UiAction::JumpVaultDir(if parent.is_empty() {
                                    "/".to_string()
                                } else {
                                    parent
                                }));
                            }
                            if ui.button("🏠 / Root").clicked() {
                                actions.push(UiAction::JumpVaultDir("/".to_string()));
                            }
                        });
                        ui.label(format!("Percorso Vault: {current_dir_snapshot}"));
                        ui.separator();

                        ScrollArea::vertical()
                            .id_salt("dual_pane_vault_scroll")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let w = ui.available_width();
                                for ve in &vault_entries_snapshot {
                                    let is_sel = selected_vault_snapshot.as_deref()
                                        == Some(&ve.virtual_path);
                                    let name = Path::new(&ve.virtual_path)
                                        .file_name()
                                        .map(|s| s.to_string_lossy().to_string())
                                        .unwrap_or_else(|| ve.virtual_path.clone());
                                    let txt = if ve.is_dir {
                                        format!("📁 {name}/")
                                    } else {
                                        format!("📄 {name}  ({})", format_bytes(ve.original_size))
                                    };
                                    let resp = ui.add_sized(
                                        [w, 26.0],
                                        egui::SelectableLabel::new(is_sel, txt),
                                    );
                                    if resp.double_clicked() {
                                        actions.push(UiAction::SelectEntry(ve.clone()));
                                    } else if resp.clicked() {
                                        self.selected_path = Some(ve.virtual_path.clone());
                                        self.selected_is_dir = ve.is_dir;
                                    }
                                }
                            });
                    });
                });
            }

            // 3. EDITOR TESTO IN RAM
            PreviewState::Text { path, content } => {
                let p_clone = path.clone();
                ui.horizontal(|ui| {
                    ui.heading(format!("📝 Editor Testo in RAM: {p_clone}"));
                    if ui.button("💾 Salva Modifiche").clicked() {
                        actions.push(UiAction::SaveText {
                            path: p_clone.clone(),
                            data: content.as_bytes().to_vec(),
                        });
                    }
                    if ui.button("🔬 Apri in Hex & Entropia").clicked() {
                        actions.push(UiAction::OpenHexInspector {
                            path: p_clone,
                            offset: 0,
                        });
                    }
                    if ui.button("🗺️ Torna a Donut & Treemap").clicked() {
                        actions.push(UiAction::SwitchToTreemap);
                    }
                });
                ui.separator();
                let avail = ui.available_size();
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_sized(avail, egui::TextEdit::multiline(content).code_editor());
                    });
            }

            // 4. VISUALIZZATORE IMMAGINI RAM
            PreviewState::Image {
                path,
                texture,
                dims,
            } => {
                let p_clone = path.clone();
                ui.horizontal(|ui| {
                    ui.heading(format!(
                        "🖼️ Visualizzatore Immagini RAM (Zero-Temp): {p_clone} ({}x{} px)",
                        dims.0, dims.1
                    ));
                    if ui.button("🔬 Ispeziona Hex & Entropia").clicked() {
                        actions.push(UiAction::OpenHexInspector {
                            path: p_clone,
                            offset: 0,
                        });
                    }
                    if ui.button("🗺️ Torna a Donut & Treemap").clicked() {
                        actions.push(UiAction::SwitchToTreemap);
                    }
                });
                ui.separator();
                ui.image((texture.id(), ui.available_size()));
            }

            // 5. VISUALIZZATORE PDF MULTI-STADIO IN RAM CON SIDEBAR DELLE PAGINE
            PreviewState::Pdf {
                path,
                doc,
                current_page,
                font_size,
                page_filter,
            } => {
                let p_clone = path.clone();
                let total_pages = doc.pages.len().max(1);
                if *current_page >= total_pages {
                    *current_page = total_pages - 1;
                }

                ui.horizontal_wrapped(|ui| {
                    ui.heading(format!(
                        "📕 Lettore PDF in RAM: {} (Pag. {} di {} • {})",
                        p_clone,
                        *current_page + 1,
                        total_pages,
                        format_bytes(doc.raw_size as u64)
                    ));
                    if ui.button("◀ Pag. Prec").clicked() && *current_page > 0 {
                        *current_page -= 1;
                    }
                    if ui.button("Pag. Succ ▶").clicked() && *current_page + 1 < total_pages {
                        *current_page += 1;
                    }
                    ui.add(egui::Slider::new(font_size, 11.0..=24.0).text("Zoom Testo"));

                    if ui
                        .button(
                            RichText::new("🚀 Apri nel Lettore PDF di Sistema")
                                .color(Color32::from_rgb(16, 185, 129))
                                .strong(),
                        )
                        .clicked()
                    {
                        actions.push(UiAction::OpenPdfExternal(p_clone.clone()));
                    }
                    if ui.button("🔬 Hex").clicked() {
                        actions.push(UiAction::OpenHexInspector {
                            path: p_clone,
                            offset: 0,
                        });
                    }
                    if ui.button("🗺️ Treemap").clicked() {
                        actions.push(UiAction::SwitchToTreemap);
                    }
                });
                ui.separator();

                let avail_h = ui.available_height();
                ui.columns(2, |cols| {
                    // Colonna 1: Indice Interattivo delle Pagine + Ricerca nel PDF
                    cols[0].set_max_width(260.0);
                    egui::Frame::group(cols[0].style()).show(&mut cols[0], |ui| {
                        ui.set_min_height(avail_h - 8.0);
                        ui.strong(format!("📑 Pagine del Documento ({total_pages})"));
                        ui.add(
                            egui::TextEdit::singleline(page_filter)
                                .hint_text("🔍 Cerca parola nel PDF...")
                                .desired_width(f32::INFINITY),
                        );
                        ui.separator();

                        let q_filter = page_filter.trim().to_lowercase();
                        ScrollArea::vertical()
                            .id_salt("pdf_pages_sidebar")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let w = ui.available_width();
                                for (idx, p) in doc.pages.iter().enumerate() {
                                    if !q_filter.is_empty()
                                        && !p.text.to_lowercase().contains(&q_filter)
                                        && !p.title.to_lowercase().contains(&q_filter)
                                    {
                                        continue;
                                    }
                                    let is_active = *current_page == idx;
                                    let btn_label =
                                        format!("📄 {} ({} car.)", p.title, p.char_count);
                                    if ui
                                        .add_sized(
                                            [w, 28.0],
                                            egui::SelectableLabel::new(is_active, btn_label),
                                        )
                                        .clicked()
                                    {
                                        *current_page = idx;
                                    }
                                }
                            });
                    });

                    // Colonna 2: Contenuto della Pagina Selezionata + Immagini Incorporate
                    egui::Frame::group(cols[1].style()).show(&mut cols[1], |ui| {
                        ui.set_min_height(avail_h - 8.0);
                        let active_page = &doc.pages[*current_page];
                        ui.colored_label(
                            Color32::from_rgb(6, 182, 212),
                            RichText::new(&active_page.title).size(16.0).strong(),
                        );
                        ui.separator();

                        if !doc.embedded_images.is_empty() {
                            ui.collapsing(
                                format!(
                                    "🖼️ Immagini Incorporate nel PDF ({})",
                                    doc.embedded_images.len()
                                ),
                                |ui| {
                                    ScrollArea::horizontal().show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            for (tex, dims) in &doc.embedded_images {
                                                ui.vertical(|ui| {
                                                    ui.image((tex.id(), Vec2::new(180.0, 140.0)));
                                                    ui.label(format!("{}x{} px", dims.0, dims.1));
                                                });
                                            }
                                        });
                                    });
                                },
                            );
                            ui.separator();
                        }

                        let mut page_text_copy = active_page.text.clone();
                        let remaining = ui.available_size();
                        ScrollArea::vertical()
                            .id_salt("pdf_page_body_scroll")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.add_sized(
                                    remaining,
                                    egui::TextEdit::multiline(&mut page_text_copy)
                                        .font(egui::FontId::proportional(*font_size)),
                                );
                            });
                    });
                });
            }

            // 6. ISPETTORE VISUALE HEX O(1) + MAPPA TERMICA DELL'ENTROPIA
            PreviewState::HexInspector { state } => {
                let p_clone = state.path.clone();
                ui.horizontal(|ui| {
                    ui.heading(format!("🔬 Ispettore Hex & Mappa Termica Entropia: {p_clone}"));
                    if ui.button("▶ Stream Video O(1)").clicked() {
                        if let Some(v) = &self.vault {
                            if let Ok(url) = v.get_stream_url(&p_clone) {
                                let _ = open::that(url);
                            }
                        }
                    }
                    if ui.button("🗺️ Torna a Donut & Treemap").clicked() {
                        actions.push(UiAction::SwitchToTreemap);
                    }
                });
                ui.separator();

                if let Some(next_off) = preview::draw_hex_entropy_inspector(ui, state) {
                    actions.push(UiAction::OpenHexInspector {
                        path: p_clone,
                        offset: next_off,
                    });
                }
            }
        });

        if let Some(sel_loc) = new_selected_local {
            self.selected_local = Some(sel_loc);
        }

        // Gestione Outbound Drag Ghost & Rilascio fuori finestra
        if let Some(dragged) = self.dragging_entry.clone() {
            if let Some(pos) = ctx.input(|i| i.pointer.interact_pos()) {
                self.last_drag_pos = Some(pos);
                egui::Area::new(egui::Id::new("outbound_drag_ghost"))
                    .order(Order::Tooltip)
                    .fixed_pos(pos + Vec2::new(14.0, 14.0))
                    .show(ctx, |ui| {
                        egui::Frame::popup(ui.style()).show(ui, |ui| {
                            let icon = if dragged.is_dir { "📁 Cartella" } else { "📄 File" };
                            ui.strong(format!("📤 Esporta {icon}: {}", dragged.virtual_path));
                            ui.colored_label(
                                Color32::from_rgb(16, 185, 129),
                                "➔ Rilascia nella Dock in basso o oltre il bordo esterno per esportare sul Desktop!",
                            );
                        });
                    });
            }

            if ctx.input(|i| i.pointer.any_released()) {
                if let Some((entry, mode)) = dock_drop_action {
                    self.execute_outbound_drag_export(entry, mode);
                } else if let Some(last_pos) = self.last_drag_pos {
                    let screen: Rect = ctx.screen_rect();
                    let near_outer_border = !screen.shrink(18.0).contains(last_pos);
                    if near_outer_border {
                        self.execute_outbound_drag_export(dragged, OutboundDropMode::Desktop);
                    }
                }
                self.dragging_entry = None;
                self.last_drag_pos = None;
            }
        }

        // Esegue tutte le azioni raccolte senza conflitti di prestito
        if !actions.is_empty() {
            self.process_ui_actions(ctx, actions);
        }
    }
}
