use crate::vault::SecureVault;
use std::io;
use std::sync::Arc;

#[cfg(feature = "native-fuse")]
pub fn mount_fuse(vault: Arc<SecureVault>, mount_point: &str) -> io::Result<()> {
    // Implementazione con crate fuser quando compilato con --features native-fuse
    let _ = (vault, mount_point);
    Ok(())
}

#[cfg(not(feature = "native-fuse"))]
pub fn mount_fuse(_vault: Arc<SecureVault>, _mount_point: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Per abilitare il mount FUSE/WinFsp ricompila con: cargo build --release --features native-fuse",
    ))
}
