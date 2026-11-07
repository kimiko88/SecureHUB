use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use secureusb_rs::vault::SecureVault;
use tempfile::tempdir;

fn bench_vault_pipeline(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let vault = SecureVault::init_or_open(dir.path(), "BenchMasterKey", true).unwrap();

    // Payload da 16 MB (4 chunk da 4 MB)
    let data: Vec<u8> = (0..(16 * 1024 * 1024))
        .map(|i| ((i * 73) % 251) as u8)
        .collect();

    let mut group = c.benchmark_group("svault03_rust_simd_rayon");
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("parallel_encrypt_16MB", |b| {
        b.iter(|| {
            vault.write_file("/bench.bin", black_box(&data)).unwrap();
        });
    });

    vault.write_file("/bench.bin", &data).unwrap();

    group.bench_function("parallel_decrypt_16MB", |b| {
        b.iter(|| {
            let out = vault.read_file(black_box("/bench.bin")).unwrap();
            black_box(out);
        });
    });

    let mut seeker = vault.open_read_seeker("/bench.bin").unwrap();
    let mut read_buf = [0u8; 4096];
    group.throughput(Throughput::Bytes(read_buf.len() as u64));
    group.bench_function("random_access_seek_O1_4KB", |b| {
        let mut iter_idx = 0u64;
        b.iter(|| {
            let offset = (iter_idx * 65536) % (15 * 1024 * 1024);
            iter_idx = iter_idx.wrapping_add(1);
            let n = seeker.read_at(black_box(&mut read_buf), offset).unwrap();
            black_box(n);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_vault_pipeline);
criterion_main!(benches);
