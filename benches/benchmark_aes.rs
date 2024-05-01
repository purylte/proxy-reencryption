use aes::{
    cipher::{BlockDecrypt, BlockEncrypt},
    Aes128,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto_common::{generic_array::GenericArray, typenum::U16, KeyInit};
use proxy_reencryption_lib::utils::new_random_arr;

type Block = GenericArray<u8, U16>;

fn encrypt_blocks(key: &[u8; 16], blocks: &mut Vec<Block>) {
    let cipher = Aes128::new_from_slice(key).unwrap();
    for block in blocks.iter_mut() {
        cipher.encrypt_block(block);
    }
}

fn decrypt_blocks(key: &[u8; 16], blocks: &mut Vec<Block>) {
    let cipher = Aes128::new_from_slice(key).unwrap();
    for block in blocks.iter_mut() {
        cipher.decrypt_block(block);
    }
}

fn reencrypt_blocks(dec_key: &[u8; 16], enc_key: &[u8; 16], blocks: &mut Vec<Block>) {
    let dec_cipher = Aes128::new_from_slice(dec_key).unwrap();
    let enc_cipher = Aes128::new_from_slice(enc_key).unwrap();

    for block in blocks.iter_mut() {
        dec_cipher.decrypt_block(block);
        enc_cipher.encrypt_block(block);
    }
}

pub fn aes_encrypt_benchmark_1(c: &mut Criterion) {
    c.bench_function("aes_encryption", |b| {
        b.iter_batched(
            || encryption_input(1),
            |(key, x)| encrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_encrypt_benchmark_10(c: &mut Criterion) {
    c.bench_function("aes_encryption", |b| {
        b.iter_batched(
            || encryption_input(10),
            |(key, x)| encrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_encrypt_benchmark_100(c: &mut Criterion) {
    c.bench_function("aes_encryption", |b| {
        b.iter_batched(
            || encryption_input(100),
            |(key, x)| encrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_encrypt_benchmark_1000(c: &mut Criterion) {
    c.bench_function("aes_encryption", |b| {
        b.iter_batched(
            || encryption_input(1000),
            |(key, x)| encrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_encrypt_benchmark_10000(c: &mut Criterion) {
    c.bench_function("aes_encryption", |b| {
        b.iter_batched(
            || encryption_input(10000),
            |(key, x)| encrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_encrypt_benchmark_100000(c: &mut Criterion) {
    c.bench_function("aes_encryption", |b| {
        b.iter_batched(
            || encryption_input(100000),
            |(key, x)| encrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn aes_decrypt_benchmark_1(c: &mut Criterion) {
    c.bench_function("aes_decryption", |b| {
        b.iter_batched(
            || decryption_input(1),
            |(key, x)| decrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_decrypt_benchmark_10(c: &mut Criterion) {
    c.bench_function("aes_decryption", |b| {
        b.iter_batched(
            || decryption_input(10),
            |(key, x)| decrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_decrypt_benchmark_100(c: &mut Criterion) {
    c.bench_function("aes_decryption", |b| {
        b.iter_batched(
            || decryption_input(100),
            |(key, x)| decrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_decrypt_benchmark_1000(c: &mut Criterion) {
    c.bench_function("aes_decryption", |b| {
        b.iter_batched(
            || decryption_input(1000),
            |(key, x)| decrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_decrypt_benchmark_10000(c: &mut Criterion) {
    c.bench_function("aes_decryption", |b| {
        b.iter_batched(
            || decryption_input(10000),
            |(key, x)| decrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_decrypt_benchmark_100000(c: &mut Criterion) {
    c.bench_function("aes_decryption", |b| {
        b.iter_batched(
            || decryption_input(100000),
            |(key, x)| decrypt_blocks(black_box(&key), black_box(&mut x.to_owned())),
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn aes_reencrypt_benchmark_1(c: &mut Criterion) {
    c.bench_function("aes_reencryption", |b| {
        b.iter_batched(
            || reencryption_input(1),
            |(key, key2, x)| {
                reencrypt_blocks(
                    black_box(&key),
                    black_box(&key2),
                    black_box(&mut x.to_owned()),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn aes_reencrypt_benchmark_10(c: &mut Criterion) {
    c.bench_function("aes_reencryption", |b| {
        b.iter_batched(
            || reencryption_input(10),
            |(key, key2, x)| {
                reencrypt_blocks(
                    black_box(&key),
                    black_box(&key2),
                    black_box(&mut x.to_owned()),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn aes_reencrypt_benchmark_100(c: &mut Criterion) {
    c.bench_function("aes_reencryption", |b| {
        b.iter_batched(
            || reencryption_input(100),
            |(key, key2, x)| {
                reencrypt_blocks(
                    black_box(&key),
                    black_box(&key2),
                    black_box(&mut x.to_owned()),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn aes_reencrypt_benchmark_1000(c: &mut Criterion) {
    c.bench_function("aes_reencryption", |b| {
        b.iter_batched(
            || reencryption_input(1000),
            |(key, key2, x)| {
                reencrypt_blocks(
                    black_box(&key),
                    black_box(&key2),
                    black_box(&mut x.to_owned()),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn aes_reencrypt_benchmark_10000(c: &mut Criterion) {
    c.bench_function("aes_reencryption", |b| {
        b.iter_batched(
            || reencryption_input(10000),
            |(key, key2, x)| {
                reencrypt_blocks(
                    black_box(&key),
                    black_box(&key2),
                    black_box(&mut x.to_owned()),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn aes_reencrypt_benchmark_100000(c: &mut Criterion) {
    c.bench_function("aes_reencryption", |b| {
        b.iter_batched(
            || reencryption_input(100000),
            |(key, key2, x)| {
                reencrypt_blocks(
                    black_box(&key),
                    black_box(&key2),
                    black_box(&mut x.to_owned()),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn encryption_input(blocks_length: usize) -> ([u8; 16], Vec<Block>) {
    let k = new_random_arr();
    let x = (0..blocks_length)
        .map(|_| GenericArray::from(new_random_arr::<16>()))
        .collect();
    (k, x)
}

fn decryption_input(blocks_length: usize) -> ([u8; 16], Vec<Block>) {
    let k = new_random_arr();
    let x = (0..blocks_length)
        .map(|_| GenericArray::from(new_random_arr::<16>()))
        .collect();
    (k, x)
}

fn reencryption_input(blocks_length: usize) -> ([u8; 16], [u8; 16], Vec<Block>) {
    let k1 = new_random_arr();
    let k2 = new_random_arr();
    let x = (0..blocks_length)
        .map(|_| GenericArray::from(new_random_arr::<16>()))
        .collect();
    (k1, k2, x)
}

criterion_group!(
    aes_encrypt,
    aes_encrypt_benchmark_1,
    aes_encrypt_benchmark_10,
    aes_encrypt_benchmark_100,
    aes_encrypt_benchmark_1000,
    aes_encrypt_benchmark_10000,
    aes_encrypt_benchmark_100000
);

criterion_group!(
    aes_reencrypt,
    aes_reencrypt_benchmark_1,
    aes_reencrypt_benchmark_10,
    aes_reencrypt_benchmark_100,
    aes_reencrypt_benchmark_1000,
    aes_reencrypt_benchmark_10000,
    aes_reencrypt_benchmark_100000
);
criterion_group!(
    aes_decrypt,
    aes_decrypt_benchmark_1,
    aes_decrypt_benchmark_10,
    aes_decrypt_benchmark_100,
    aes_decrypt_benchmark_1000,
    aes_decrypt_benchmark_10000,
    aes_decrypt_benchmark_100000
);

criterion_main!(aes_encrypt, aes_reencrypt, aes_decrypt);
