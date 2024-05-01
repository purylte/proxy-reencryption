use criterion::{black_box, criterion_group, criterion_main, Criterion};
use proxy_reencryption_lib::{
    proxy_reencryption_lib::{Blocks, Key, ProxyReencryption},
    utils::new_random_arr,
};
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
pub fn encrypt_benchmark_1(c: &mut Criterion) {
    c.bench_function("encryption", |b| {
        b.iter_batched(
            || encryption_input(1),
            encrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn encrypt_benchmark_10(c: &mut Criterion) {
    c.bench_function("encryption", |b| {
        b.iter_batched(
            || encryption_input(10),
            encrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn encrypt_benchmark_100(c: &mut Criterion) {
    c.bench_function("encryption", |b| {
        b.iter_batched(
            || encryption_input(100),
            encrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn encrypt_benchmark_1000(c: &mut Criterion) {
    c.bench_function("encryption", |b| {
        b.iter_batched(
            || encryption_input(1000),
            encrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn encrypt_benchmark_10000(c: &mut Criterion) {
    c.bench_function("encryption", |b| {
        b.iter_batched(
            || encryption_input(10000),
            encrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn encrypt_benchmark_100000(c: &mut Criterion) {
    c.bench_function("encryption", |b| {
        b.iter_batched(
            || encryption_input(100000),
            encrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn decrypt_benchmark_1(c: &mut Criterion) {
    c.bench_function("decryption", |b| {
        b.iter_batched(
            || decryption_input(1),
            decrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn decrypt_benchmark_10(c: &mut Criterion) {
    c.bench_function("decryption", |b| {
        b.iter_batched(
            || decryption_input(10),
            decrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn decrypt_benchmark_100(c: &mut Criterion) {
    c.bench_function("decryption", |b| {
        b.iter_batched(
            || decryption_input(100),
            decrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn decrypt_benchmark_1000(c: &mut Criterion) {
    c.bench_function("decryption", |b| {
        b.iter_batched(
            || decryption_input(1000),
            decrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn decrypt_benchmark_10000(c: &mut Criterion) {
    c.bench_function("decryption", |b| {
        b.iter_batched(
            || decryption_input(10000),
            decrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn decrypt_benchmark_100000(c: &mut Criterion) {
    c.bench_function("decryption", |b| {
        b.iter_batched(
            || decryption_input(100000),
            decrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn reencrypt_benchmark_1(c: &mut Criterion) {
    c.bench_function("reencryption", |b| {
        b.iter_batched(
            || reencryption_input(1),
            reencrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn reencrypt_benchmark_10(c: &mut Criterion) {
    c.bench_function("reencryption", |b| {
        b.iter_batched(
            || reencryption_input(10),
            reencrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn reencrypt_benchmark_100(c: &mut Criterion) {
    c.bench_function("reencryption", |b| {
        b.iter_batched(
            || reencryption_input(100),
            reencrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn reencrypt_benchmark_1000(c: &mut Criterion) {
    c.bench_function("reencryption", |b| {
        b.iter_batched(
            || reencryption_input(1000),
            reencrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn reencrypt_benchmark_10000(c: &mut Criterion) {
    c.bench_function("reencryption", |b| {
        b.iter_batched(
            || reencryption_input(10000),
            reencrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn reencrypt_benchmark_100000(c: &mut Criterion) {
    c.bench_function("reencryption", |b| {
        b.iter_batched(
            || reencryption_input(100000),
            reencrypt_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}

pub fn generate_reencryption_key_benchmark_1(c: &mut Criterion) {
    c.bench_function("generate_reencryption_key", |b| {
        b.iter_batched(
            || generate_reencryption_key_input(1),
            generate_reencryption_key_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn generate_reencryption_key_benchmark_10(c: &mut Criterion) {
    c.bench_function("generate_reencryption_key", |b| {
        b.iter_batched(
            || generate_reencryption_key_input(10),
            generate_reencryption_key_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn generate_reencryption_key_benchmark_100(c: &mut Criterion) {
    c.bench_function("generate_reencryption_key", |b| {
        b.iter_batched(
            || generate_reencryption_key_input(100),
            generate_reencryption_key_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn generate_reencryption_key_benchmark_1000(c: &mut Criterion) {
    c.bench_function("generate_reencryption_key", |b| {
        b.iter_batched(
            || generate_reencryption_key_input(1000),
            generate_reencryption_key_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn generate_reencryption_key_benchmark_10000(c: &mut Criterion) {
    c.bench_function("generate_reencryption_key", |b| {
        b.iter_batched(
            || generate_reencryption_key_input(10000),
            generate_reencryption_key_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}
pub fn generate_reencryption_key_benchmark_100000(c: &mut Criterion) {
    c.bench_function("generate_reencryption_key", |b| {
        b.iter_batched(
            || generate_reencryption_key_input(100000),
            generate_reencryption_key_benchmark(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn encrypt_benchmark() -> impl FnMut((Key<16>, Key<16>, Key<16>, u8, Blocks)) {
    |(k1, k2, k3, ctr, m)| {
        ProxyReencryption::encryption(
            black_box(&k1),
            black_box(&k2),
            black_box(&k3),
            black_box(ctr),
            black_box(&m),
        );
    }
}

fn encryption_input(blocks_length: usize) -> (Key<16>, Key<16>, Key<16>, u8, Blocks) {
    let k1 = Key::new(new_random_arr());
    let k2 = Key::new(new_random_arr());
    let k3 = Key::new(new_random_arr());
    let ctr: u8 = thread_rng().gen();
    let m = Blocks::new((0..blocks_length).map(|_| new_random_arr()).collect());
    (k1, k2, k3, ctr, m)
}

fn decrypt_benchmark() -> impl FnMut((Key<16>, Key<16>, Key<16>, u8, [u8; 16], Blocks)) -> Blocks {
    |(k1, k2, k3, ctr, iv, c)| {
        ProxyReencryption::decryption(
            black_box(&k1),
            black_box(&k2),
            black_box(&k3),
            black_box(ctr),
            black_box(&iv),
            black_box(c),
        )
    }
}

fn decryption_input(blocks_length: usize) -> (Key<16>, Key<16>, Key<16>, u8, [u8; 16], Blocks) {
    let k1 = Key::new(new_random_arr());
    let k2 = Key::new(new_random_arr());
    let k3 = Key::new(new_random_arr());
    let ctr: u8 = thread_rng().gen();
    let iv = new_random_arr::<16>();
    let c = Blocks::new((0..blocks_length + 1).map(|_| new_random_arr()).collect());
    (k1, k2, k3, ctr, iv, c)
}

fn reencrypt_benchmark() -> impl FnMut((Vec<usize>, Key<16>, Key<16>, Vec<usize>, [u8; 16], Blocks))
{
    |(ck1, k2, k2_1, ck3, iv, c)| {
        ProxyReencryption::reencryption(
            black_box(ck1),
            black_box(&k2),
            black_box(&k2_1),
            black_box(ck3),
            black_box(&iv),
            black_box(c),
        );
    }
}

fn reencryption_input(
    blocks_length: usize,
) -> (Vec<usize>, Key<16>, Key<16>, Vec<usize>, [u8; 16], Blocks) {
    let ck1 = new_random_permutation(16);
    let k2 = Key::new(new_random_arr());
    let k2_1 = Key::new(new_random_arr());
    let ck3 = new_random_permutation(blocks_length);
    let iv = new_random_arr::<16>();
    let c = Blocks::new((0..blocks_length + 1).map(|_| new_random_arr()).collect());
    (ck1, k2, k2_1, ck3, iv, c)
}

fn generate_reencryption_key_benchmark<'a>() -> impl FnMut((Key<16>, Key<16>, Key<16>, usize)) {
    |(k1, k2, k3, n)| {
        ProxyReencryption::reencryption_key_generator(
            black_box(&k1),
            black_box(&k2),
            black_box(&k3),
            black_box(n),
        );
    }
}

fn generate_reencryption_key_input(blocks_length: usize) -> (Key<16>, Key<16>, Key<16>, usize) {
    let k1 = Key::new(new_random_arr());
    let k2 = Key::new(new_random_arr());
    let k3 = Key::new(new_random_arr());
    let n = blocks_length;
    (k1, k2, k3, n)
}

fn new_random_permutation(n: usize) -> Vec<usize> {
    let mut rng = thread_rng();
    let mut array = (0..n).collect::<Vec<usize>>();
    array.shuffle(&mut rng);
    array
}

criterion_group!(
    encrypt,
    encrypt_benchmark_1,
    encrypt_benchmark_10,
    encrypt_benchmark_100,
    encrypt_benchmark_1000,
    encrypt_benchmark_10000,
    encrypt_benchmark_100000
);
criterion_group!(
    reencrypt,
    reencrypt_benchmark_1,
    reencrypt_benchmark_10,
    reencrypt_benchmark_100,
    reencrypt_benchmark_1000,
    reencrypt_benchmark_10000,
    reencrypt_benchmark_100000
);
criterion_group!(
    decrypt,
    decrypt_benchmark_1,
    decrypt_benchmark_10,
    decrypt_benchmark_100,
    decrypt_benchmark_1000,
    decrypt_benchmark_10000,
    decrypt_benchmark_100000
);
criterion_group!(
    generate_reencryption_key,
    generate_reencryption_key_benchmark_1,
    generate_reencryption_key_benchmark_10,
    generate_reencryption_key_benchmark_100,
    generate_reencryption_key_benchmark_1000,
    generate_reencryption_key_benchmark_10000,
    generate_reencryption_key_benchmark_100000
);

criterion_main!(encrypt, decrypt, reencrypt, generate_reencryption_key);
