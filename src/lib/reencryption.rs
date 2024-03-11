use aes::cipher::generic_array::{typenum::U16, GenericArray};

use crate::{
    e_aonth, permutation,
    util::{encrypt, xor},
};

// N: amount of block
// L: block size in byte
fn key_generator(
    g: bool,
    k1: [u8; 16],
    k2: [u8; 16],
    k3: [u8; 16],
    n: usize,
) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
    if g {
        //TODO
        //generate random k1,k2,k3
        let k1 = [0u8; 16];
        let k2 = [0u8; 16];
        let k3 = [0u8; 16];
    }
    let p1 = pg(k1, 16);
    let p2 = pg(k2, 16);
    let p3 = pg(k3, n);

    (p1, p2, p3)
}

pub fn encryption(
    k1: [u8; 16],
    k2: [u8; 16],
    k3: [u8; 16],
    ctr: u8,
    m: Vec<[u8; 16]>,
    n: usize,
) -> ([u8; 16], Vec<[u8; 16]>) {
    let (p1, p2, p3) = key_generator(false, k1, k2, k3, n);
    let mut iv = [0u8; 16];
    let m1 = e_aonth(ctr, m);
    let m2 = permutation(p3, m);
    let mut c: Vec<[u8; 16]> = Vec::with_capacity(n + 1);
    c[0] = xor(
        permutation(p1, (m1[n + 1]).to_vec()),
        permutation(p2, iv.to_vec()),
    );
    for i in 0..n {
        c[i + i] = xor(
            permutation(p1, m2[i].to_vec()),
            permutation(p2, c[i].to_vec()),
        );
    }
    return (iv, c);
}

pub fn pg(key: [u8; 16], n: usize) -> Vec<usize> {
    let mut p: Vec<usize> = (1..n).collect();
    let mut tmp: Vec<GenericArray<u8, U16>> = Vec::new();
    for i in 0..n {
        tmp.push(encrypt(i as u8, key));
    }
    p.sort_by_key(|&x| tmp[(x - 1) as usize]);
    p
}
