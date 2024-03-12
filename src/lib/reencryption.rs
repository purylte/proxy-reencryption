use crate::{
    aonth::d_aonth,
    depermutation, e_aonth, find_conversion_key, permutation,
    util::{encrypt, new_random_arr, xor},
};

// N: amount of block
// L: block size in byte

pub fn encryption(
    k1: &[u8; 16],
    k2: &[u8; 16],
    k3: &[u8; 16],
    ctr: u8,
    m: Vec<[u8; 16]>,
    n: usize,
) -> ([u8; 16], Vec<[u8; 16]>) {
    let (p1, p2, p3) = key_generator(false, k1, k2, k3, n);
    let iv = new_random_arr::<16>();
    let m_1: Vec<[u8; 16]> = e_aonth(ctr, &m);
    let m_2 = permutation(&p3, &m);
    let mut c: Vec<[u8; 16]> = Vec::with_capacity(n + 1);
    c[0] = xor(
        &permutation(&p1, &(m_1[n + 1]).to_vec()),
        &permutation(&p2, &iv.to_vec()),
    )
    .try_into()
    .unwrap();
    for i in 0..n {
        c[i + i] = xor(
            &permutation(&p1, &m_2[i].to_vec()),
            &permutation(&p2, &c[i].to_vec()),
        )
        .try_into()
        .unwrap();
    }
    (iv, c)
}

pub fn decryption(
    k1: &[u8; 16],
    k2: &[u8; 16],
    k3: &[u8; 16],
    ctr: u8,
    iv: &[u8; 16],
    c: Vec<[u8; 16]>,
    n: usize,
) -> Vec<[u8; 16]> {
    let (p1, p2, p3) = key_generator(false, k1, k2, k3, n);

    let mut m_2: Vec<[u8; 16]> = Vec::with_capacity(n);
    for i in n - 1..0 {
        m_2[i] = depermutation(&p1, &xor(&c[i].to_vec(), &permutation(&p2, &c[i].to_vec())))
            .try_into()
            .unwrap();
    }

    let mut m_1: Vec<[u8; 16]> = Vec::with_capacity(n + 1);
    m_1.extend(depermutation(&p3, &m_2));
    m_1[n] = depermutation(&p1, &xor(&c[0].to_vec(), &permutation(&p2, &iv.to_vec())))
        .try_into()
        .unwrap();

    let m = d_aonth(ctr, &m_1);
    m
}

pub fn reencryption(
    ck1: Vec<usize>,
    k2: &[u8; 16],
    k2_2: &[u8; 16],
    ck3: Vec<usize>,
    iv: &[u8; 16],
    c: Vec<[u8; 16]>,
    n: usize,
) -> ([u8; 16], Vec<[u8; 16]>) {
    let p2 = pg(k2, 16);
    let p2_2 = pg(k2_2, 16);
    let mut c_1: Vec<[u8; 16]> = Vec::with_capacity(n);
    for i in n..0 {
        c_1[i] = permutation(
            &ck1,
            &xor(&c[i].to_vec(), &permutation(&p2, &c[i - 1].to_vec())),
        )
        .try_into()
        .unwrap();
    }
    let mut c_2: Vec<[u8; 16]> = Vec::with_capacity(n + 1);
    c_2[0] = xor(
        &permutation(&ck1, &xor(&c[0].to_vec(), &permutation(&p2, &iv.to_vec()))),
        &permutation(&p2_2, &iv.to_vec()),
    )
    .try_into()
    .unwrap();

    c_2.extend(permutation(&ck3, &c[1..].to_vec()));

    let mut c_res = Vec::with_capacity(n + 1);
    c_res[0] = c[0];
    for i in 1..n + 1 {
        c_res[i] = xor(&c_2[i].to_vec(), &permutation(&p2, &c_2[i - 1].to_vec()))
            .try_into()
            .unwrap();
    }

    (*iv, c_res)
}

fn pg(key: &[u8; 16], n: usize) -> Vec<usize> {
    let mut p: Vec<usize> = (1..n).collect();
    let mut tmp: Vec<[u8; 16]> = Vec::new();
    for i in 0..n {
        tmp.push(encrypt(i as u8, &key));
    }
    p.sort_by_key(|&x| tmp[(x - 1) as usize]);
    p
}

fn key_generator(
    g: bool,
    k1: &[u8; 16],
    k2: &[u8; 16],
    k3: &[u8; 16],
    n: usize,
) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
    if !g {
        let p1 = pg(k1, 16);
        let p2 = pg(k2, 16);
        let p3 = pg(k3, n);

        return (p1, p2, p3);
    }
    let t_k1 = new_random_arr::<16>();
    let t_k2 = new_random_arr::<16>();
    let t_k3 = new_random_arr::<16>();

    let p1 = pg(&t_k1, 16);
    let p2 = pg(&t_k2, 16);
    let p3 = pg(&t_k3, n);

    (p1, p2, p3)
}

fn reencryption_key_generator(k1: &[u8; 16], k2: &[u8; 16], k3: &[u8; 16], n: usize) {
    let (p1, p2, p3) = key_generator(false, k1, k2, k3, n);
    let (p1_1, p2_1, p3_1) = key_generator(true, &[0u8; 16], &[0u8; 16], &[0u8; 16], n);
    let ck1 = find_conversion_key(&p1, &p1_1);
    let ck3 = find_conversion_key(&p3, &p3_1);

    (ck1, k2, k2_1, ck3)
}
