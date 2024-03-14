use crate::{
    aonth::{d_aonth, e_aonth},
    permutation::{depermutate, depermutate_vec, find_conversion_key, permutate, permutate_vec},
    util::{encrypt, new_random_arr, xor},
};

// N: amount of block
// L: block size in byte

pub fn encryption(
    k1: &[u8; 16],
    k2: &[u8; 16],
    k3: &[u8; 16],
    ctr: u8,
    m: &Vec<[u8; 16]>,
) -> ([u8; 16], Vec<[u8; 16]>) {
    let n = m.len();
    let (p1, p2, p3) = key_generator_with_keys(k1, k2, k3, n);
    let iv = new_random_arr::<16>();
    let m_1: Vec<[u8; 16]> = e_aonth(ctr, &m);
    let m_2 = permutate_vec(&p3, &m);
    let mut c: Vec<[u8; 16]> = vec![[0; 16]; n + 1];
    c[0] = xor(&permutate(&p1, &(m_1[n])), &permutate(&p2, &iv));
    for i in 0..n {
        c[i + 1] = xor(&permutate(&p1, &m_2[i]), &permutate(&p2, &c[i]))
    }
    (iv, c)
}

pub fn decryption(
    k1: &[u8; 16],
    k2: &[u8; 16],
    k3: &[u8; 16],
    ctr: u8,
    iv: &[u8; 16],
    c: &Vec<[u8; 16]>,
) -> Vec<[u8; 16]> {
    let n = c.len() - 1;
    let (p1, p2, p3) = key_generator_with_keys(k1, k2, k3, n);

    let mut m_2: Vec<[u8; 16]> = vec![[0; 16]; n];
    for i in n - 1..0 {
        m_2[i] = depermutate(&p1, &xor(&c[i], &permutate(&p2, &c[i])));
    }

    let mut m_1: Vec<[u8; 16]> = Vec::with_capacity(n + 1);
    m_1.extend(depermutate_vec(&p3, &m_2));
    m_1.push(depermutate(&p1, &xor(&c[0], &permutate(&p2, &iv))));

    let m = d_aonth(ctr, &m_1);
    m
}

pub fn reencryption(
    ck1: Vec<usize>,
    k2: &[u8; 16],
    k2_2: &[u8; 16],
    ck3: Vec<usize>,
    iv: &[u8; 16],
    c: &Vec<[u8; 16]>,
) -> ([u8; 16], Vec<[u8; 16]>) {
    let n = c.len() - 1;
    let p2 = pg(k2, 16);
    let p2_2 = pg(k2_2, 16);
    let mut c_1: Vec<[u8; 16]> = vec![[0; 16]; n];
    for i in n..0 {
        c_1[i] = permutate(&ck1, &xor(&c[i], &permutate(&p2, &c[i - 1])))
    }
    let mut c_2: Vec<[u8; 16]> = Vec::with_capacity(n + 1);
    c_2.push(xor(
        &permutate(&ck1, &xor(&c[0], &permutate(&p2, &iv))),
        &permutate(&p2_2, &iv),
    ));

    c_2.extend(permutate_vec(&ck3, &c[1..].to_vec()));

    let mut c_res = vec![[0; 16]; n + 1];
    c_res[0] = c[0];
    for i in 1..n + 1 {
        c_res[i] = xor(&c_2[i], &permutate(&p2, &c_2[i - 1]));
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

fn key_generator_with_keys(
    k1: &[u8; 16],
    k2: &[u8; 16],
    k3: &[u8; 16],
    n: usize,
) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
    let p1 = pg(k1, 16);
    let p2 = pg(k2, 16);
    let p3 = pg(k3, n);

    (p1, p2, p3)
}

fn key_generator(
    n: usize,
) -> (
    Vec<usize>,
    Vec<usize>,
    Vec<usize>,
    [u8; 16],
    [u8; 16],
    [u8; 16],
) {
    let t_k1 = new_random_arr::<16>();
    let t_k2 = new_random_arr::<16>();
    let t_k3 = new_random_arr::<16>();

    let p1 = pg(&t_k1, 16);
    let p2 = pg(&t_k2, 16);
    let p3 = pg(&t_k3, n);

    (p1, p2, p3, t_k1, t_k2, t_k3)
}

pub fn reencryption_key_generator<'a>(
    k1: &[u8; 16],
    k2: &'a [u8; 16],
    k3: &[u8; 16],
    n: usize,
) -> (Vec<usize>, &'a [u8; 16], [u8; 16], Vec<usize>) {
    let (p1, _p2, p3) = key_generator_with_keys(k1, k2, k3, n);
    let (p1_1, _p2_1, p3_1, _k1_1, k2_1, _k3_1) = key_generator(n);
    let ck1 = find_conversion_key(&p1, &p1_1);
    let ck3 = find_conversion_key(&p3, &p3_1);

    (ck1, k2, k2_1, ck3)
}
