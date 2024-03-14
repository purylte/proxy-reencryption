use crate::util::{encrypt, hash, new_random_arr, xor};

pub fn e_aonth(ctr: u8, m: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let n = m.len();
    let k_1 = new_random_arr::<16>();

    let mut x = vec![[0; 16]; n + 1];
    for i in 0..n {
        x[i] = xor(&m[i], &encrypt(ctr + 1, &k_1));
    }

    let mut m_1 = vec![[0; 16]; n + 1];
    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    m_1[n] = xor(&k_1, &hash(&x_alloc));

    let mut ctr_bytes = [0u8; 16];
    for i in 0..n {
        ctr_bytes[15] = ctr + i as u8;
        m_1[i] = xor(&x[i], &hash(&xor(&m_1[n], &ctr_bytes)))
    }

    m_1
}

pub fn d_aonth(ctr: u8, m_1: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let n = m_1.len() - 1;
    let mut x = vec![[0; 16]; n];
    let mut ctr_bytes = [0u8; 16];

    for i in 0..n {
        ctr_bytes[15] = ctr + i as u8;
        x[i] = xor(&m_1[i], &hash(&xor(&m_1[n], &ctr_bytes)))
    }

    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    let k_1 = xor(&m_1[n], &hash(&x_alloc));

    let mut m = vec![[0; 16]; n];
    for i in 0..n {
        m[i] = xor(&x[i], &encrypt(ctr + 1, &k_1));
    }

    m
}
