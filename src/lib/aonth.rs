use crate::util::{encrypt, hash, new_random_arr, xor};
// E-AONTH algorithm
pub fn e_aonth(ctr: u8, m: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let n = m.len();
    let k_1 = new_random_arr::<16>();

    let mut x = Vec::with_capacity(n + 1);
    for i in 0..n {
        x[i] = xor(&m[i].to_vec(), &encrypt(ctr + 1, &k_1).to_vec());
    }

    // m'[n + 1] = K' ⊕ H (x[1]...x[n])
    let mut m1 = Vec::with_capacity(n + 1);
    m1.extend_from_slice(m);

    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    m1.push(
        xor(&k_1.to_vec(), &hash(&x_alloc).to_vec())
            .try_into()
            .unwrap(),
    );

    let mut ctr_bytes = vec![0u8; 16];
    for i in 0..n {
        ctr_bytes[15] = ctr + i as u8;
        m1[i] = xor(
            &x[i].to_vec(),
            &hash(&xor(&m1[n + 1].to_vec(), &ctr_bytes)).to_vec(),
        )
        .try_into()
        .unwrap()
    }

    m1
}

pub fn d_aonth(ctr: u8, m_1: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let n = m_1.len() - 1;
    let mut x = Vec::with_capacity(n);
    let mut ctr_bytes = vec![0u8; 16];
    for i in 0..n {
        ctr_bytes[15] = ctr + i as u8;
        x[i] = xor(
            &m_1[i].to_vec(),
            &hash(&xor(&m_1[n + 1].to_vec(), &ctr_bytes)).to_vec(),
        )
    }

    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    let k_1: [u8; 16] = xor(&m_1[n + 1].to_vec(), &hash(&x_alloc).to_vec())
        .try_into()
        .unwrap();

    let mut m = Vec::with_capacity(n);
    for i in 0..n {
        m[i] = xor(&x[i].to_vec(), &encrypt(ctr + 1, &k_1).to_vec())
            .try_into()
            .unwrap();
    }

    m
}
