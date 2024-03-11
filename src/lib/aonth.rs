use crate::util::{encrypt, hash, xor};
use rand::Rng;

// E-AONTH algorithm
pub fn e_aonth(ctr: u8, m: Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let mut k = [0u8; 16];
    rand::thread_rng().fill(&mut k[..]);

    let mut x = Vec::with_capacity(m.len() + 1);
    for i in 0..m.len() {
        x[i] = m[i] ^ encrypt(ctr + 1, k);
    }

    // m'[n + 1] = K' ⊕ H (x[1]...x[n])
    let mut m1 = Vec::with_capacity(m.len() + 1);
    m1 = m.to_vec();
    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    m1.push(xor(k, hash(&x_alloc)));

    for i in 0..m.len() {
        let mut ctr_bytes = [0u8; 16];
        ctr_bytes[ctr_bytes.len() - 1] = ctr + i as u8;
        m1[i] = xor(x[i], hash(&xor(m1[m.len() + 1], ctr_bytes)))
    }

    m1
}
