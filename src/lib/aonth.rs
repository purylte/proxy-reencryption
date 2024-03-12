use crate::util::{encrypt, hash, xor};
use rand::Rng;

// E-AONTH algorithm
pub fn e_aonth(ctr: u8, m: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let mut k = [0u8; 16];
    rand::thread_rng().fill(&mut k[..]);

    let mut x = Vec::with_capacity(m.len() + 1);
    for i in 0..m.len() {
        x[i] = xor(&m[i].to_vec(), &encrypt(ctr + 1, &k).to_vec());
    }

    // m'[n + 1] = K' ⊕ H (x[1]...x[n])
    let mut m1 = Vec::with_capacity(m.len() + 1);
    m1.extend_from_slice(m);

    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    m1.push(
        xor(&k.to_vec(), &hash(&x_alloc).to_vec())
            .try_into()
            .unwrap(),
    );

    for i in 0..m.len() {
        let mut ctr_bytes = vec![0u8; 16];
        ctr_bytes[15] = ctr + i as u8;
        m1[i] = xor(
            &x[i].to_vec(),
            &hash(&xor(&m1[m.len() + 1].to_vec(), &ctr_bytes)).to_vec(),
        )
        .try_into()
        .unwrap()
    }

    m1
}
