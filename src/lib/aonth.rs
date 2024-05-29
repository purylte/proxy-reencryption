//! This module provides functions for authenticated encryption and decryption using a variant of AONT (All-or-Nothing Transform) scheme.
//!
//! The AONTH scheme is a method for encrypting data in a way that ensures the integrity and confidentiality of the data.
//!
//! This module includes two main functions: `e_aonth` for encryption and `d_aonth` for decryption.

use crate::utils::{encrypt, hash, new_random_arr, xor};

/// Encrypts data using the AONTH scheme.
///
/// This function takes a counter value and a vector of 16-byte blocks as input and returns a new vector of encrypted blocks.
pub fn e_aonth(ctr: u64, m: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let n = m.len();
    let k_1 = new_random_arr::<16>();

    let x: Vec<[u8; 16]> = m
        .iter()
        .enumerate()
        .map(|(i, block)| xor(block, &encrypt(ctr as u128 + i as u128, &k_1)))
        .collect();

    let mut m_1 = vec![[0; 16]; n + 1];
    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    m_1[n] = xor(&k_1, &hash(&x_alloc));

    for i in 0..n {
        let ctr_bytes = (ctr as u128 + i as u128).to_be_bytes();
        m_1[i] = xor(&x[i], &hash(&xor(&m_1[n], &ctr_bytes)))
    }

    m_1
}

/// Decrypts data using the AONTH scheme.
///
/// This function takes a counter value and a vector of encrypted blocks as input and returns the original data.
pub fn d_aonth(ctr: u64, m_1: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let n = m_1.len() - 1;
    let mut x = vec![[0; 16]; n];

    for i in 0..n {
        let ctr_bytes = (ctr as u128 + i as u128).to_be_bytes();
        x[i] = xor(&m_1[i], &hash(&xor(&m_1[n], &ctr_bytes)))
    }

    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    let k_1 = xor(&m_1[n], &hash(&x_alloc));

    let mut m = vec![[0; 16]; n];
    for i in 0..n {
        m[i] = xor(&x[i], &encrypt(ctr as u128 + i as u128, &k_1));
    }

    m
}

#[cfg(test)]
mod aonth_tests {
    use crate::aonth::{d_aonth, e_aonth};

    #[test]
    fn symmetric_tests() {
        let m = vec![
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [
                254, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
            ],
        ];
        let e = e_aonth(10, &m);
        assert_eq!(d_aonth(10, &e), m);
    }
}
