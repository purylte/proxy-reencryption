//! This module provides an implementation of the symmetric proxy re-encryption.

use std::io::{Error, ErrorKind, Result};

use crate::{
    aonth::{d_aonth, e_aonth},
    key_generator::{key_generator, key_generator_with_keys, pg},
    permutation::{depermutate, depermutate_vec, find_conversion_key, permutate, permutate_vec},
    utils::{new_random_arr, xor},
};

/// This struct represents a proxy re-encryption system.
pub struct ProxyReencryption;

impl ProxyReencryption {
    /// Encrypts data using the proxy re-encryption scheme.
    ///
    /// # Arguments
    ///
    /// - `k1`: The first key.
    /// - `k2`: The second key.
    /// - `k3`: The third key.
    /// - `ctr`: The counter.
    /// - `m`: The data to encrypt.
    ///
    /// # Returns
    ///
    /// - `iv`: The initialization vector.
    /// - `c`: The encrypted data.
    pub fn encryption(
        k1: &Key<16>,
        k2: &Key<16>,
        k3: &Key<16>,
        ctr: u64,
        m: &Blocks,
    ) -> ([u8; 16], Blocks) {
        let n = m.blocks.len();

        // (P1, P2, P3) <- G(0, K1, K2, K3)
        let (p1, p2, p3) = key_generator_with_keys(k1, k2, k3, n);

        // iv <- {0,1}^l
        let iv: [u8; 16] = new_random_arr::<16>();

        // m'[1]...m'[n+1] <- E-AONTH(ctr, m[1]...m[n])
        let m_1: Vec<[u8; 16]> = e_aonth(ctr, &m.blocks);

        // m''[1]...m''[n] <- PEp3(m'[1]...m'[n])
        let m_2: Vec<&[u8; 16]> = permutate_vec(&p3, &m_1[..n]);

        // c[0] <- PEp1(m'[n+1][1...l]) xor PEp2(iv[i...l])
        let mut c: Vec<[u8; 16]> = vec![[0; 16]; n + 1];
        c[0] = xor(&permutate(&p1, &(m_1[n])), &permutate(&p2, &iv));

        // for i = i to n
        for i in 0..n {
            // c[1] <- PEp1(m''[i][i...l]) xor PEp2(c[i-1][1...l])
            c[i + 1] = xor(&permutate(&p1, &m_2[i]), &permutate(&p2, &c[i]))
        }

        (iv, Blocks::new(c))
    }

    /// Decrypts data using the proxy re-encryption scheme.
    ///
    /// # Arguments
    ///
    /// - `k1`: The first key.
    /// - `k2`: The second key.
    /// - `k3`: The third key.
    /// - `ctr`: The counter.
    /// - `iv`: The initialization vector.
    /// - `c`: The encrypted data.
    ///
    /// # Returns
    ///
    /// - `m`: The decrypted data.
    pub fn decryption(
        k1: &Key<16>,
        k2: &Key<16>,
        k3: &Key<16>,
        ctr: u64,
        iv: &[u8; 16],
        c: Blocks,
    ) -> Blocks {
        let n = c.blocks.len() - 1;
        // (P1, P2, P3) <- G(0, K1, K2, K3)
        let (p1, p2, p3) = key_generator_with_keys(k1, k2, k3, n);

        let mut m_2: Vec<[u8; 16]> = vec![[0; 16]; n];
        // for i = n to 1
        for i in (0..n).rev() {
            // m[i]'' <- DPp1(c[1] xor PEp2(c[i-1][1...l]))
            m_2[i] = depermutate(&p1, &xor(&c.blocks[i + 1], &permutate(&p2, &c.blocks[i])));
        }
        // m'[n+1] = DPp1(c[0][1...l] xor PEp2(iv[i...l]))
        // m'[n]...m'[n] <- DPp3(m''[1]...m''[n])
        let mut m_1: Vec<[u8; 16]> = Vec::with_capacity(n + 1);
        m_1.extend(depermutate_vec(&p3, &m_2));
        m_1.push(depermutate(&p1, &xor(&c.blocks[0], &permutate(&p2, &iv))));
        // m[1]...m[n] <- D-AONTH(ctr, m'[1]...m'[n+1])
        let m = d_aonth(ctr, &m_1);
        Blocks::new(m)
    }

    /// Re-encrypts data using the proxy re-encryption scheme.
    ///
    /// # Arguments
    ///
    /// - `ck1`: The conversion key for the first key.
    /// - `k2`: The second key.
    /// - `k2_1`: The second key for re-encryption.
    /// - `ck3`: The conversion key for the third key.
    /// - `iv`: The initialization vector.
    /// - `c`: The encrypted data.
    ///
    /// # Returns
    ///
    /// - `iv`: The new initialization vector.
    /// - `c`: The re-encrypted data.
    pub fn reencryption(
        ck1: Vec<usize>,
        k2: &Key<16>,
        k2_1: &Key<16>,
        ck3: Vec<usize>,
        iv: &[u8; 16],
        c: Blocks,
    ) -> ([u8; 16], Blocks) {
        let n = c.blocks.len() - 1;
        // P2 <- PGk2(l)
        let p2 = pg(k2, 16);
        // P2_1 <- PGk2_1(l)
        let p2_1 = pg(k2_1, 16);

        let mut c_1: Vec<[u8; 16]> = vec![[0; 16]; n];
        // for i = n to 1
        for i in (0..n).rev() {
            // c'[i] <- PEck1(c[i] xor PEp2(c[i-1][i...l]))
            let temp1 = &permutate(&p2, &c.blocks[i]);

            let temp2 = &xor(&c.blocks[i + 1], temp1);
            c_1[i] = permutate(&ck1, temp2);
        }
        // c''[1]...c''[n] <- PECK3(c'[1]...c'[n])
        // c''[0] = PECK1(c[0] xor PEP2(iv[1...l])) xor PEP2'(iv[1...l])
        let mut c_2: Vec<[u8; 16]> = Vec::with_capacity(n + 1);
        c_2.push(xor(
            &permutate(&ck1, &xor(&c.blocks[0], &permutate(&p2, &iv))),
            &permutate(&p2_1, &iv),
        ));
        c_2.extend(permutate_vec(&ck3, &c_1));
        for i in 0..n {
            // c[i] <- c''[i] xor PEp'2(c''[i-1][1...l])
            c_2[i + 1] = xor(&c_2[i + 1], &permutate(&p2_1, &c_2[i]));
        }

        (*iv, Blocks::new(c_2))
    }

    /// Generates keys for re-encryption.
    ///
    /// # Arguments
    ///
    /// - `k1`: The first key.
    /// - `k2`: The second key.
    /// - `k3`: The third key.
    /// - `n`: The number of blocks.
    ///
    /// # Returns
    ///
    /// - `ck1`: The conversion key for the first key.
    /// - `k2`: The second key.
    /// - `k2_1`: The second key for re-encryption.
    /// - `ck3`: The conversion key for the third key.
    /// - `k1_1`: The first key for re-encryption.
    /// - `k3_1`: The third key for re-encryption.
    pub fn reencryption_key_generator<'a>(
        k1: &Key<16>,
        k2: &'a Key<16>,
        k3: &Key<16>,
        n: usize,
    ) -> (
        Vec<usize>,
        &'a Key<16>,
        Key<16>,
        Vec<usize>,
        Key<16>,
        Key<16>,
    ) {
        let (p1, _p2, p3) = key_generator_with_keys(&k1, &k2, &k3, n);
        let (p1_1, _p2_1, p3_1, k1_1, k2_1, k3_1) = key_generator(n);
        let ck1 = find_conversion_key(&p1, &p1_1);
        let ck3 = find_conversion_key(&p3, &p3_1);

        (ck1, k2, k2_1, ck3, k1_1, k3_1)
    }
}

/// Represents a cryptographic key of a fixed size.
pub struct Key<const N: usize> {
    /// The actual key bytes.
    pub key: [u8; N],
}

impl<const N: usize> Key<N> {
    /// Creates a new `Key` from a byte array.
    pub fn new(key: [u8; N]) -> Self {
        Self { key }
    }
    /// Creates a new `Key` from a vector of bytes.
    pub fn from_vec(vec: Vec<u8>) -> Self {
        let key = vec
            .as_slice()
            .try_into()
            .expect("Key bytes length is wrong");
        Self { key }
    }
}

/// Represents a collection of 16-byte blocks.
#[derive(Clone)]
pub struct Blocks {
    /// The actual blocks.
    pub blocks: Vec<[u8; 16]>,
}
// use PKCS7 Padding
impl Blocks {
    /// Creates a new `Blocks` from a vector of 16-byte blocks.
    pub fn new(blocks: Vec<[u8; 16]>) -> Self {
        Self { blocks }
    }

    /// Creates a new `Blocks` from a vector of bytes, applying PKCS#7 padding.
    pub fn from_vec(data: Vec<u8>) -> Self {
        let block_size = 16;
        let padding_needed = (block_size - (data.len() % block_size)) % block_size;
        let padding_value = if padding_needed == 0 {
            block_size
        } else {
            padding_needed
        };
        let mut padded_data = data;
        padded_data.extend(vec![padding_value as u8; padding_value]);

        let blocks = padded_data
            .chunks(block_size)
            .map(|chunk| {
                let mut array = [0u8; 16];
                array.copy_from_slice(chunk);
                array
            })
            .collect();

        Self { blocks }
    }

    /// Creates a new `Blocks` from a vector of bytes without applying padding.
    pub fn from_vec_no_pad(data: Vec<u8>) -> Self {
        let block_size = 16;
        let padding_needed = (block_size - (data.len() % block_size)) % block_size;
        assert_eq!(padding_needed, 0, "Invalid ciphertext length");
        let blocks = data
            .chunks(block_size)
            .map(|chunk| {
                let mut array = [0u8; 16];
                array.copy_from_slice(chunk);
                array
            })
            .collect();

        Self { blocks }
    }
    /// Removes PKCS#7 padding from the blocks.
    pub fn remove_padding(&self) -> Result<Vec<u8>> {
        if let Some(last_block) = self.blocks.last() {
            let padding_value = last_block[15] as usize;
            if padding_value == 0 || padding_value > 16 {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid PKCS#7 padding"));
            }
            let total_length = self.blocks.len() * 16;
            let unpadded_length = total_length - padding_value;
            let mut data = Vec::with_capacity(unpadded_length);
            for block in &self.blocks[..self.blocks.len() - 1] {
                data.extend_from_slice(block);
            }
            data.extend_from_slice(&last_block[..16 - padding_value]);
            Ok(data)
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "No data to unpad"))
        }
    }
}

#[cfg(test)]
mod proxy_reencryption_test {
    use crate::proxy_reencryption_lib::{Blocks, Key, ProxyReencryption};

    #[test]
    fn encrypt_symmetric_tests() {
        let k1 = Key::new([
            11, 12, 13, 14, 15, 16, 17, 18, 19, 110, 111, 112, 113, 114, 115, 116,
        ]);
        let k2 = Key::new([
            21, 22, 23, 24, 25, 26, 27, 28, 29, 210, 211, 212, 213, 214, 215, 216,
        ]);
        let k3 = Key::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let ctr = 5;
        let m = Blocks::new(vec![
            [
                122, 121, 233, 41, 213, 162, 222, 34, 12, 31, 2, 131, 241, 136, 242, 123,
            ],
            [
                3, 240, 238, 236, 123, 27, 18, 219, 182, 3, 61, 37, 47, 153, 104, 37,
            ],
            [
                244, 189, 162, 112, 38, 189, 169, 223, 43, 169, 252, 33, 229, 26, 197, 41,
            ],
            [
                166, 151, 86, 20, 73, 50, 189, 91, 163, 72, 98, 186, 136, 97, 160, 10,
            ],
        ]);

        // let m = vec![[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]];
        let (iv, c) = ProxyReencryption::encryption(&k1, &k2, &k3, ctr, &m);
        let m_1 = ProxyReencryption::decryption(&k1, &k2, &k3, ctr, &iv, c);
        assert_eq!(
            m.remove_padding().expect("Failed to unpad m"),
            m_1.remove_padding().expect("Failed to unpad m_1")
        );
    }

    #[test]
    fn reencryption_tests() {
        let k1 = Key::new([
            11, 12, 13, 14, 15, 16, 17, 18, 19, 110, 111, 112, 113, 114, 115, 116,
        ]);
        let k2 = Key::new([
            21, 22, 23, 24, 25, 26, 27, 28, 29, 210, 211, 212, 213, 214, 215, 216,
        ]);
        let k3 = Key::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let ctr = 5;
        let m = Blocks::new(vec![
            [
                122, 121, 233, 41, 213, 162, 222, 34, 12, 31, 2, 131, 241, 136, 242, 123,
            ],
            [
                3, 240, 238, 236, 123, 27, 18, 219, 182, 3, 61, 37, 47, 153, 104, 37,
            ],
            [
                244, 189, 162, 112, 38, 189, 169, 223, 43, 169, 252, 33, 229, 26, 197, 41,
            ],
            [
                166, 151, 86, 20, 73, 50, 189, 91, 163, 72, 98, 186, 136, 97, 160, 10,
            ],
        ]);

        let (iv, c) = ProxyReencryption::encryption(&k1, &k2, &k3, ctr, &m);
        let (ck1, k2, k2_1, ck3, k1_1, k3_1) =
            ProxyReencryption::reencryption_key_generator(&k1, &k2, &k3, m.blocks.len());
        let (iv, c_2) = ProxyReencryption::reencryption(ck1, &k2, &k2_1, ck3, &iv, c);
        let m_new = ProxyReencryption::decryption(&k1_1, &k2_1, &k3_1, ctr, &iv, c_2);
        assert_eq!(m.blocks, m_new.blocks);
    }
    #[test]
    fn pad_tests() {
        let input = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27,
        ];
        let x = Blocks::from_vec(input.clone());
        assert_eq!(input, x.remove_padding().expect("Failed to unpad x"));
    }
}
