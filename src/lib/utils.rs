use aes::cipher::BlockEncrypt;
use aes::Aes128;
use crypto_common::typenum::U16;
use crypto_common::{generic_array::GenericArray, KeyInit};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

pub fn hash(x: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(x);
    let digest: [u8; 16] = hasher.finalize().as_slice()[..16].try_into().unwrap();
    digest
}

pub fn xor<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut res = [0u8; N];
    for i in 0..N {
        res[i] = a[i] ^ b[i];
    }
    res
}

pub fn encrypt(plaintext: u128, key: &[u8; 16]) -> [u8; 16] {
    let plaintext_bytes = plaintext.to_be_bytes();
    let mut block: GenericArray<u8, U16> = GenericArray::from(plaintext_bytes);
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut block);

    let res = block.as_slice().try_into().unwrap();
    res
}
pub fn new_random_arr<const N: usize>() -> [u8; N] {
    let mut k = [0u8; N];
    thread_rng().fill(&mut k[..]);
    k
}

#[cfg(test)]
mod tools_test {
    use super::hash;

    #[test]
    fn hash_correctness() {
        let m = [97, 98, 99];
        let answer = [
            186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35,
        ];

        assert_eq!(hash(&m), answer);
    }
}