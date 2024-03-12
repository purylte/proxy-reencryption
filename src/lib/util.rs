use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;
use sha2::{Digest, Sha256};

pub fn hash(x: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(x);
    let digest: [u8; 16] = hasher.finalize().as_slice()[..16].try_into().unwrap();
    digest
}

pub fn xor(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    Vec::new()
}

pub fn encrypt(plaintext: u8, key: &[u8; 16]) -> [u8; 16] {
    let mut longer_bytes = [0u8; 16];
    longer_bytes[longer_bytes.len() - 1] = plaintext;

    let mut block: GenericArray<u8, U16> = GenericArray::from(longer_bytes);
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut block);

    block.as_slice().try_into().unwrap()
}
