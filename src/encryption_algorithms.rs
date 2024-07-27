use std::string;

// 1. Hash the master password using SHA-256
use sha2::{Sha256, Digest};
use hex;
use aes::Aes256;
use rand::Rng;
use block_cipher::generic_array::GenericArray;
use block_cipher::BlockCipher;
use block_modes::BlockMode;
use block_modes::block_padding::Pkcs7;
use block_modes::block_padding::Pkcs7;

pub fn hash_master(password: &str) -> String {
    let converted_password = password.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(converted_password);
    let result = hasher.finalize();
    hex::encode(result)
}

// 2. Encrypt a given password using the master password

pub fn encrypt_password(password: &str, hashed_master: &str) -> [String; [u8; 16]] {
    //let hashed_master = hash_master(master_password);
    let key = hashed_master.as_bytes();
    let iv: [u8; 16] = rand::thread_rng().gen();
    let cipher = Cbc::<Aes256, Pkcs7>::new_var(&key, &iv).unwrap();
    let result = cipher.encrypt_vec(password.as_bytes());
    [string::from_utf8(result).expect("Error converting to string during encryption"), iv]
}

pub fn decrypt_password(encrypted_password: Vec<u8>, iv:[u8; 16], master_password: &str) -> String {
    let hashed_master = hash_master(master_password);
    let key = hashed_master.as_bytes();
    let cipher = Cbc::<Aes256, Pkcs7>::new_var(&key, &iv).unwrap();
    let result = cipher.decrypt_vec(&encrypted_password).unwrap();
    string::from_utf8(result).expect("Error converting to string during decryption")

}