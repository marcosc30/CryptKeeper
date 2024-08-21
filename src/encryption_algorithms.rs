extern crate crypto;
extern crate hex;
extern crate rand;

use sha2::{Sha256, Digest};
use crypto::aes::KeySize::KeySize256;
use crypto::aes::cbc_encryptor;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use rand::Rng;
use std::str;
use crypto::aes::cbc_decryptor;

/// Hash the master password
pub fn hash_master(password: &str, salt: [u8; 32]) -> [u8; 32] {
    // We check since the limit for a password and a hash is 2^64-1 bits
    if password.as_bytes().len() > 2u64.pow(61) as usize {
        panic!("Password is too long");
    }

    // Represent the password as bytes and start a new hasher instance
    let converted_password = password.as_bytes();
    let mut hasher = Sha256::new();

    // Hash the password and salt
    hasher.update(converted_password);
    hasher.update(&salt);
    let result = hasher.finalize();

    // Copy the result into a fixed-size array
    let mut hashed_password = [0; 32];
    hashed_password.copy_from_slice(&result[..]);

    hashed_password
}

// Encrypt a password, also used to encrypt other data like account names and website names
pub fn encrypt_password(password: &str, key: &[u8; 32]) -> Vec<u8> {
    // Generate a random IV
    let iv: [u8; 16] = rand::thread_rng().gen();

    // Create an encryptor instance
    let mut encryptor = cbc_encryptor(KeySize256, key, &iv, PkcsPadding);

    // Buffer setup
    let mut read_buffer = RefReadBuffer::new(password.as_bytes());
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    // Perform encryption
    let mut encrypted_data = Vec::new();
    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        encrypted_data.extend(write_buffer.take_read_buffer().take_remaining().iter().copied());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    // Combine IV and ciphertext
    [iv.to_vec(), encrypted_data].concat()
}

/// Decrypt a password or other data
pub fn decrypt_password(encrypted_data: &[u8], key: &[u8]) -> String {
    // Split the IV and ciphertext
    let (iv, ciphertext) = encrypted_data.split_at(16);

    // Create a decryptor instance
    let mut decryptor = cbc_decryptor(KeySize256, key, iv, PkcsPadding);

    // Buffer setup
    let mut read_buffer = RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    // Perform decryption
    let mut decrypted_data = Vec::new();
    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        decrypted_data.extend(write_buffer.take_read_buffer().take_remaining().iter().copied());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    // Convert the decrypted data to a string
    String::from_utf8(decrypted_data).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hash_master() {
        let password = "supersecret";
        let salt = [0u8; 32]; // Using a zeroed salt for simplicity

        // Hash the master password
        let hashed_password = hash_master(password, salt);

        // Ensure the hashed password is 32 bytes long
        assert_eq!(hashed_password.len(), 32);

        // Hash the same password with the same salt again
        let hashed_password_again = hash_master(password, salt);

        // Ensure the hashed passwords are the same
        assert_eq!(hashed_password, hashed_password_again);
    }

    #[test]
    fn test_hash_master_with_different_salts() {
        let password = "supersecret";
        let salt1 = [0u8; 32]; // Using a zeroed salt for simplicity
        let salt2 = [1u8; 32]; // Using a different salt

        // Hash the master password with the first salt
        let hashed_password1 = hash_master(password, salt1);

        // Hash the master password with the second salt
        let hashed_password2 = hash_master(password, salt2);

        // Ensure the hashed passwords are different
        assert_ne!(hashed_password1, hashed_password2);
    }

    #[test]
    fn test_hash_master_with_different_passwords() {
        let password1 = "supersecret";
        let password2 = "anothersecret";
        let salt = [0u8; 32]; // Using a zeroed salt for simplicity

        // Hash the first password
        let hashed_password1 = hash_master(password1, salt);

        // Hash the second password
        let hashed_password2 = hash_master(password2, salt);

        // Ensure the hashed passwords are different
        assert_ne!(hashed_password1, hashed_password2);
    }

    #[test]
    fn test_encrypt_decrypt_password() {
        let password = "supersecret";
        let key = [0u8; 32]; // Using a zeroed key for simplicity

        // Encrypt the password
        let encrypted_password = encrypt_password(password, &key);

        // Ensure the encrypted password is not the same as the original password
        assert_ne!(password.as_bytes(), &encrypted_password[..]);
        
        // Decrypt the password
        let decrypted_password = decrypt_password(&encrypted_password, &key);

        // Ensure the decrypted password is the same as the original password
        assert_eq!(password, decrypted_password);
    }

    #[test]
    fn test_encrypt_decrypt_harder_password_with_real_key() {
        let password = "vjyuk32ropk'fmi34o;u[4";
        let key = "fhwebsdkfuyr1[23r4ibth34--";
        let salt = [0u8; 32]; // Using a zeroed salt for simplicity

        let hashed_key = hash_master(key, salt);
        
        // Encrypt the password
        let encrypted_password = encrypt_password(password, &hashed_key);

        // Decrypt the password
        let decrypted_password = decrypt_password(&encrypted_password, &hashed_key);

        // Ensure the decrypted password is the same as the original password
        assert_eq!(password, decrypted_password);
    }
}