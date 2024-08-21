use rand::{rngs::StdRng, Rng, SeedableRng};
use Option;
use std::fs::File;

pub fn generate_password(length: u32) -> String {
    let character_pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let character_pool_len = character_pool.len();

    let mut rng = StdRng::from_entropy();
    // It will be organized in blocks of 4 to be easier to remember with a dash between each block

    let mut password = String::new();
    for i in 0..length {
        if i % 4 == 0 && i != 0 {
            password.push('-');
            continue;
        }
        let character = rng.gen_range(0..character_pool_len);
        password.push(character_pool.chars().nth(character).unwrap());
    }

    password
}

/// this function will provide a safety rating from 0 to 50 based on several factors like length, character diversity, 
/// whether it is on a common password list, etc.
pub fn check_password_safety(password: &str) -> (u32, Vec<String>) {
    let mut safety_rating = 0;
    let mut safety_message: Vec<String>= Vec::new();

    // Check if the password is on a common password list from the storage/100k-most-used-passwords.txt file
    use std::io::{BufRead, BufReader};
    
    let common_passwords = BufReader::new(File::open("storage/100k-most-used-passwords.txt").expect("Failed to open common passwords file"));
    if common_passwords.lines().any(|line| line.unwrap() == password) {
        safety_message.push("This password is on a common password list".to_string());
    } else {
        safety_rating += 15;
    }

    // Check if the password is at least 8 characters long
    if password.len() >= 8 {
        safety_rating += 5;
    } else {
        safety_message.push("This password is too short".to_string());
    }

    // Check if the password has more than 8 distinct characters
    let mut distinct_characters = 0;
    for character in password.chars() {
        if !password.chars().filter(|&c| c == character).collect::<Vec<char>>().contains(&character) {
            distinct_characters += 1;
        }
    }
    if distinct_characters >= 8 {
        safety_rating += 10;
    } else {
        safety_message.push("This password has too few distinct characters".to_string());
    }

    // Check if the password has at least one uppercase letter
    if password.chars().any(|c| c.is_uppercase()) {
        safety_rating += 5;
    } else {
        safety_message.push("This password has no uppercase letters".to_string());
    }

    // Check if the password has at least one lowercase letter
    if password.chars().any(|c| c.is_lowercase()) {
        safety_rating += 5;
    } else {
        safety_message.push("This password has no lowercase letters".to_string());
    }

    // Check if the password has at least one number
    if password.chars().any(|c| c.is_numeric()) {
        safety_rating += 5;
    } else {
        safety_message.push("This password has no numbers".to_string());
    }

    // Check if the password has at least one special character
    if password.chars().any(|c| !c.is_alphanumeric()) {
        safety_rating += 5;
    } else {
        safety_message.push("This password has no special characters".to_string());
    }

    (safety_rating, safety_message)
}