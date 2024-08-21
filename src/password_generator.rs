use rand::{rngs::StdRng, Rng, SeedableRng};
use std::fs::File;

/// This function generates a password of a given length
pub fn generate_password(length: u32) -> String {
    // Define a character pool
    let character_pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let character_pool_len = character_pool.len();

    // Generate a random seed using StdRng for extra security
    let mut rng = StdRng::from_entropy();

    // Generate the password
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

/// This function will provide a safety rating from 0 to 50 based on several factors like length, character diversity, 
/// whether it is on a common password list, etc.
pub fn check_password_safety(password: &str) -> (u32, Vec<String>) {
    let mut safety_rating = 0;
    let mut safety_message: Vec<String>= Vec::new();

    // Check if the password is on a common password list from the storage/100k-most-used-passwords.txt file
    use std::io::{BufRead, BufReader};
    
    let common_passwords = BufReader::new(File::open("storage/100k-most-used-passwords-NCSC.txt").expect("Failed to open common passwords file"));
    if common_passwords.lines().any(|line| line.unwrap() == password) {
        safety_message.push("This password is on a common password list".to_string());
        return (0, safety_message);
    } else {
        safety_rating += 15;
    }

    // Check if the password is at least 8 characters long
    if password.len() >= 8 {
        safety_rating += 5;
    } else {
        safety_message.push("This password is too short".to_string());
        return (10, safety_message);
    }

    // Check if the password has more than 8 distinct characters
    let mut distinct_characters = 0;
    for char in password.chars() {
        if password.chars().filter(|c| c == &char).count() == 1 {
            distinct_characters += 1;
        }
    }
    if distinct_characters >= 6 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password() {
        let password = generate_password(16);
        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_check_password_safety() {
        let (safety_rating, safety_message) = check_password_safety("password");
        assert_eq!(safety_rating, 0);
        assert_eq!(safety_message, vec!["This password is on a common password list".to_string()]);

        let (safety_rating, safety_message) = check_password_safety("password123");
        assert_eq!(safety_rating, 0);
        assert_eq!(safety_message, vec!["This password is on a common password list".to_string()]);

        let (safety_rating, safety_message) = check_password_safety("P@ssw0rd123");
        assert_eq!(safety_rating, 50);
        let empty_vec: Vec<String> = Vec::new();
        assert_eq!(safety_message, empty_vec);
    }

    #[test]
    fn test_good_password() {
        let password = "[bX+L+$8x4T7";
        let (safety_rating, safety_message) = check_password_safety(password);
        assert_eq!(safety_rating, 50);
        let empty_vec: Vec<String> = Vec::new();
        assert_eq!(safety_message, empty_vec);
    }

    #[test]
    fn test_bad_passwords_not_common() {
        // No uppercase letters
        let (safety_rating, safety_message) = check_password_safety("[bx+l+$8x4t7");
        assert_eq!(safety_rating, 45);
        assert_eq!(safety_message, vec!["This password has no uppercase letters".to_string()]);

        // No lowercase letters
        let (safety_rating, safety_message) = check_password_safety("[BX+L+$8X4T7");
        assert_eq!(safety_rating, 45);
        assert_eq!(safety_message, vec!["This password has no lowercase letters".to_string()]);

        // No numbers
        let (safety_rating, safety_message) = check_password_safety("[bX+L+$xT");
        assert_eq!(safety_rating, 45);
        assert_eq!(safety_message, vec!["This password has no numbers".to_string()]);

        // No special characters
        let (safety_rating, safety_message) = check_password_safety("bXLP8x4T7");
        assert_eq!(safety_rating, 45);
        assert_eq!(safety_message, vec!["This password has no special characters".to_string()]);

        // Not enough distinct characters
        let (safety_rating, safety_message) = check_password_safety("XXX]X4t7X");
        assert_eq!(safety_rating, 40);
        assert_eq!(safety_message, vec!["This password has too few distinct characters".to_string()]);

        // No special characters and no numbers
        let (safety_rating, safety_message) = check_password_safety("bXLPxTxYpT");
        assert_eq!(safety_rating, 40);
        assert_eq!(safety_message, vec!["This password has no numbers".to_string(), "This password has no special characters".to_string()]);

        // Too short
        let (safety_rating, safety_message) = check_password_safety("[BX+l");
        assert_eq!(safety_rating, 10);
        assert_eq!(safety_message, vec!["This password is too short".to_string()]);


    }
}