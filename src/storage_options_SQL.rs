use crate::encryption_algorithms;
use crate::encryption_algorithms::encrypt_password;
use crate::encryption_algorithms::decrypt_password;
use std::io::{Error, ErrorKind};
use std::str;
use rusqlite;

pub fn add_user_id(user_account: &str, hashed_master: &[u8; 32]) -> Result<i32, Error> {
    // Returns the new user_id of the user account
    let conn = rusqlite::Connection::open("storage/users.db").expect("Failed to open database");
    // First, we find the largest user_id, then we add 1 to it
    let mut statement = conn.prepare("SELECT MAX(user_id) FROM user_id").expect("Failed to prepare statement");
    let max: i32 = statement.query_row([], |row| row.get(0)).expect("Failed to get max user_id");

    let user_id = max + 1;

    let hashed_master_vector = hashed_master.to_vec();

    // Add a check to make sure a user account with that name doesn't exist yet

    conn.execute(
        "INSERT INTO user_id (account, user_id, hashed_master_password) VALUES (?, ?, ?)",
        rusqlite::params![user_account, user_id, hashed_master_vector]
    ).expect("Failed to add user_id");

    Ok(user_id)
}

pub fn get_user_id(user_account: &str) -> Result<i32, Error> {
    let conn = rusqlite::Connection::open("storage/users.db").expect("Failed to open database");
    let mut user_id = 0;
    let mut statement = conn.prepare("SELECT user_id FROM user_id WHERE account = ?").expect("Failed to prepare statement");
    let mut rows = statement.query(&[&user_account]).unwrap();

    while let Some(row) = rows.next().unwrap() {
        user_id = row.get(0).unwrap();
    }

    Ok(user_id)
}

pub fn get_hashed_master(user_id: i32) -> Vec<u8> {
    let conn = rusqlite::Connection::open("storage/users.db").expect("Failed to open database");
    let mut hashed_master = Vec::new();
    let mut statement = conn.prepare("SELECT hashed_master_password FROM user_id WHERE user_id = ?").expect("Failed to prepare statement");
    let mut rows = statement.query(&[&user_id]).unwrap();

    while let Some(row) = rows.next().unwrap() {
        hashed_master = row.get(0).unwrap();
    }

    hashed_master
}


// Add a password/Account pair

pub fn add_password(user_id: i32, account: &str, password: &str, hashed_master: &[u8; 32], website: &str) -> Result<(), Error> {
    // master password can be stored within the main function as soon as you enter it, without ever being stored on the disk

    // as long as external and debugging tools are off, you cannot access this memory
    let encrypted_password = encrypt_password(password, hashed_master);
    let encrypted_account = encrypt_password(account, hashed_master);
    let encrypted_website = encrypt_password(website, hashed_master);

    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    let mut entry_id = 0;
    let mut statement = conn.prepare("SELECT MAX(entry_id) FROM passwords").expect("Failed to prepare statement");
    let max: i32 = statement.query_row([], |row| row.get(0)).expect("Failed to get max entry_id");

    entry_id = max + 1;

    conn.execute(
        "INSERT INTO passwords (entry_id, user_id, account, password, website) VALUES (?, ?, ?, ?, ?)",
        rusqlite::params![entry_id, user_id, encrypted_account, encrypted_password, encrypted_website]
    ).expect("Failed to add password");

    Ok(())
}

// Get a password given an account

// Decrypt all of the account names and return them in order 
// (also returns password names, but keeps them under the hood until user asks for them)

pub fn get_accounts(hashed_master: &[u8; 32], user_id: i32) -> [Vec<String>; 3] {
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");
    // Filter so only the user's accounts are shown
    let mut accounts = Vec::new();
    let mut websites = Vec::new();
    let mut passwords = Vec::new();
    let mut statement = conn.prepare("SELECT account, website, password FROM passwords where user_id = ?").unwrap();

    let mut rows = statement.query(&[&user_id]).unwrap();

    while let Some(row) = rows.next().unwrap() {
        let encrypted_account: Vec<u8> = row.get(0).unwrap();
        let encrypted_website: Vec<u8> = row.get(1).unwrap();
        let encrypted_password: Vec<u8> = row.get(2).unwrap();

        let account = decrypt_password(&encrypted_account, hashed_master);
        let website = decrypt_password(&encrypted_website, hashed_master);
        let password = decrypt_password(&encrypted_password, hashed_master);

        accounts.push(account);
        websites.push(website);
        passwords.push(password);
    }

    [accounts, websites, passwords]
}

pub fn find_entry_id(user_id: i32, account: &str, website: &str, hashed_master: &[u8; 32]) -> i32 {
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");
    let mut entry_id = 0;

    // We must unencrypt the account names to see which one matchs

    let mut statement = conn.prepare("SELECT entry_id, account, website FROM passwords WHERE user_id = ?").expect("Failed to prepare statement");

    let mut rows = statement.query(&[&user_id]).unwrap();

    while let Some(row) = rows.next().unwrap() {
        let encrypted_account: Vec<u8> = row.get(1).unwrap();
        let encrypted_website: Vec<u8> = row.get(2).unwrap();

        let decrypted_account = decrypt_password(&encrypted_account, hashed_master);
        let decrypted_website = decrypt_password(&encrypted_website, hashed_master);

        if decrypted_account == account && decrypted_website == website {
            entry_id = row.get(0).unwrap();
        }
    }

    entry_id
}

// Remove a password/Account pair

pub fn remove_password(entry_id: i32) -> Result<(), Error> {
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    conn.execute(
        "DELETE FROM passwords WHERE entry_id = ?",
        rusqlite::params![entry_id]
    ).expect("Failed to remove password");
   
    Ok(())
}
