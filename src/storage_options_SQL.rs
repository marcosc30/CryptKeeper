use crate::encryption_algorithms::encrypt_password;
use crate::encryption_algorithms::decrypt_password;
use std::io::Error;
use std::str;
use rusqlite;

/// Creates a new user in the database
pub fn add_user_id(user_account: &str, hashed_master: &[u8; 32], salt: &[u8; 32], kdf_salt: &[u8; 32]) -> Result<i32, Error> {
    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");
    // Find the largest user_id, then we add 1 to it to define the new user_id
    let mut statement = conn.prepare("SELECT MAX(user_id) FROM user_id").expect("Failed to prepare statement");
    let max: i32 = statement.query_row([], |row| row.get(0)).expect("Failed to get max user_id");
    let user_id = max + 1;

    // Convert the hashed_master to a vector
    let hashed_master_vector = hashed_master.to_vec();

    // Check to make sure a user account with that name doesn't exist yet
    let mut statement = conn.prepare("SELECT user_id FROM user_id WHERE account = ?").expect("Failed to prepare statement");
    let mut rows = statement.query(&[&user_account]).unwrap();
    if rows.next().unwrap().is_some() {
        return Err(Error::new(std::io::ErrorKind::AlreadyExists, "User account already exists"));
    }
    // This would currently panic the program, but it should be impossible to get to this error in the current setup 
    // So it will be left as a panic

    // Add the user_id to the database
    conn.execute(
        "INSERT INTO user_id (account, user_id, hashed_master_password, salt, kdf_salt) VALUES (?, ?, ?, ?, ?)",
        rusqlite::params![user_account, user_id, hashed_master_vector, salt, kdf_salt]
    ).expect("Failed to add user_id");

    Ok(user_id)
}

/// Get the user_id of a user account
pub fn get_user_id(user_account: &str) -> Result<i32, Error> {
    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    // Find the user_id of the user account
    let mut user_id = 0;
    let mut statement = conn.prepare("SELECT user_id FROM user_id WHERE account = ?").expect("Failed to prepare statement");
    let mut rows = statement.query(&[&user_account]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        user_id = row.get(0).unwrap();
    }

    Ok(user_id)
}

/// Get the salt of a user account
pub fn get_salt(user_id: i32) -> Vec<u8> {
    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    // Find the salt of the user account
    let mut salt = Vec::new();
    let mut statement = conn.prepare("SELECT salt FROM user_id WHERE user_id = ?").expect("Failed to prepare statement");
    let mut rows = statement.query(&[&user_id]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        salt = row.get(0).unwrap();
    }

    salt
}

/// Get the KDF salt of a user account
pub fn get_kdf_salt(user_id: i32) -> Vec<u8> {
    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    // Find the salt of the user account
    let mut salt = Vec::new();
    let mut statement = conn.prepare("SELECT kdf_salt FROM user_id WHERE user_id = ?").expect("Failed to prepare statement");
    let mut rows = statement.query(&[&user_id]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        salt = row.get(0).unwrap();
    }

    salt
}

/// Get the hashed master password of a user account
pub fn get_hashed_master(user_id: i32) -> Vec<u8> {
    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    // Find the hashed master password of the user account
    let mut hashed_master = Vec::new();
    let mut statement = conn.prepare("SELECT hashed_master_password FROM user_id WHERE user_id = ?").expect("Failed to prepare statement");
    let mut rows = statement.query(&[&user_id]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        hashed_master = row.get(0).unwrap();
    }

    hashed_master
}


/// Add a password/account/website triplet to the database
pub fn add_password(user_id: i32, account: &str, password: &str, hashed_master: &[u8; 32], website: &str) -> Result<(), Error> {
    // Encrypt the password, account, and website
    let encrypted_password = encrypt_password(password, hashed_master);
    let encrypted_account = encrypt_password(account, hashed_master);
    let encrypted_website = encrypt_password(website, hashed_master);

    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    // Find the largest entry_id, then we add 1 to it to define the new entry_id
    let mut statement = conn.prepare("SELECT MAX(entry_id) FROM passwords").expect("Failed to prepare statement");
    let max: i32 = statement.query_row([], |row| row.get(0)).expect("Failed to get max entry_id");
    let entry_id = max + 1;

    // Add the details to the database
    conn.execute(
        "INSERT INTO passwords (entry_id, user_id, account, password, website) VALUES (?, ?, ?, ?, ?)",
        rusqlite::params![entry_id, user_id, encrypted_account, encrypted_password, encrypted_website]
    ).expect("Failed to add password");

    Ok(())
}

/// Get all of the accounts for a user by decrypting all of the data
pub fn get_accounts(hashed_master: &[u8; 32], user_id: i32) -> [Vec<String>; 3] {
    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    // Filter so only the user's accounts are shown
    let mut accounts = Vec::new();
    let mut websites = Vec::new();
    let mut passwords = Vec::new();
    let mut statement = conn.prepare("SELECT account, website, password FROM passwords where user_id = ?").unwrap();
    let mut rows = statement.query(&[&user_id]).unwrap();

    // Decrypt the data
    while let Some(row) = rows.next().unwrap() {
        let encrypted_account: Vec<u8> = row.get(0).expect("Failed to get account");
        let encrypted_website: Vec<u8> = row.get(1).expect("Failed to get website");
        let encrypted_password: Vec<u8> = row.get(2).expect("Failed to get password");

        let account = decrypt_password(&encrypted_account, hashed_master);
        let website = decrypt_password(&encrypted_website, hashed_master);
        let password = decrypt_password(&encrypted_password, hashed_master);

        accounts.push(account);
        websites.push(website);
        passwords.push(password);
    }

    [accounts, websites, passwords]
}

/// Find the entry_id of a account/website/password triplet
pub fn find_entry_id(user_id: i32, account: &str, password: &str, website: &str, hashed_master: &[u8; 32]) -> i32 {
    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");
    let mut entry_id = 0;

    // We unencrypt the account names to see which one matchs to find the entry_id
    let mut statement = conn.prepare("SELECT entry_id, account, website, password FROM passwords WHERE user_id = ?").unwrap();
    let mut rows = statement.query(&[&user_id]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let encrypted_account: Vec<u8> = row.get(1).unwrap();
        let encrypted_website: Vec<u8> = row.get(2).unwrap();
        let encrypted_password: Vec<u8> = row.get(3).unwrap();

        let decrypted_account = decrypt_password(&encrypted_account, hashed_master);
        let decrypted_website = decrypt_password(&encrypted_website, hashed_master);
        let decrypted_password = decrypt_password(&encrypted_password, hashed_master);

        if decrypted_account == account && decrypted_website == website && decrypted_password == password {
            entry_id = row.get(0).unwrap();
            break;
        }
    }

    // There is no way to reach this via the GUI, so it will be left as a panic
    if entry_id == 0 {
        panic!("Failed to find entry_id");
    }

    entry_id
}

/// Remove a password/account/website triplet from the database by using the unique entry id
pub fn remove_password(entry_id: i32) -> Result<(), Error> {
    // Open the database
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    // Remove the password
    conn.execute(
        "DELETE FROM passwords WHERE entry_id = ?",
        rusqlite::params![entry_id]
    ).expect("Failed to remove password");
   
    Ok(())
}

/// Change the master password of a user
pub fn change_master_password(user_id: i32, old_master_hashed: &[u8; 32], new_master_hashed: &[u8; 32], new_salt: &[u8; 32], new_kdf_salt: &[u8; 32]) {
    // Open the databases
    let conn = rusqlite::Connection::open("storage/passwords.db").expect("Failed to open database");

    // Update the users database
    conn.execute(
        "UPDATE user_id SET hashed_master_password = ?, salt = ?, kdf_salt = ? WHERE user_id = ?",
        rusqlite::params![new_master_hashed, new_salt, new_kdf_salt, user_id]
    ).expect("Failed to update user_id");

    // Get all of the passwords, which decrypts them so they can be reencrypted later
    let accounts;
    let websites;
    let passwords;
    [accounts, websites, passwords] = get_accounts(old_master_hashed, user_id);
    
    // Rencrypt all of the passwords
    for i in 0..accounts.len() {
        let encrypted_account = encrypt_password(&accounts[i], new_master_hashed);
        let encrypted_website = encrypt_password(&websites[i], new_master_hashed);
        let encrypted_password = encrypt_password(&passwords[i], new_master_hashed);

        conn.execute(
            "UPDATE passwords SET account = ?, website = ?, password = ? WHERE user_id = ?",
            rusqlite::params![encrypted_account, encrypted_website, encrypted_password, user_id]
        ).expect("Failed to update password");
    }
}