use crate::encryption_algorithms::encrypt_password;
use crate::encryption_algorithms::decrypt_password;
use std::io::{Error, ErrorKind};
use std::str;
use rusqlite;

pub fn add_user_id(user_account: &str) -> Result<(), Error> {
    let conn = rusqlite::Connection::open("storage/passwords.db").unwrap();
    // First, we find the largest user_id, then we add 1 to it
    let mut statement = conn.prepare("SELECT MAX(user_id) FROM user_id").unwrap();
    let max: i32 = statement.query_row([], |row| row.get(0)).unwrap();
    
    let user_id = max + 1;

    // Add a check to make sure a user account with that name doesn't exist yet

    conn.execute(
        "INSERT INTO user_id (user_account, user_id) VALUES (?, ?)",
        rusqlite::params![user_account, user_id]
    );

    Ok(())
}

pub fn get_user_id(user_account: &str) -> Result<i32, Error> {
    let conn = rusqlite::Connection::open("storage/passwords.db").unwrap();
    let mut user_id = 0;
    let mut statement = conn.prepare("SELECT user_id FROM user_id WHERE user_account = ?").unwrap();
    let mut rows = statement.query(&[&user_account]).unwrap();

    while let Some(row) = rows.next().unwrap() {
        user_id = row.get(0).unwrap();
    }

     if user_id == 0 {
        println!("User not found, would you like to add them? (y/n)");
        let mut response = String::new();
        std::io::stdin().read_line(&mut response).expect("Failed to read line");
        if response == "y" {
            add_user_id(user_account);
        } else {
            return Err(Error::new(ErrorKind::Other, "User not found"));
        }
    }

    Ok(user_id)
}

// Do initital constant value checking
// This is not extremelty important, since if the value is correct even with the wrong password, the passwords will be gibberish

// Add a password/Account pair

pub fn add_password(user_id: i32, account: &str, password: &str, hashed_master: &[u8], website: &str) -> Result<(), Error> {
    // master password can be stored within the main function as soon as you enter it, without ever being stored on the disk

    // as long as external and debugging tools are off, you cannot access this memory
    let encrypted_password = encrypt_password(password, hashed_master);
    let encrypted_account = encrypt_password(account, hashed_master);
    let encrypted_website = encrypt_password(website, hashed_master);

    let conn = rusqlite::Connection::open("storage/passwords.db").unwrap();

    conn.execute(
        "INSERT INTO passwords (userID, account, password, website) VALUES (?, ?, ?, ?)",
        rusqlite::params![user_id, encrypted_account, encrypted_password, encrypted_website]
    ).expect("Failed to add password");

    Ok(())
}

// Get a password given an account

// Decrypt all of the account names and return them in order 
// (also returns password names, but keeps them under the hood until user asks for them)

pub fn get_accounts(hashed_master: &[u8], user_id: i32) -> [Vec<String>; 3] {
    let conn = rusqlite::Connection::open("storage/passwords.db").unwrap();
    // Filter so only the user's accounts are shown
    let mut accounts = Vec::new();
    let mut websites = Vec::new();
    let mut passwords = Vec::new();
    let mut statement = conn.prepare("SELECT account, website, password FROM passwords where userID = ?").unwrap();

    struct Account {
        account: String,
        website: String,
        password: String
    }
    
    let rows_iter = statement.query_map(&[&user_id], |row| {
        Ok(Account {
            account: row.get(0)?,
            website: row.get(1)?,
            password: row.get(2)?
        })
    });

    for account in rows_iter.unwrap() {
        let account = account.unwrap();
        accounts.push(decrypt_password(&account.account.as_bytes(), hashed_master));
        websites.push(decrypt_password(&account.website.as_bytes(), hashed_master));
        passwords.push(decrypt_password(&account.password.as_bytes(), hashed_master));
    }
    
    [accounts, websites, passwords]
}

// Remove a password/Account pair

pub fn remove_password(account_name: &str) -> Result<(), Error> {
    // This function can be used without the master password, since you will have to see the accounts to use the function
    // First, we find where on the list it is, then we go that index in the file and remove it
    let conn = rusqlite::Connection::open("storage/passwords.db").unwrap();

    // Now, we find all accounts with that name (In the future, I'll add the ability to select which to delete if there are multiple)
    // I may also have a delete straight by account number, so that the user can click to delete

    // We delete these rows from the database
    conn.execute("DELETE FROM passwords WHERE account = ?", &[&account_name]);

    Ok(())
}