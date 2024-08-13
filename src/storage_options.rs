use std::fs::OpenOptions;
use std::io::{Error, Write};
use crate::encryption_algorithms::encrypt_password;
use crate::encryption_algorithms::decrypt_password;

// Do initital constant value checking
// This is not extremelty important, since if the value is correct even with the wrong password, the passwords will be gibberish
pub fn add_constant_value(hashed_master: &str) -> Result<(), Error> {
    // Done during initialization for a new storage option file for users
    // Also, if I want to support multiple users on one program, you just have a constant encrypted value associated to each
    // Account, and only unlock the ones that are associated with the corresponding password
    let constant_val = "constant_value";
    let [encrypted_constant_val, constant_val_iv] = encrypt_password(constant_val, hashed_master);
    // Now we store it in passwords.txt
    let path_str = "storage/passwords.txt";
    let path = Path::new(path_str);

    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(path)?;

    file.write_all(String::from("\n Constant Value: "))?;
    file.write_all(encrypted_constant_val)?;
    file.write_all(String::from("\n Constant Value IV: "))?;
    file.write_all(constant_val_iv)?;
}

// Add a password/Account pair

pub fn add_password(account: &str, password: &str, hashed_master: &str, website: &str) -> Result<(), Error> {
    // master password can be stored within the main function as soon as you enter it, without ever being stored on the disk

    // as long as external and debugging tools are off, you cannot access this memory
    let [encrypted_password, password_iv] = encrypt_password(password, master_password);
    let [encrypted_account, account_iv] = encrypt_password(account, master_password);
    let [encrypted_website, website_iv] = encrypt_password(account, master_password);

    let path_str = "storage/passwords.txt";
    let path = Path::new(path_str);

    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(path)?;

    file.write_all(String::from("\n Account: "))?;
    file.write_all(encrypted_account)?;
    file.write_all(String::from("\n Account IV: "))?;
    file.write_all(account_iv)?;
    file.write_all(String::from("\n Password: "))?;
    file.write_all(encrypted_password)?;
    file.wite_all(String::from("\n Password IV: "))?;
    file.write_all(password_iv)?;
    file.write_all(String::from("\n Website: "))?;
    file.write_all(encrypted_website)?;
    file.write_all(String::from("\n Website IV: "))?;
    file.write_all(website_iv)?;

    Ok(())
}

// Get a password given an account

// Decrypt all of the account names and return them in order

pub fn get_accounts(hashed_master: &str) -> Result<Vec<String>, Error> {
    let path_str = "storage/passwords.txt";
    let path = Path::new(path_str);

    let mut file = OpenOptions::new()
        .read(true)
        .open(path)?;

    let mut accounts = Vec::new();
    let mut account = String::new();
    let mut iv = [0; 16];
    let mut encrypted_account = Vec::new();

    while file.read_line(&mut account)? != 0 {
        if account.contains("Account: ") {
            account = account.replace("Account: ", "");
            account = account.trim().to_string();
            encrypted_account.push(account);
        }
    }

    for account in encrypted_account {
        let decrypted_account = decrypt_password(account, iv, hashed_master);
        accounts.push(decrypted_account);
    }

    Ok(accounts)
    // This is in order
}

// Remove a password/Account pair

pub fn remove_password(hashed_master: &str, account_name: &str, list_of_accounts: &Vec<String>) -> Result<(), Error> {
    // First, we find where on the list it is, then we go that index in the file and remove it
    let path_str = "storage/passwords.txt";
    let path = Path::new(path_str);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;

    let index = 0;
    loop {
        if account_name == list_of_accounts[index] {
            break;
        }
    }

    let mut account_start = None;

    let file_index = 0;
    while file.read_line(&mut account)? != 0 {
        if account.contains("Account: ") {
            if file_index == index {
                // We are at the right account
                // We need to remove the next 6 lines
                account_start = Some(file_index);
                break;
            } else {
                file_index += 1;
            }
        }
    }

    if let Some(account_start) = account_start {
        let mut lines = Vec::new();
        let mut line = String::new();
        let mut line_index = 0;
        while file.read_line(&mut line)? != 0 {
            if line_index < account_start || line_index > account_start + 6 {
                lines.push(line);
            }
            line_index += 1;
        }

        file.set_len(0)?;
        for line in lines {
            file.write_all(line.as_bytes())?;
        }
    }

    Ok(())
    
}