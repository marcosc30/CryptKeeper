use std::io::Error;
use std::str;
use rusqlite;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use base64::{ encode, decode};

// user_id database:
//     user_id INTEGER PRIMARY KEY,
//     account BLOB NOT NULL,
//     hashed_master_password BLOB NOT NULL,
//     salt BLOB,
//     kdf_salt BLOB,
//     open_instances INTEGER NOT NULL

// passwords database:
//     entry_id INTEGER PRIMARY KEY,
//     user_id INTEGER NOT NULL,
//     account BLOB NOT NULL,
//     password BLOB NOT NULL,
//     website BLOB NOT NULL

// Define the structures for serialization and deserialization

#[derive(Serialize)]
struct GetAccountsRequest {
    account_name: String,
    hashed_password: String
}

#[derive(Serialize)]
struct PasswordItemSend {
    entry_id: i32,
    user_id: i32,
    account: String,  // Base64 encoded
    password: String, // Base64 encoded
    website: String,  // Base64 encoded
}

#[derive(Deserialize)]
struct PasswordItemReceive {
    entry_id: i32,
    user_id: i32,
    account: String,  // Base64 encoded
    password: String, // Base64 encoded
    website: String,  // Base64 encoded
}

struct PasswordItemReceiveConverted {
    entry_id: i32,
    user_id: i32,
    account: Vec<u8>,
    password: Vec<u8>,
    website: Vec<u8>
}

#[derive(Serialize)]
struct SyncRequest {
    user_id: String,
    data: Vec<PasswordItemSend>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct UserIDRequest {
    account_name: String
}

#[derive(Deserialize)]
struct UserIDResponse {
    user_id: i32,
    salt: String, // Base64 encoded
    kdf_salt: String, // Base64 encoded
}

#[derive(Serialize)]
struct UserRegistrationRequest {
    account_name: String,
    hashed_master_password: String, // Base64 encoded
    salt: String, // Base64 encoded
    kdf_salt: String, // Base64 encoded
}

// We need a function to get a user id and the salts associated with that account 
pub async fn get_user_id (client: &Client, base_url: &str, account_name: &str) -> Result<(i32, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let request_body = UserIDRequest {
        account_name: account_name.to_string()
    };

    let response = client
        .post(&format!("{}/get_user_id", base_url))
        .json(&request_body)
        .send()
        .await?;

    if response.status().is_success() {
        let response_body: UserIDResponse = response.json().await?;
        let salt = decode_base64(&response_body.salt)?;
        let kdf_salt = decode_base64(&response_body.kdf_salt)?;
        Ok((response_body.user_id, salt, kdf_salt))
    } else {
        let error_response: ErrorResponse = response.json().await?;
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            error_response.error,
        )))
    }
}

pub async fn register_user(client: &Client, base_url: &str, account_name: &str, hashed_master: &[u8; 32], salt: &[u8; 32], kdf_salt: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let request_body = UserRegistrationRequest {
        account_name: account_name.to_string(),
        hashed_master_password: encode_base64(hashed_master),
        salt: encode_base64(salt),
        kdf_salt: encode_base64(kdf_salt),
    };

    let response = client
        .post(&format!("{}/register_user", base_url))
        .json(&request_body)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        let error_response: ErrorResponse = response.json().await?;
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            error_response.error,
        )))
    }
}

pub async fn get_accounts(client: &Client, base_url: &str, account_name: &str, hashed_master: &[u8; 32]) -> Result<Vec<PasswordItemReceiveConverted>, Box<dyn std::error::Error>> {
    let request_body = GetAccountsRequest {
        account_name: account_name.to_string(),
        hashed_password: encode_base64(hashed_master),
    };

    let response = client
        .post(&format!("{}/get_accounts", base_url))
        .json(&request_body)
        .send()
        .await?;

    if response.status().is_success() {
        let passwords: Vec<PasswordItemReceive> = response.json().await?;
        let converted_passwords: Vec<PasswordItemReceiveConverted> = passwords.iter().map(|password| {
            PasswordItemReceiveConverted {
                entry_id: password.entry_id,
                user_id: password.user_id,
                account: decode_base64(&password.account).unwrap(),
                password: decode_base64(&password.password).unwrap(),
                website: decode_base64(&password.website).unwrap(),
            }
        }).collect();
        Ok(converted_passwords)
    } else if response.status().as_u16() == 404 {
        Ok(Vec::new())
    } else {
        let error_response: ErrorResponse = response.json().await?;
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            error_response.error,
        )))
    }
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match decode(encoded) {
        Ok(decoded) => Ok(decoded),
        Err(e) => Err(Box::new(e)),
    }
}

fn encode_base64(data: &[u8]) -> String {
    encode(data)
}

async fn sync(client: &Client, base_url: &str, user_id: &str, data: Vec<PasswordItemSend>) -> Result<(), Box<dyn std::error::Error>> {
    let sync_request = SyncRequest {
        user_id: user_id.to_string(),
        data,
    };

    let response = client
        .post(&format!("{}/sync", base_url))
        .json(&sync_request)
        .send()
        .await?;

    if response.status().is_success() {
        println!("Sync successful.");
        Ok(())
    } else {
        let error_response: ErrorResponse = response.json().await?;
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            error_response.error,
        )))
    }
}

// Prepare the data to be synced using the opened in memory SQL table
fn prepare_sync_data () -> Vec<PasswordItemSend> {
    let conn = rusqlite::Connection::open_in_memory().expect("Failed to open in memory database");
    let mut stmt = conn.prepare("SELECT * FROM passwords").expect("Failed to prepare statement");
    let password_items: Vec<PasswordItemReceiveConverted> = stmt.query_map([], |row| {
        Ok(PasswordItemReceiveConverted {
            entry_id: row.get(0)?,
            user_id: row.get(1)?,
            account: row.get(2)?,
            password: row.get(3)?,
            website: row.get(4)?,
        })
    }).expect("Failed to query data").map(|item| item.unwrap()).collect();

    password_items.iter().map(|item| {
        PasswordItemSend {
            entry_id: item.entry_id,
            user_id: item.user_id,
            account: encode_base64(&item.account),
            password: encode_base64(&item.password),
            website: encode_base64(&item.website),
        }
    }).collect()
}

// Converts the password_items vector to a SQL .db file and saves it locally, this file is deleted on program exit
pub fn password_items_to_sql (password_items: Vec<PasswordItemReceiveConverted>) -> Result<(), Error> {
    let conn = rusqlite::Connection::open_in_memory().expect("Failed to open in memory database");
    conn.execute(
        "CREATE TABLE passwords (
            entry_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            account BLOB NOT NULL,
            password BLOB NOT NULL,
            website BLOB NOT NULL
        )",
        [],
    ).expect("Failed to create table");

    for password_item in password_items {
        conn.execute(
            "INSERT INTO passwords (entry_id, user_id, account, password, website) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![password_item.entry_id, password_item.user_id, password_item.account, password_item.password, password_item.website],
        ).expect("Failed to insert data");
    }

    Ok(())
}