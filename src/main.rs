use rusqlite::Connection;
mod storage_options_SQL;
mod encryption_algorithms;

fn main() {
    init_SQL_storage();
    init_user_id_table();

    let mut user_id = 0;
    
    loop {
        println!("Please enter a Username");
        let mut user_account = String::new();
        std::io::stdin().read_line(&mut user_account).expect("Failed to read line");
        user_account = user_account.trim().to_string();

        user_id = storage_options_SQL::get_user_id(&user_account)
            .expect("Failed to get user id");
        // Implement better error checking here so if the wrong user id is input, the program can just prompt you for the Username again
        break;
    }

    loop {
        println!("Please enter a command: ");
        println!("1. Add a password");
        println!("2. Get a password");
        println!("3. Delete a password");
        println!("4. Exit");
        let mut command = String::new();
        std::io::stdin().read_line(&mut command).expect("Failed to read line");
        command = command.trim().to_string();

        match command.as_str() {
            "2" => {
                println!("Please enter the master password: ");
                let mut master_password = String::new();
                std::io::stdin().read_line(&mut master_password).expect("Failed to read line");
                master_password = master_password.trim().to_string();
                // This will first show all account names associated with the user_id then ask for the account name (by numbering them
                // and allowing the user to simply input which number on the list it is)
                let hashed_master = encryption_algorithms::hash_master(&master_password);
                let account_list = storage_options_SQL::get_accounts(&hashed_master.to_be_bytes(), user_id);
                
                for (i, account) in account_list.iter().enumerate() {
                    let account = account.clone();
                    println!("{}. {}, {}", i, account[0], account[2]);
                }

                println!("Please enter the number of the account you would like to get the password for: ");
                let mut account_number = String::new();
                std::io::stdin().read_line(&mut account_number).expect("Failed to read line");
                account_number = account_number.trim().to_string();
                let account_number = account_number.parse::<usize>().expect("Failed to parse account number");

                let account = account_list[account_number].clone();

                println!("The password for {} is: {}", account[0], account[1]);

            }
            _ => {
                println!("Invalid command");
            }
        }

    }
}
// fn init_storage() {
//     // I'm going to change this to SQL, and add a userID to the table to make it easier than the constant value technique
//     let path_str = "storage/passwords.txt";
//     let path = Path::new(path_str);

//     if !path.exists() {
//         File::create(path_str).expect("Failed to create storage file");
//     }
// }

fn init_user_id_table() {
    // This is the initialization of the storage database with the encrypted passwords in SQL using SQLx
    let conn = rusqlite::Connection::open("storage/passwords.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_id (
            id INTEGER PRIMARY KEY,
            account BLOB NOT NULL
        )",
        [],
    ).unwrap();
}

fn init_SQL_storage() {
    // This is the initialization of the storage database with the encrypted passwords in SQL using SQLx
    let conn = Connection::open("storage/passwords.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            encrypted_account BLOB NOT NULL,
            encrypted_password BLOB NOT NULL,
            encrypted_website BLOB NOT NULL,
        )",
        [],
    ).unwrap();
}