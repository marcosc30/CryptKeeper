use core::hash;

use rusqlite::Connection;
mod storage_options_SQL;
mod encryption_algorithms;

fn main() {
    init_SQL_storage();
    init_user_id_table();

    let mut user_id = 0;
    
    // Maybe add a bool to the password storage to have extra secure that asks for master password again before getting it

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
    
    println!("Please enter the master password: ");
    let mut master_password = String::new();
    std::io::stdin().read_line(&mut master_password).expect("Failed to read line");
    master_password = master_password.trim().to_string();
    let hashed_master = encryption_algorithms::hash_master(&master_password);
    let hashed_master_vec = hashed_master.to_vec();

    let hashed_user_master = storage_options_SQL::get_hashed_master(user_id);

    if hashed_master_vec != hashed_user_master {
        println!("Incorrect master password");
        return;
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
            "1" => {
                println!("Please enter the account name: ");
                let mut account = String::new();
                std::io::stdin().read_line(&mut account).expect("Failed to read line");
                account = account.trim().to_string();

                println!("Please enter the website: ");
                let mut website = String::new();
                std::io::stdin().read_line(&mut website).expect("Failed to read line");
                website = website.trim().to_string();

                println!("Please enter the password: ");
                let mut password = String::new();
                std::io::stdin().read_line(&mut password).expect("Failed to read line");
                password = password.trim().to_string();

                storage_options_SQL::add_password(user_id, &account, &password, &hashed_master, &website)
                    .expect("Failed to add password");

                // Add a check so you can't add two identical accounts (with same account name and website, password doesn't matter)
            }
            "2" => {
                // This will first show all account names associated with the user_id then ask for the account name (by numbering them
                // and allowing the user to simply input which number on the list it is)
                let account_list = storage_options_SQL::get_accounts(&hashed_master, user_id);
                
                println!("Enter 0 to cancel");

                for (i, account) in account_list[0].iter().enumerate() {
                    println!("{}. {}, {}", i + 1, account, account_list[1][i]);
                }

                println!("Please enter the number of the account you would like to get the password for: ");
                let mut account_number = String::new();
                std::io::stdin().read_line(&mut account_number).expect("Failed to read line");
                account_number = account_number.trim().to_string();
                let account_number = account_number.parse::<usize>().expect("Failed to parse account number");

                if account_number == 0 {
                    continue;
                }

                println!("The password for {} is: {}", account_list[0][account_number - 1], account_list[2][account_number - 1]);

            }
            "3" => {
                // This will ask for the account associated with the password and delete it
                println!("Please enter the name of the account you wish to delete: ");
                let mut account = String::new();
                std::io::stdin().read_line(&mut account).expect("Failed to read line");
                account = account.trim().to_string();

                println!("Please enter the website of the account you wish to delete: ");
                let mut website = String::new();
                std::io::stdin().read_line(&mut website).expect("Failed to read line");
                website = website.trim().to_string();

                let entry_id = storage_options_SQL::find_entry_id(user_id, account.as_str(), website.as_str(), &hashed_master);

                storage_options_SQL::remove_password(entry_id)
                    .expect("Failed to delete password");
            }

            "4" => {
                break;
            }

            _ => {
                println!("Invalid command");
            }
        }

    }
}

fn init_user_id_table() {
    // This is the initialization of the storage database with the encrypted passwords in SQL using SQLx
    let conn = rusqlite::Connection::open("storage/users.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_id (
            user_id INTEGER PRIMARY KEY,
            account BLOB NOT NULL,
            hashed_master_password BLOB NOT NULL
        )",
        [],
    ).expect("Failed to create SQL user_id table");

    // Now we add an admin account if there is not already one, there must always be an admin
    let mut statement = conn.prepare("SELECT COUNT(*) FROM user_id WHERE account = 'admin'").expect("Failed to prepare statement");
    let count: i32 = statement.query_row([], |row| row.get(0)).expect("Failed to get count of admin account");

    if count == 0 {
        let hashed_master = encryption_algorithms::hash_master("admin");
        let hashed_master_vec = hashed_master.to_vec();
        conn.execute(
            "INSERT INTO user_id (user_id, account, hashed_master_password) VALUES (0, 'admin', ?)",
            rusqlite::params![hashed_master_vec]
        ).expect("Failed to add admin account");
    }
}

fn init_SQL_storage() {
    // This is the initialization of the storage database with the encrypted passwords in SQL using SQLx
    let conn = Connection::open("storage/passwords.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            entry_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            account BLOB NOT NULL,
            password BLOB NOT NULL,
            website BLOB NOT NULL
        )",
        [],
    ).expect("Failed to create SQL password table");

    // Now we add an initial password for the admin account
    let mut statement = conn.prepare("SELECT COUNT(*) FROM passwords WHERE account = 'admin'").expect("Failed to prepare statement");
    let count: i32 = statement.query_row([], |row| row.get(0)).expect("Failed to get count of admin account");

    if count == 0 {
        let hashed_master = encryption_algorithms::hash_master("admin");
        let hashed_master_vec = hashed_master.to_vec();
        conn.execute(
            "INSERT INTO passwords (user_id, account, password, website) VALUES (0, 'admin', ?, 'admin')",
            rusqlite::params![hashed_master_vec]
        ).expect("Failed to add admin account");
    }

}