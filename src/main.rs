#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod storage_options_sql;
mod encryption_algorithms;
mod password_generator;
use egui::Color32;
use egui::RichText;
use egui::Stroke;
use rusqlite::Connection;
use eframe::egui;
use clipboard::{ClipboardContext, ClipboardProvider};
use egui::FontFamily::Proportional;
use egui::FontId;
use egui::TextStyle::*;
use rand::Rng;

enum Screen {
    Login,
    UserNotFound,
    EnterNewMaster,
    InsertMaster,
    Main,
    AddPassword,
    GetPassword,
    ChangeMasterPassword
}
struct PasswordManagerApp{
    current_screen: Screen,
    display_incorrect_msg: bool,
    user_id: i32,
    account: String,
    salt: [u8; 32],
    kdf_salt: [u8; 32],
    hashed_master: [u8; 32],
    text_buffer: String,
    current_account: String,
    current_website: String,
    current_password: String,
    password_attempts: i32,
    password_limit: bool,
    master_safe: (u32, Vec<String>)
}

impl PasswordManagerApp {
    /// Creates a new PasswordManagerApp by initializing the fields to their default values
    fn new() -> Self {
        Self {
            current_screen: Screen::Login,
            display_incorrect_msg: false,
            user_id: 0,
            account: String::new(),
            salt: [0; 32],
            kdf_salt: [0; 32],
            hashed_master: [0; 32],
            text_buffer: String::new(),
            current_account: String::new(),
            current_website: String::new(),
            current_password: String::new(),
            password_attempts: 0,
            password_limit: false,
            master_safe: (0, Vec::new())
        }
    }
    /// This function will display the login screen, where the user will enter their username
    /// Depending on the username, the user will be taken to the insert master screen or the user not found screen
    fn login_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Please enter a Username");
        ui.text_edit_singleline(&mut self.account);

        if ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            self.user_id = storage_options_sql::get_user_id(&self.account)
                .expect("Failed to get user id");
            if self.user_id == 0 {
                self.current_screen = Screen::UserNotFound;
            } else {
                self.current_screen = Screen::InsertMaster;
            }
        };
    }
    /// This function will display the user not found screen, where the user will be asked if they want to create a new user
    /// If they do, they will be taken to the enter new master screen where the inserted username is used as a username
    fn user_not_found_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("User not found, would you like to create a new user?");
        if ui.button("Yes").clicked() {
           self.current_screen = Screen::EnterNewMaster;      
        }
        if ui.button("No").clicked() {
            println!("User not found");
            self.current_screen = Screen::Login;
            return;
        }
    } 
    /// This function will display the enter new master screen, where the user will enter a new master password
    /// and with it, an account is created
    fn enter_new_master_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Please enter the new master password: ");
        ui.text_edit_singleline(&mut self.text_buffer);
        let master_password = self.text_buffer.clone();

        // Add password confirmation here

        if ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            self.text_buffer.clear();
            // generate a random salt
            let salt = rand::thread_rng().gen::<[u8; 32]>();
            let hashed_master = encryption_algorithms::hash_master(&master_password, salt);
            self.hashed_master = hashed_master;
            // Generate another random salt to serve as the kdf salt
            let mut kdf_salt = rand::thread_rng().gen::<[u8; 32]>();
            while kdf_salt == salt {
                kdf_salt = rand::thread_rng().gen::<[u8; 32]>();
            }
            self.user_id = storage_options_sql::add_user_id(self.account.as_str(), &hashed_master, &salt, &kdf_salt).expect("Failed to add user_id");
            self.current_screen = Screen::Login;
        }              
    }
    /// This function will display the change master password screen, where the user will enter their new master password
    /// and with it, the master password will be changed
    fn change_master_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Your current master password has the following vulnerabilities: ");
        for message in self.master_safe.1.iter() {
            ui.label(RichText::new(message).color(Color32::RED).size(12.5));
        }

        ui.label("Please enter the new master password: ");
        ui.text_edit_singleline(&mut self.text_buffer);
        let master_password = self.text_buffer.clone();

        ui.label("Please confirm the new master password: ");
        ui.text_edit_singleline(&mut self.current_password);

        // Add password confirmation here

        if (ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter))) && self.text_buffer == master_password {
            self.current_password.clear();

            // Generate a new random salt
            let salt = rand::thread_rng().gen::<[u8; 32]>();
            let hashed_master = encryption_algorithms::hash_master(&master_password, salt);

            // Generate a new random kdf salt
            let mut kdf_salt = rand::thread_rng().gen::<[u8; 32]>();
            while kdf_salt == salt {
                kdf_salt = rand::thread_rng().gen::<[u8; 32]>();
            }

            storage_options_sql::change_master_password(self.user_id, &self.hashed_master, &hashed_master, &salt, &kdf_salt);

            self.hashed_master = hashed_master;
            self.text_buffer.clear();
            self.current_screen = Screen::Login;
        }      

        if ui.button("Cancel").clicked() {
            self.current_screen = Screen::Main;
        }
    }       
    
    /// This function will display the insert master screen, where the user will enter their master password
    /// If the master password is correct, the user will be taken to the main screen
    /// If the master password is incorrect, the user will be shown an error message and be given a chance it insert it again
    /// A locking mechanism at the SQL level will be introduced in the future to prevent brute force attacks
    /// For now, it returns you to the login screen after 10 attempts
    /// Since the database is stored locally, brute force attacks can be done regardless of this software, but in the cloud
    /// It will be implemented to prevent any type of brute force attacks
    fn insert_master_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Please enter the master password: ");
        ui.text_edit_singleline(&mut self.text_buffer);

        if self.password_attempts > 20 && self.password_limit == true {
            // I'm going to implement a locking technique here stored in the file, that calculates the current date
            // And adds a certain amount of time to it, and if the current date is less than that time, the user is locked out
            self.current_screen = Screen::Login;
            self.password_attempts = 0;
            self.text_buffer.clear();
            self.hashed_master = [0; 32];
            self.user_id = 0;
            self.account.clear();
            self.salt = [0; 32];
            self.display_incorrect_msg = false;
            return;
        }

        if self.display_incorrect_msg {
            ui.label("Incorrect master password, please try again");
        }

        if ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            self.password_attempts += 1;
            let master_password = self.text_buffer.clone();

            let salt = storage_options_sql::get_salt(self.user_id); 
            for i in 0..32 {
                self.salt[i] = salt[i];
            }

            self.text_buffer.clear();
            let hashed_master = encryption_algorithms::hash_master(&master_password, self.salt);
            self.hashed_master = hashed_master;
            let hashed_master_vec = hashed_master.to_vec();
            let hashed_user_master = storage_options_sql::get_hashed_master(self.user_id);

            if hashed_master_vec != hashed_user_master {
                self.hashed_master = [0; 32];
                self.display_incorrect_msg = true;
                println!("Incorrect master password");
                return;
            } else {
                self.master_safe = password_generator::check_password_safety(&master_password);
                self.password_attempts = 0;
                self.display_incorrect_msg = false;
                // Change the hash to be the KDF hash, so that the stored hash cannot actually decrypt anything
                let kdf_salt = storage_options_sql::get_kdf_salt(self.user_id);
                for i in 0..32 {
                    self.kdf_salt[i] = kdf_salt[i];
                }
                self.hashed_master = encryption_algorithms::hash_master(&master_password, self.kdf_salt);
                self.current_screen = Screen::Main;
            }
        }
    }
    /// This function will display the main screen, where the user can add a password, check for compromised passwords,
    /// get any password, change any password, delete any password, exit the application
    /// The check for compromised passwords is not implemented yet
    fn main_screen(&mut self, ui: &mut egui::Ui) {
        self.current_account.clear();
        self.current_website.clear();
        self.current_password.clear();

        if ui.button("Add a password").clicked() {
            self.current_screen = Screen::AddPassword;
        }

        if self.master_safe.0 < 30 {
            ui.label(RichText::new("Your master password is not safe, please change it").color(Color32::RED).size(12.5));
        }

        if ui.button("Change Master Password").clicked() {
            self.current_screen = Screen::ChangeMasterPassword;
        }

        if ui.button("Exit").clicked() {
            self.hashed_master = [0; 32];
            self.text_buffer.clear();
            self.user_id = 0;
            self.account.clear();
            self.salt = [0; 32];
            self.current_screen = Screen::Login;
        } else {
            // if ui.button("Check for compromised passwords").clicked() {
            //     // This will check all the passwords associated with the user_id and see if they have been compromised
            //     // It will then display a list of all the compromised passwords
            // }
            ui.horizontal(|ui| {
                ui.label("Search for an account: ");
                ui.text_edit_singleline(&mut self.text_buffer);
            });

            let mut account_list = storage_options_sql::get_accounts(&self.hashed_master, self.user_id);
            // Filter the accounts to match the text_buffer, storing the indices of matching account triplets
            let mut indices = Vec::new();
            for i in 0..account_list[0].len() {
                // Make a copy of the text_buffer that is all lowercase and convert the account names to lowercase
                let text_buffer_lower = self.text_buffer.to_lowercase();
                let account_lower = account_list[0][i].to_lowercase();
                let website_lower = account_list[1][i].to_lowercase();
                if account_lower.contains(&text_buffer_lower) || website_lower.contains(&text_buffer_lower) {
                    indices.push(i);
                }
            }

            // Create a new account list with only the matching accounts
            account_list = [
                indices.iter().map(|&i| account_list[0][i].clone()).collect(),
                indices.iter().map(|&i| account_list[1][i].clone()).collect(),
                indices.iter().map(|&i| account_list[2][i].clone()).collect()
            ];

            if account_list[0].is_empty() {
                ui.label("No accounts found");
            }

            for (i, account) in account_list[0].iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(account);
                    ui.label(account_list[1][i].as_str());
                    if ui.button("Get Password").clicked() {
                        self.current_account =  account_list[0][i].clone();
                        self.current_website = account_list[1][i].clone();
                        self.current_password = account_list[2][i].clone();
                        self.current_screen = Screen::GetPassword;
                    }
                    if ui.button("Change Password").clicked() {
                        self.current_account =  account_list[0][i].clone();
                        self.current_website = account_list[1][i].clone();
                        self.current_password = account_list[2][i].clone();
                        storage_options_sql::remove_password(storage_options_sql::find_entry_id(self.user_id, account.as_str(), account_list[2][i].as_str(), account_list[1][i].as_str(), &self.hashed_master))
                            .expect("Failed to delete password");
                        self.current_screen = Screen::AddPassword;
                    }
                    if ui.button("Delete Password").clicked() {
                        let entry_id = storage_options_sql::find_entry_id(self.user_id, account.as_str(), account_list[2][i].as_str(), account_list[1][i].as_str(), &self.hashed_master);
                        storage_options_sql::remove_password(entry_id)
                            .expect("Failed to delete password");
                    }
                });
            }
        }

    }

    /// This function will display the add password screen, where the user will enter the account name, website, and password
    fn add_password_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Please enter the account name: ");
        ui.text_edit_singleline(&mut self.current_account);

        ui.label("Please enter the website: ");
        ui.text_edit_singleline(&mut self.current_website);

        ui.label("Please enter the password: ");
        ui.text_edit_singleline(&mut self.current_password);
        if ui.button("Generate password").clicked() {
            self.current_password = password_generator::generate_password(20);
        }

        if ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            storage_options_sql::add_password(self.user_id, &self.current_account, &self.current_password, &self.hashed_master, &self.current_website)
                .expect("Failed to add password");
            self.current_account.clear();
            self.current_website.clear();
            self.current_password.clear();
            self.current_screen = Screen::Main;
        }
    }
    /// This function will display the get password screen, where the user will be shown the password for the account and website
    fn get_password_screen(&mut self, ui: &mut egui::Ui) {
        ui.label(format!("The password for {} on {} is: {}", self.current_account, self.current_website, self.current_password));

        // Display password safety
        let (safety_rating, safety_message) = password_generator::check_password_safety(&self.current_password);
        ui.label(format!("Password safety rating: {}/50", safety_rating));
        for message in safety_message {
            ui.label(RichText::new(message).color(Color32::RED).size(12.5));
        }
        
        if ui.button("Copy to clipboard").clicked() {
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents(self.current_password.clone()).expect("Failed to copy to clipboard");
        }
        // if ui.button("Check if password has been compromised").clicked() {
            
        // }
        if ui.button("Back").clicked() {
            self.current_account.clear();
            self.current_website.clear();
            self.current_password.clear();
            self.current_screen = Screen::Main;
        }
    }
}

/// This is the implementation of the App trait for the PasswordManagerApp struct
impl eframe::App for PasswordManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let mut style = (*ctx.style()).clone();
            style.text_styles = [
            (Heading, FontId::new(30.0, Proportional)),
            (Name("Heading2".into()), FontId::new(25.0, Proportional)),
            (Name("Context".into()), FontId::new(23.0, Proportional)),
            (Body, FontId::new(18.0, Proportional)),
            (Monospace, FontId::new(14.0, Proportional)),
            (Button, FontId::new(14.0, Proportional)),
            (Small, FontId::new(10.0, Proportional)),
            ].into();

            style.visuals.override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
            style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(0, 0, 0);
            style.visuals.extreme_bg_color = egui::Color32::from_rgb(13, 6, 48);
            style.visuals.panel_fill = egui::Color32::from_rgb(24, 49, 79);
            style.visuals.warn_fg_color = egui::Color32::from_rgb(211, 101, 130);
            style.visuals.error_fg_color = egui::Color32::from_rgb(255, 0, 0);
            style.visuals.faint_bg_color = egui::Color32::from_rgb(31, 56, 86);
            style.visuals.hyperlink_color = egui::Color32::from_rgb(136, 162, 170);

            style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(31, 56, 86);
            style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(31, 56, 86);
            style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(31, 56, 86);
            style.visuals.widgets.inactive.weak_bg_fill = egui::Color32::from_rgb(31, 56, 86);
            style.visuals.widgets.open.bg_fill = egui::Color32::from_rgb(31, 56, 86);
            style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, egui::Color32::from_rgb(31, 56, 86));
            style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(13, 6, 48);
            style.visuals.widgets.inactive.expansion = 0.3;



            ctx.set_style(style);

            match self.current_screen {
                Screen::Login => self.login_screen(ui),
                Screen::InsertMaster => self.insert_master_screen(ui),
                Screen::Main => self.main_screen(ui),
                Screen::UserNotFound => self.user_not_found_screen(ui),
                Screen::EnterNewMaster => self.enter_new_master_screen(ui),
                Screen::AddPassword => self.add_password_screen(ui),
                Screen::GetPassword => self.get_password_screen(ui),
                Screen::ChangeMasterPassword => self.change_master_screen(ui)
            }
        });
    }
    /// This function will be called when the application is exited, to clear all sensitive data from memory
    fn on_exit(&mut self, _ctx: Option<&eframe::glow::Context>) {
        println!("Exiting");
        self.hashed_master = [0; 32];
        self.user_id = 0;
        self.account.clear();
        self.current_account.clear();
        self.current_website.clear();
        self.current_password.clear();
    }

}

// This is the main function that will run the application by running native egui
fn main() {
    std::fs::create_dir_all("storage").expect("Failed to create storage directory");
    init_sql_storage();
    init_user_id_table();
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Password Manager App",
        options,
        Box::new(|_cc| Ok(Box::new(PasswordManagerApp::new()))),
    ).expect("Failed to run native");
}

/// This function initializes the user_id table in the SQL database
fn init_user_id_table() {
    // This is the initialization of the storage database with the encrypted passwords in SQL using SQLx
    let conn = rusqlite::Connection::open("storage/passwords.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_id (
            user_id INTEGER PRIMARY KEY,
            account BLOB NOT NULL,
            hashed_master_password BLOB NOT NULL,
            salt BLOB,
            kdf_salt BLOB
        )",
        [],
    ).expect("Failed to create SQL user_id table");

    // Now we add an admin account if there is not already one, there must always be an admin
    let mut statement = conn.prepare("SELECT COUNT(*) FROM user_id WHERE account = 'admin'").expect("Failed to prepare statement");
    let count: i32 = statement.query_row([], |row| row.get(0)).expect("Failed to get count of admin account");

    if count == 0 {
        let hashed_master = encryption_algorithms::hash_master("admin", [0; 32]);
        let hashed_master_vec = hashed_master.to_vec();
        conn.execute(
            "INSERT INTO user_id (user_id, account, hashed_master_password) VALUES (0, 'admin', ?)",
            rusqlite::params![hashed_master_vec]
        ).expect("Failed to add admin account");
    }
}

/// This function initializes the password table in the SQL database
fn init_sql_storage() {
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
        let hashed_master = encryption_algorithms::hash_master("admin", [0; 32]);
        // Admin is a misnomer, since this doesn't really have any permissions, it is just the initial created account to avoid 
        // Tricky edge cases in creation of the SQL tables
        let hashed_master_vec = hashed_master.to_vec();
        conn.execute(
            "INSERT INTO passwords (user_id, account, password, website) VALUES (0, 'admin', ?, 'admin')",
            rusqlite::params![hashed_master_vec]
        ).expect("Failed to add admin account");
    }

}