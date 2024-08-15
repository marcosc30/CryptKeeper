use egui::Stroke;
use rusqlite::Connection;
mod storage_options_SQL;
mod encryption_algorithms;
use eframe::egui;
use std::fs;
use clipboard::{ClipboardContext, ClipboardProvider};
use egui::FontFamily::Proportional;
use egui::FontId;
use egui::TextStyle::*;


enum Screen {
    Login,
    UserNotFound,
    EnterNewMaster,
    InsertMaster,
    Main,
    AddPassword,
    GetPassword
}
struct PasswordManagerApp{
    current_screen: Screen,
    user_id: i32,
    account: String,
    hashed_master: [u8; 32],
    text_buffer: String,
    current_account: String,
    current_website: String,
    current_password: String
}

impl PasswordManagerApp {
    fn new() -> Self {
        Self {
            user_id: 0,
            account: String::new(),
            current_screen: Screen::Login,
            hashed_master: [0; 32],
            text_buffer: String::new(),
            current_account: String::new(),
            current_website: String::new(),
            current_password: String::new()
        }
    }
    fn login_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Please enter a Username");
        ui.text_edit_singleline(&mut self.account);

        if ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            self.user_id = storage_options_SQL::get_user_id(&self.account)
                .expect("Failed to get user id");
            if self.user_id == 0 {
                self.current_screen = Screen::UserNotFound;
            } else {
                self.current_screen = Screen::InsertMaster;
            }
        };
    }
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
    fn enter_new_master_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Please enter the new master password: ");
        ui.text_edit_singleline(&mut self.text_buffer);
        let master_password = self.text_buffer.clone();

        // Add password confirmation here

        if ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            self.text_buffer.clear();
            let hashed_master = encryption_algorithms::hash_master(&master_password);
            self.hashed_master = hashed_master;
            self.user_id = storage_options_SQL::add_user_id(self.account.as_str(), &hashed_master).expect("Failed to add user_id");
            self.current_screen = Screen::Login;
        }              
    }
    fn insert_master_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Please enter the master password: ");
        ui.text_edit_singleline(&mut self.text_buffer);

        if ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            let master_password = self.text_buffer.clone();
            self.text_buffer.clear();
            let hashed_master = encryption_algorithms::hash_master(&master_password);
            self.hashed_master = hashed_master;
            let hashed_master_vec = hashed_master.to_vec();
            let hashed_user_master = storage_options_SQL::get_hashed_master(self.user_id);

            if hashed_master_vec != hashed_user_master {
                self.hashed_master = [0; 32];
                println!("Incorrect master password");
                return;
            }
            self.current_screen = Screen::Main;
        }
    }
    fn main_screen(&mut self, ui: &mut egui::Ui) {
        // This main screen will be different to the terminal version, it will have buttons for each of the commands
        // It will have an add a password button at the top
        // Then a list of all the accounts associated with the user_id, with buttons next to each one to get the password or delete the password
        // Then a button to exit

        if ui.button("Add a password").clicked() {
            self.current_screen = Screen::AddPassword;
        }
        if ui.button("Exit").clicked() {
            self.hashed_master = [0; 32];
            self.user_id = 0;
            self.account.clear();
            self.current_screen = Screen::Login;
        }

        // if ui.button("Check for compromised passwords").clicked() {
        //     // This will check all the passwords associated with the user_id and see if they have been compromised
        //     // It will then display a list of all the compromised passwords
        // }

        let account_list = storage_options_SQL::get_accounts(&self.hashed_master, self.user_id);

        for (i, account) in account_list[0].iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(account);
                if ui.button("Get Password").clicked() {
                    self.current_account =  account_list[0][i].clone();
                    self.current_website = account_list[1][i].clone();
                    self.current_password = account_list[2][i].clone();
                    self.current_screen = Screen::GetPassword;
                }
                if ui.button("Delete Password").clicked() {
                    let entry_id = storage_options_SQL::find_entry_id(self.user_id, account.as_str(), account_list[1][i].as_str(), &self.hashed_master);
                    storage_options_SQL::remove_password(entry_id)
                        .expect("Failed to delete password");
                }
            });
        }

    }
    fn add_password_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("Please enter the account name: ");
        ui.text_edit_singleline(&mut self.current_account);

        ui.label("Please enter the website: ");
        ui.text_edit_singleline(&mut self.current_website);

        ui.label("Please enter the password: ");
        ui.text_edit_singleline(&mut self.current_password);

        if ui.button("Submit").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            storage_options_SQL::add_password(self.user_id, &self.current_account, &self.current_password, &self.hashed_master, &self.current_website)
                .expect("Failed to add password");
            self.current_account.clear();
            self.current_website.clear();
            self.current_password.clear();
            self.current_screen = Screen::Main;
        }
    }
    fn get_password_screen(&mut self, ui: &mut egui::Ui) {
        ui.label(format!("The password for {} on {} is: {}", self.current_account, self.current_website, self.current_password));
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
                _ => {}
            }
        });
    }
    fn on_exit(&mut self, _ctx: Option<&eframe::glow::Context>) {
        self.hashed_master = [0; 32];
        self.user_id = 0;
        self.account.clear();
        self.current_account.clear();
        self.current_website.clear();
        self.current_password.clear();
    }
}

fn main() {
    std::fs::create_dir_all("storage").expect("Failed to create storage directory");
    init_SQL_storage();
    init_user_id_table();
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Password Manager App",
        options,
        Box::new(|_cc| Ok(Box::new(PasswordManagerApp::new()))),
    );
}

fn main_orig() {
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