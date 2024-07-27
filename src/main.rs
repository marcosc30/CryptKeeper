use std::fs::File;
use std::path::Path;
mod storage_options;
mod encryption_algorithms;

fn main() {
    init_storage();
}

fn init_storage() {
    let path_str = "storage/passwords.txt";
    let path = Path::new(path_str);

    if !path.exists() {
        File::create(path_str).expect("Failed to create storage file");
    }
}

