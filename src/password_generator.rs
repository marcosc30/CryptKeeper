use rand::{rngs::StdRng, Rng, SeedableRng};

pub fn generate_password(length: u32) -> String {
    let character_pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let character_pool_len = character_pool.len();

    let mut rng = StdRng::from_entropy();
    // It will be organized in blocks of 4 to be easier to remember with a dash between each block

    let mut password = String::new();
    for i in 0..length {
        if i % 4 == 0 && i != 0 {
            password.push('-');
            continue;
        }
        let character = rng.gen_range(0..character_pool_len);
        password.push(character_pool.chars().nth(character).unwrap());
    }

    password
}