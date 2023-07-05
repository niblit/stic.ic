use crate::{constants, KeyAndSalt, SaltType};
use rand::RngCore;
use zeroize::Zeroizing;

pub fn derive_key(
    password: Zeroizing<String>,
    salt: Option<SaltType>,
) -> crate::TResult<KeyAndSalt> {
    let argon2id = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            constants::argon2id_params::M,
            constants::argon2id_params::T,
            constants::argon2id_params::P,
            Some(constants::KEY_SIZE),
        )?,
    );

    let mut key = Zeroizing::new([0u8; 32]);

    let salt = match salt {
        Some(salt) => salt,
        None => {
            let mut salt = [0u8; constants::SALT_SIZE];
            rand::thread_rng().fill_bytes(&mut salt);
            salt
        }
    };

    argon2id.hash_password_into(password.as_bytes(), &salt, key.as_mut())?;

    Ok((key, salt))
}

#[cfg(test)]
mod test {
    use zeroize::Zeroizing;

    use crate::constants;

    use super::derive_key;

    #[test]
    #[ignore]
    fn time_params() {
        let start = std::time::Instant::now();
        let result = derive_key(Zeroizing::new(String::from("Password1!")), None).unwrap();
        let end = start.elapsed();

        let seconds = std::time::Duration::as_secs_f64(&end);
        dbg!(result);
        println!("{seconds} s");
    }

    #[test]
    #[ignore]
    fn empty_password_no_salt() {
        derive_key(Zeroizing::new(String::new()), None).unwrap();
    }

    #[test]
    #[ignore]
    fn empty_password_some_salt() {
        derive_key(
            Zeroizing::new(String::new()),
            Some([0u8; constants::SALT_SIZE]),
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn small_password_no_salt() {
        derive_key(Zeroizing::new(String::from("A")), None).unwrap();
    }

    #[test]
    #[ignore]
    fn small_password_some_salt() {
        derive_key(
            Zeroizing::new(String::from("A")),
            Some([b'A'; constants::SALT_SIZE]),
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn minimum_password_no_salt() {
        derive_key(Zeroizing::new(String::from("12345678")), None).unwrap();
    }

    #[test]
    #[ignore]
    fn minimum_password_some_salt() {
        derive_key(
            Zeroizing::new(String::from("12345678")),
            Some([b'`'; constants::SALT_SIZE]),
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn maximum_password_no_salt() {
        derive_key(Zeroizing::new("¬".repeat(4_000)), None).unwrap();
    }

    #[test]
    #[ignore]
    fn maximum_password_some_salt() {
        derive_key(
            Zeroizing::new("¬".repeat(4_000)),
            Some([255u8; constants::SALT_SIZE]),
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn big_password_no_salt() {
        derive_key(Zeroizing::new("^".repeat(1_000_000)), None).unwrap();
    }

    #[test]
    #[ignore]
    fn big_password_some_salt() {
        derive_key(
            Zeroizing::new("^".repeat(1_000_000)),
            Some([b'('; constants::SALT_SIZE]),
        )
        .unwrap();
    }
}
