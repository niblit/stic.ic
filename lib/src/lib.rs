mod constants;
mod crypto;
mod pathmanip;

pub type TResult<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

pub type KeyType = zeroize::Zeroizing<[u8; constants::KEY_SIZE]>;
pub type SaltType = [u8; constants::SALT_SIZE];
pub type KeyAndSalt = (KeyType, SaltType);
