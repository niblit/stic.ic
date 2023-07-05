pub const FILE_EXTENSION: &str = "ic";
pub const FILE_HEADER: &str = "[stic.ic] made with <3 by niblit";

pub const READ_WRITE_BUFFER_SIZE: usize = 1048576; // 1MiB
pub const MAX_BUFFER_SIZE: usize = 1073741824; // 1GiB

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;

pub mod argon2id_params {
    pub const M: u32 = 524_288; // memory in bytes
    pub const T: u32 = 8; // iteration cost
    pub const P: u32 = 16; // degree of parallelism
}
