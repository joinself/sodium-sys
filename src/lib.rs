#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/sodium.rs"));


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn init() {
        unsafe {
            sodium_init();
        }
    }
}