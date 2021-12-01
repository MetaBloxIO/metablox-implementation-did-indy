use indy_api_types::errors::prelude::*;

use libc::c_int;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::box_;

use super::ed25519_box;
use super::randombytes::randombytes;

use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Sha256, Digest};

pub const SEEDBYTES: usize = sign::SEEDBYTES;
pub const SIG_PUBLICKEYBYTES: usize = sign::PUBLICKEYBYTES;
pub const ENC_PUBLICKEYBYTES: usize = box_::PUBLICKEYBYTES;
pub const SIG_SECRETKEYBYTES: usize = sign::SECRETKEYBYTES;
pub const ENC_SECRETKEYBYTES: usize = box_::SECRETKEYBYTES;
pub const SIGNATUREBYTES: usize = sign::SIGNATUREBYTES;

sodium_type!(Seed, sign::Seed, SEEDBYTES);
sodium_type!(PublicKey, sign::PublicKey, SIG_PUBLICKEYBYTES);
sodium_type!(SecretKey, sign::SecretKey, SIG_SECRETKEYBYTES);
sodium_type!(Signature, sign::Signature, SIGNATUREBYTES);

extern {
    // TODO: fix hack:
    // this functions isn't included to sodiumoxide rust wrappers,
    // temporary local binding is used to call libsodium-sys function
    pub fn crypto_sign_ed25519_pk_to_curve25519(
        curve25519_pk: *mut [u8; ENC_PUBLICKEYBYTES],
        ed25519_pk: *const [u8; SIG_PUBLICKEYBYTES]) -> c_int;
    pub fn crypto_sign_ed25519_sk_to_curve25519(
        curve25519_sk: *mut [u8; ENC_SECRETKEYBYTES],
        ed25519_sk: *const [u8; SIG_SECRETKEYBYTES]) -> c_int;
}


pub fn create_key_pair_for_signature(seed: Option<&[u8; 32]>) -> Result<(secp256k1::PublicKey, secp256k1::SecretKey), IndyError> {
    //let (public_key, secret_key) =
    //    sign::keypair_from_seed(
    //        &seed.unwrap_or(
    //            &Seed::from_slice(&randombytes(SEEDBYTES)).unwrap()
    //        ).0
     //   );

     let secp = Secp256k1::new();
        
    let mut rng: StdRng = match seed {
        Some(seed_value) => SeedableRng::from_seed(array_ref!(seed_value.as_ref(), 0, 32).clone()),
        None =>  SeedableRng::from_rng(rand::thread_rng()).unwrap(),
    } ;

    //let mut rng: StdRng = SeedableRng::from_seed(seed);
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);

    let secret_key = secp256k1::SecretKey::from_slice(&bytes);
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key.unwrap());
    
    Ok((public_key,  secret_key.unwrap()))
}

pub fn sign(secret_key: &secp256k1::SecretKey, doc: &[u8]) -> Result<secp256k1::Signature, IndyError> {
    let mut hasher = Sha256::new();
    hasher.update(doc);
    
    let message = secp256k1::Message::from_slice(&hasher.finalize()[..]);
    let secp = Secp256k1::new();
    let sign_result = secp.sign(&message.unwrap(), &secret_key);
   
    Ok(sign_result)
}

pub fn verify(public_key: &secp256k1::PublicKey, doc: &[u8], signature: &secp256k1::Signature) -> Result<bool, IndyError> {
    let mut hasher = Sha256::new();
    hasher.update(doc);

    let message = secp256k1::Message::from_slice(&hasher.finalize()[..]);
    
    let secp = Secp256k1::new();

    let result = secp.verify(&message.unwrap(), signature, public_key);

    match result {
        Ok(()) => Ok(true),
        Err(_) => Ok(false)
    }
}

pub fn sk_to_curve25519(sk: &SecretKey) -> Result<ed25519_box::SecretKey, IndyError> {
    let mut to: [u8; ENC_SECRETKEYBYTES] = [0; ENC_SECRETKEYBYTES];
    unsafe {
        crypto_sign_ed25519_sk_to_curve25519(&mut to, &(sk.0).0);
    }
    ed25519_box::SecretKey::from_slice(&to)
}

pub fn vk_to_curve25519(pk: &PublicKey) -> Result<ed25519_box::PublicKey, IndyError> {
    let mut to: [u8; ENC_PUBLICKEYBYTES] = [0; ENC_PUBLICKEYBYTES];
    unsafe {
        crypto_sign_ed25519_pk_to_curve25519(&mut to, &(pk.0).0);
    }
    ed25519_box::PublicKey::from_slice(&to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519_box;

    #[test]
    fn signin_verify_works() {
        let seed = Seed::from_slice(&randombytes(SEEDBYTES)).unwrap();
        let text = randombytes(16);

        let (public_key, secret_key) = create_key_pair_for_signature(Some(&seed)).unwrap();
        let alice_signed_text = sign(&secret_key, &text).unwrap();
        let verified = verify(&public_key, &text, &alice_signed_text).unwrap();

        assert!(verified);
    }

    #[test]
    fn pk_to_curve25519_works() {
        let pk = vec!(236, 191, 114, 144, 108, 87, 211, 244, 148, 23, 20, 175, 122, 6, 159, 254, 85, 99, 145, 152, 178, 133, 230, 236, 192, 69, 35, 136, 141, 194, 243, 134);
        let pk = PublicKey::from_slice(&pk).unwrap();
        let pkc_test = vk_to_curve25519(&pk).unwrap();
        let pkc_exp = vec!(8, 45, 124, 147, 248, 201, 112, 171, 11, 51, 29, 248, 34, 127, 197, 241, 60, 158, 84, 47, 4, 176, 238, 166, 110, 39, 207, 58, 127, 110, 76, 42);
        let pkc_exp = ed25519_box::PublicKey::from_slice(&pkc_exp).unwrap();
        assert_eq!(pkc_exp, pkc_test);
    }

    #[test]
    fn sk_to_curve25519_works() {
        let sk = vec!(78, 67, 205, 99, 150, 131, 75, 110, 56, 154, 76, 61, 27, 142, 36, 141, 44, 223, 122, 199, 14, 230, 12, 163, 4, 255, 94, 230, 21, 242, 97, 200, 236, 191, 114, 144, 108, 87, 211, 244, 148, 23, 20, 175, 122, 6, 159, 254, 85, 99, 145, 152, 178, 133, 230, 236, 192, 69, 35, 136, 141, 194, 243, 134);
        let sk = SecretKey::from_slice(&sk).unwrap();
        let skc_test = sk_to_curve25519(&sk).unwrap();
        let skc_exp = vec!(144, 112, 64, 101, 69, 167, 61, 44, 220, 148, 58, 187, 108, 73, 11, 247, 130, 161, 158, 40, 100, 1, 40, 27, 76, 148, 209, 240, 195, 35, 153, 121);
        let skc_exp = ed25519_box::SecretKey::from_slice(&skc_exp).unwrap();
        assert_eq!(skc_exp, skc_test);
    }
}
