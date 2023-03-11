#[cfg(test)]
pub mod testing;


use openssl::{
    error::ErrorStack,
    symm::{decrypt, encrypt, Cipher},
};

pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    encrypt(Cipher::aes_256_cbc(), key, None, plaintext)
}

pub fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    decrypt(Cipher::aes_256_cbc(), key, None, ciphertext)
}

pub fn des_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    encrypt(Cipher::des_cbc(), key, None, plaintext)
}

pub fn des_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    decrypt(Cipher::des_cbc(), key, None, ciphertext)
}

// https://datatracker.ietf.org/doc/html/rfc2315
// Assume that the blocksize can't exceed 255 and assume that blocksize / 8 makes sense
pub fn pkcs_padding(blocksize_num_bytes: u8, input: &mut Vec<u8>) {
    let num_bytes = input.len();
    let padding_num = blocksize_num_bytes - ((num_bytes % (blocksize_num_bytes as usize)) as u8);
    let mut i = 0;
    let mut padding: Vec<u8> = vec![];
    while i < padding_num {
        padding.push(padding_num);
        i += 1;
    }
    input.append(&mut padding);
}

pub fn verify_pkcs_padding(blocksize: u8, input: &[u8]) {
    assert!(!input.is_empty(), "Input is empty");
    assert!(
        input.len() % (blocksize as usize) == 0,
        "Input isn't a multiple of blocksize"
    );
    let last_byte: u8 = *input.last().unwrap();
    assert!(blocksize >= last_byte);
    if last_byte == blocksize {
        assert!(input.len() > blocksize as usize);
    }
    let ref slice = input[input.len() - last_byte as usize..];
    for x in slice.iter() {
        assert_eq!(x, &last_byte);
    }

    assert_eq!(
        ((input.len() - last_byte as usize) % blocksize as usize) as u8,
        blocksize - last_byte
    );
}

#[cfg(test)]
mod tests {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::typenum::U16;
    use aes::cipher::{BlockDecrypt, KeyInit};
    use aes::{Aes256};
    use openssl::rsa::{Padding, Rsa};
    

    use crate::{aes_decrypt, aes_encrypt, des_encrypt, verify_pkcs_padding};

    #[test]
    fn ch3_4() {
        let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let ciphertext = b"\x53\x9B\x33\x3B\x39\x70\x6D\x14\x90\x28\xCF\xE1\xD9\xD4\xA4\x07";

        let plaintext = aes_decrypt(key, ciphertext).unwrap();

        assert_eq!(aes_encrypt(key, &plaintext).unwrap(), ciphertext);
    }

    #[test]
    fn ch3_9() {
        let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let plaintext = b"\x29\x6C\x93\xFD\xF4\x99\xAA\xEB\x41\x94\xBA\xBC\x2E\x63\x56\x1D";
        println!("Len: {}", plaintext.len());

        let ciphertext = aes_encrypt(key, plaintext).unwrap();

        let rsa = Rsa::generate(3072).unwrap();
        let mut buf = vec![0; rsa.size() as usize];
        let encrypted_len = rsa
            .public_encrypt(&ciphertext, &mut buf, Padding::PKCS1)
            .unwrap();

        let mut buf2 = vec![0; rsa.size() as usize];
        let decrypted_len = rsa
            .private_decrypt(&buf[0..encrypted_len], &mut buf2, Padding::PKCS1)
            .unwrap();

        assert_eq!(ciphertext, buf2[0..decrypted_len].to_vec());
    }

    #[test]
    fn ch3_10() {
        let key = b"\x00\x00\x00\x00\x00\x00\x00\x01";
        let plaintext = b"\x00\x00\x00\x00\x00\x00\x00\x01";

        let ciphertext: Vec<u8> = des_encrypt(key, plaintext).unwrap();

        println!("{:?}", ciphertext);

        let inv_key = key.map(|b| !b);
        let inv_pt = plaintext.map(|b| !b);
        let inv_ct: Vec<u8> = ciphertext.iter().map(|b| !b).collect();
        assert_eq!(des_encrypt(&inv_key, &inv_pt).unwrap(), inv_ct);
    }

    use std::iter::zip;

    fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
        zip(x, y).map(|(i, j)| i ^ j).collect()
    }

    #[test]
    fn ch4_4() {
        let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let iv = b"\x87\xF3\x48\xFF\x79\xB8\x11\xAF\x38\x57\xD6\x71\x8E\x5F\x0F\x91";

        let c_0 = iv;
        let c_1 = b"\x7C\x3D\x26\xF7\x73\x77\x63\x5A\x5E\x43\xE9\xB5\xCC\x5D\x05\x92";
        let c_2 = b"\x6E\x26\xFF\xC5\x22\x0D\xC7\xD4\x05\xF1\x70\x86\x70\xE6\xE0\x17";

        let aes = Aes256::new(key.into());
        let mut block_c1: GenericArray<u8, U16> = GenericArray::clone_from_slice(c_1);
        let mut block_c2: GenericArray<u8, U16> = GenericArray::clone_from_slice(c_2);

        aes.decrypt_block(&mut block_c1);
        aes.decrypt_block(&mut block_c2);

        let p_1 = xor(hex::encode(block_c1).as_bytes(), c_0);
        let p_2 = xor(hex::encode(block_c2).as_bytes(), c_1);

        println!("p_1: {:?}", p_1);
        println!("p_2: {:?}", p_2);
    }

    use crate::pkcs_padding;

    #[test]
    fn test_padding() {
        let mut input = b"\x00\x00".to_vec();
        let blocksize = 4;
        pkcs_padding(blocksize, &mut input);
        assert_eq!(input, vec![0, 0, 2, 2]);

        verify_pkcs_padding(blocksize, &input);
    }

    #[test]
    fn test_padding_full_size() {
        let mut input = b"\x00\x00\x00\x00".to_vec();
        let blocksize = 4;
        pkcs_padding(blocksize, &mut input);
        assert_eq!(input, vec![0, 0, 0, 0, 4, 4, 4, 4]);

        verify_pkcs_padding(blocksize, &input);
    }

    #[test]
    fn test_padding_min_size() {
        let mut input = b"\x00\x00\x00".to_vec();
        let blocksize = 4;
        pkcs_padding(blocksize, &mut input);
        assert_eq!(input, vec![0, 0, 0, 1]);

        verify_pkcs_padding(blocksize, &input);
    }

    #[test]
    #[should_panic]
    fn test_verify_padding_fails_zeroes() {
        verify_pkcs_padding(4, &[0, 0, 0, 0]);
    }

    #[test]
    #[should_panic]
    fn test_verify_padding_fails_same_as_block_size() {
        verify_pkcs_padding(4, &[4, 4, 4, 4]);
    }

    #[test]
    #[should_panic]
    fn test_verify_padding_fails_2() {
        verify_pkcs_padding(4, &[4, 4, 4, 4, 4]);
    }

    #[test]
    #[should_panic]
    fn test_verify_padding_fails_3() {
        verify_pkcs_padding(4, &[2, 2, 1, 4]);
    }
}
