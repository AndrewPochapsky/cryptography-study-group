#[cfg(test)]
pub mod testing;

use std::{
    collections::HashMap,
};

use sha2::{self, Digest, Sha512};

fn sha512_n(message: &[u8], n: u8) -> Vec<u8> {
    let num_bytes = n / 8;
    let mut hasher = Sha512::new();

    hasher.update(message);
    let result: Vec<u8> = hasher.finalize().to_vec();

    result[0..(num_bytes as usize)].to_vec()
}

fn birthday_attack(n: u8) {
    let num_terations = get_num_iterations(n.into());
    println!("Running birthday attack for n = {}", n);
    let mut i = 0;
    let mut map: HashMap<Vec<u8>, String> = HashMap::new();
    while i < num_terations {
        let message = format!("Hello World {0}", rand::random::<u32>());
        let result = sha512_n(message.as_bytes(), n);
        if map.contains_key(&result) {
            // collision!
            println!(
                "Found colision between {} and {}",
                map.get(&result).unwrap(),
                message
            );
            return;
        } else {
            map.insert(result, message);
        }
        i += 1;
    }

    println!("No colisions found");
}

fn get_num_iterations(n: u32) -> u32 {
    2u32.pow(n / 2)
}

fn get_preimage(n: u8, image: &[u8]) -> (u32, String) {
    let max_iterations = 2u32.pow(n as u32);
    let mut i = 0;
    while i < max_iterations {
        let message = format!("Hello World {0}", rand::random::<u32>());
        let result = sha512_n(message.as_bytes(), n);
        if result == image {
            return (i + 1, message);
        }
        i += 1;
    }
    (max_iterations, String::new())
}

#[test]
fn test_birthday_attack() {
    let mut total_time = 0;
    for _ in 0..5 {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        birthday_attack(8);
        let end_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        total_time += end_time - start_time;
    }

    let avg_time = total_time / 5;
    println!("Average time is {}ns", avg_time);
}

#[test]
fn test_get_preimage() {
    let message = b"\x3D\x4B";
    let mut total_iterations = 0;
    for _ in 0..5 {
        let (num_iterations, result) = get_preimage(16, message);
        println!(
            "Found pre_image: {}, which took {} iterations",
            result, num_iterations
        );
        total_iterations += num_iterations;
    }
    let average_num_iterations = total_iterations / 5;
    // I at first thought that this should be around 2^8 = 256 iterations. But, then I realized
    // (after seem the results unfortunately), that that doesn't make sense since we aren't looking
    // for ANY colision, we are looking for a very specific colision so to speak. Therefore, this
    // should take around 2^15 = 32768 (half of the outputs) to find one on average.
    println!("Average number of iterations: {}", average_num_iterations);
}

#[test]
fn test_compute_mac() {
    use openssl::symm::{encrypt, Cipher};
    let message = b"\x4D\x41\x43\x73\x20\x61\x72\x65\x20\x76\x65\x72\x79\x20\x75\x73\x65\x66\x75\x6C\x20\x69\x6E\x20\x63\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x79\x21\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";
    let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
    let res = encrypt(Cipher::aes_256_cbc(), key, None, message).unwrap();
    println!("Total length: {}", res.len());
    // Only take the last block.
    println!("Result: {:?}", &res[res.len() - 16..]);
}
