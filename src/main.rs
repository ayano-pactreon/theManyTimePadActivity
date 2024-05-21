use std::collections::HashMap;
use std::str;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).expect("Invalid hex string");
        bytes.push(byte);
    }
    bytes
}

fn xor_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    ciphertext
        .iter()
        .zip(key.iter())
        .map(|(c, k)| c ^ k)
        .collect()
}

fn score_decryption(decrypted: &[u8]) -> f32 {
    let english_frequencies = english_char_frequency();
    let mut score = 0.0;

    for byte in decrypted {
        let ch = *byte as char;
        if english_frequencies.contains_key(&ch) {
            score += english_frequencies[&ch];
        }
    }
    score
}

fn english_char_frequency() -> HashMap<char, f32> {
    let mut frequencies = HashMap::new();
    frequencies.insert(' ', 15.00);
    frequencies.insert('!', 0.50);
    frequencies.insert(',', 1.00);
    frequencies.insert('.', 1.00);
    frequencies.insert('?', 0.50);
    frequencies.insert('a', 8.16);
    frequencies.insert('b', 1.49);
    frequencies.insert('c', 2.42);
    frequencies.insert('d', 4.32);
    frequencies.insert('e', 12.70);
    frequencies.insert('f', 2.09);
    frequencies.insert('g', 1.63);
    frequencies.insert('h', 6.02);
    frequencies.insert('i', 7.00);
    frequencies.insert('j', 0.10);
    frequencies.insert('k', 0.78);
    frequencies.insert('l', 4.00);
    frequencies.insert('m', 2.09);
    frequencies.insert('n', 6.24);
    frequencies.insert('o', 7.57);
    frequencies.insert('p', 1.52);
    frequencies.insert('q', 0.11);
    frequencies.insert('r', 5.99);
    frequencies.insert('s', 6.24);
    frequencies.insert('t', 9.06);
    frequencies.insert('u', 2.49);
    frequencies.insert('v', 0.98);
    frequencies.insert('w', 1.98);
    frequencies.insert('x', 0.17);
    frequencies.insert('y', 1.59);
    frequencies.insert('z', 0.07);

    frequencies
}

fn break_single_xor(ciphertext: &[u8]) -> (Vec<u8>, f32) {
    let mut best_key = vec![0; ciphertext.len()];
    let mut best_score = f32::MIN;
    for key_byte in 0..=255 {
        let key = vec![key_byte; ciphertext.len()];
        let decrypted = xor_decrypt(ciphertext, &key);
        let score = score_decryption(&decrypted);
        if score > best_score {
            best_score = score;
            best_key = key;
        }
    }
    (best_key, best_score)
}

fn main() {
    let ciphertexts = vec![
        "160111433b00035f536110435a380402561240555c526e1c0e431300091e4f04451d1d490d1c49010d000a0a4510111100000d434202081f0755034f13031600030d0204040e",
        "050602061d07035f4e3553501400004c1e4f1f01451359540c5804110c1c47560a1415491b06454f0e45040816431b144f0f4900450d1501094c1b16550f0b4e151e03031b450b4e020c1a124f020a0a4d09071f16003a0e5011114501494e16551049021011114c291236520108541801174b03411e1d124554284e141a0a1804045241190d543c00075453020a044e134f540a174f1d080444084e01491a090b0a1b4103570740",
        "000000000000001a49320017071704185941034504524b1b1d40500a0352441f021b0708034e4d0008451c40450101064f071d1000100201015003061b0b444c00020b1a16470a4e051a4e114f1f410e08040554154f064f410c1c00180c0010000b0f5216060605165515520e09560e00064514411304094c1d0c411507001a1b45064f570b11480d001d4c134f060047541b185c",
        "0b07540c1d0d0b4800354f501d131309594150010011481a1b5f11090c0845124516121d0e0c411c030c45150a16541c0a0b0d43540c411b0956124f0609075513051816590026004c061c014502410d024506150545541c450110521a111758001d0607450d11091d00121d4f0541190b45491e02171a0d49020a534f",
        "031a5410000a075f5438001210110a011c5350080a0048540e431445081d521345111c041f0245174a0006040002001b01094914490f0d53014e570214021d00160d151c57420a0d03040b4550020e1e1f001d071a56110359420041000c0b06000507164506151f104514521b02000b0145411e05521c1852100a52411a0054180a1e49140c54071d5511560201491b0944111a011b14090c0e41",
        "0b4916060808001a542e0002101309050345500b00050d04005e030c071b4c1f111b161a4f01500a08490b0b451604520d0b1d1445060f531c48124f1305014c051f4c001100262d38490f0b4450061800004e001b451b1d594e45411d014e004801491b0b0602050d41041e0a4d53000d0c411c41111c184e130a0015014f03000c1148571d1c011c55034f12030d4e0b45150c5c",
        "011b0d131b060d4f5233451e161b001f59411c090a0548104f431f0b48115505111d17000e02000a1e430d0d0b04115e4f190017480c14074855040a071f4448001a050110001b014c1a07024e5014094d0a1c541052110e54074541100601014e101a5c",
        "0c06004316061b48002a4509065e45221654501c0a075f540c42190b165c",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ];

    let mut key = vec![0; ciphertexts[0].len()];

    for i in 0..key.len() {
        let mut combined_ciphertext = Vec::new();
        for ct in &ciphertexts {
            let bytes = hex_to_bytes(ct);
            if i < bytes.len() {
                combined_ciphertext.extend_from_slice(&bytes[i..i + 1]);
            }
        }
        let (best_key_byte, _) = break_single_xor(&combined_ciphertext);
        key[i] = best_key_byte[0];
    }

    let valid_ascii_bytes: Vec<u8> = key
        .clone()
        .into_iter()
        .filter(|&b| b >= 32 && b <= 126)
        .collect();

    let bytes = hex_to_bytes(ciphertexts.last().unwrap());
    let decrypted = xor_decrypt(&bytes, &valid_ascii_bytes);
    let result = String::from_utf8_lossy(&decrypted);
    println!("Decrypted text:\n{}", result);

    // Based on the last line of decrypted outputs, the first statement in the Bitcoin whitepaper expected to be the key
    let key = "Bitcoin: A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution.";

    println!("\nDecrypted texts:");
    for ciphertext in &ciphertexts {
        let bytes = hex_to_bytes(ciphertext);
        let decrypted = xor_decrypt(&bytes, &key.as_bytes());
        let result = String::from_utf8_lossy(&decrypted);
        println!("{}", result);
    }

    let final_ciphertext = "1f3cb1f3e01f3fd1f3ea1f3e61f3e01f3e71f3b31f3a91f3c81f3a91f3f91f3fc1f3fb1f3ec1f3e51f3f01f3a91f3f91f3ec1f3ec526e1b014a020411074c17111b1c071c4e4f0146430d0d08131d1d010707040017091648461e1d0618444f074c010e19594f0f1f1a07024e1d041719164e1c1652114f411645541b004e244f080213010c004c3b4c0911040e480e070b00310213101c4d0d4e00360b4f151a005253184913040e115454084f010f114554111d1a550f0d520401461f3e01f3e71f3e81f3e71f3ea1f3e01f3e81f3e51f3a91f3e01f3e71f3fa1f3fd1f3e01f3fd1f3fc1f3fd1f3e01f3e61f3e71f3a7";
    let clean_ciphertext = final_ciphertext.replace("1f3", "");
    let bytes = hex_to_bytes(&clean_ciphertext);
    let decrypted = xor_decrypt(&bytes, &key.as_bytes());
    let result = String::from_utf8_lossy(&decrypted);
    println!("\nFinal text:\n{}", result);
}
