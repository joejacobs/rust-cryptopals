extern crate base64;
extern crate botan;
extern crate hex;

use std::cmp;
use std::collections::HashMap;
use std::fs;

const DATA_ROOT: &str = "/Users/joejacobs/dev/cryptopals/data";

fn challenge1() {
    println!("Challenge 1");
    let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let s = hex::decode(hex_str).unwrap();
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        base64::encode(&s)
    );
    println!("\tOk");
}

fn xor(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    assert_eq!(buf1.len(), buf2.len());
    let mut out = Vec::<u8>::new();

    for i in 0..buf1.len() {
        out.push(buf1[i] ^ buf2[i]);
    }

    out
}

fn challenge2() {
    println!("Challenge 2");
    let x1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let x2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
    assert_eq!(
        hex::encode(xor(&x1[..], &x2[..])),
        "746865206b696420646f6e277420706c6179"
    );
    println!("\tOk");
}

fn byte_xor(m: &[u8], b: u8) -> Vec<u8> {
    assert!(m.len() > 0);
    let buf = vec![b; m.len()];
    xor(m, &buf[..])
}

fn build_en_unigram_freq_map() -> HashMap<u8, f64> {
    let csv_bytes = fs::read(format!("{}/unigrams.en", DATA_ROOT)).unwrap();
    let csv_str = String::from_utf8(csv_bytes).unwrap();
    let csv_vec: Vec<&str> = csv_str.split('\n').collect();

    let mut map: HashMap<u8, f64> = HashMap::new();
    map.insert(' ' as u8, 1. / 27.);

    for csv in csv_vec {
        if !csv.is_empty() {
            let v: Vec<&str> = csv.split(",").collect();
            let unigram = v[0].chars().collect::<Vec<char>>()[0] as u8;
            let freq: f64 = v[1].parse().unwrap();
            map.insert(unigram, freq);
            map.insert(unigram - 32, freq);
        }
    }

    map
}

fn en_score(m: &[u8], unigram_freq: &HashMap<u8, f64>) -> f64 {
    let mut score = 0.;

    for c in m {
        score += match unigram_freq.get(c) {
            Some(x) => *x,
            None => 0.,
        };
    }

    score
}

fn bytes_to_printable_str(buf: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::new();

    for b in buf {
        if *b < 0x20 || *b > 0x7e {
            out.push(0x2e);
        } else {
            out.push(*b)
        }
    }

    String::from_utf8(out).unwrap()
}

fn challenge3(unigram_score: &HashMap<u8, f64>) {
    println!("Challenge 3");
    let hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ct = hex::decode(hex_str).unwrap();
    let mut max_score = 0.;
    let mut key = 0u8;

    for k in 0x00..0xff {
        let pt = byte_xor(&ct[..], k);
        let score = en_score(&pt[..], unigram_score);

        if score > max_score {
            max_score = score;
            key = k;
        }
    }

    let s = bytes_to_printable_str(&byte_xor(&ct[..], key)[..]);
    println!("\tIn : 0x{}", hex_str);
    println!("\tKey: 0x{:x}", key);
    println!("\tOut: {}", s);
}

fn challenge4(unigram_score: &HashMap<u8, f64>) {
    println!("Challenge 4");
    let hex_bytes = fs::read(format!("{}/4.txt", DATA_ROOT)).unwrap();
    let hex_strs = String::from_utf8(hex_bytes).unwrap();
    let hex_str_vec: Vec<&str> = hex_strs.split('\n').collect();
    let mut correct_ct = Vec::<u8>::new();
    let mut correct_key = 0u8;
    let mut correct_hs = "";
    let mut max_score = 0.;

    for hs in hex_str_vec {
        let ct = hex::decode(hs).unwrap();

        for k in 0x00..0xff {
            let pt = byte_xor(&ct[..], k);
            let score = en_score(&pt[..], unigram_score);

            if score > max_score {
                correct_ct = ct.clone();
                max_score = score;
                correct_hs = hs;
                correct_key = k;
            }
        }
    }

    let s = bytes_to_printable_str(&byte_xor(&correct_ct[..], correct_key)[..]);
    println!("\tIn : 0x{}", correct_hs);
    println!("\tKey: 0x{:x}", correct_key);
    println!("\tOut: {}", s);
}

fn repeating_key_xor(m: &[u8], k: &[u8]) -> Vec<u8> {
    let mut repeated_key = Vec::<u8>::new();
    let mut key_byte_ctr = 0usize;

    for _ in 0..m.len() {
        repeated_key.push(k[key_byte_ctr]);
        key_byte_ctr = (key_byte_ctr + 1) % k.len();
    }

    xor(m, &repeated_key[..])
}

fn challenge5() {
    println!("Challenge 5");
    let ct = repeating_key_xor(
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        b"ICE",
    );
    assert_eq!(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        hex::encode(ct),
    );
    println!("\tOk");
}

fn hamming_dist(buf1: &[u8], buf2: &[u8]) -> u64 {
    assert_eq!(buf1.len(), buf2.len());
    let mut dist = 0u64;

    for i in 0..buf1.len() {
        let mut val = buf1[i] ^ buf2[i];

        while val != 0 {
            dist += 1;
            val &= val - 1;
        }
    }

    dist
}

fn print_2d_byte_vec(v: &[Vec<u8>]) {
    let mut out_str = String::new();

    for i in 0..v.len() {
        let mut row_str = String::new();

        for j in 0..v[i].len() {
            if row_str.is_empty() {
                row_str = format!("{:02x}", v[i][j]);
            } else {
                row_str = format!("{}, {:02x}", row_str, v[i][j]);
            }
        }

        if out_str.is_empty() {
            out_str = format!("{}", row_str);
        } else {
            out_str = format!("{}\n{}", out_str, row_str);
        }
    }

    println!("{}", out_str);
}

fn challenge6(unigram_score: &HashMap<u8, f64>) {
    println!("Challenge 6");
    let b64_bytes = fs::read(format!("{}/6.txt", DATA_ROOT)).unwrap();
    let b64_str = String::from_utf8(b64_bytes).unwrap().replace("\n", "");
    let ct = base64::decode(&b64_str).unwrap();

    // determine key size
    let mut key_sz = 0;
    let mut min_dist = 999.;

    for ks in 2..41 {
        let mut dist_sum = 0.;
        let mut n_dists = 10;

        for i in 0..n_dists {
            let off1 = i * ks;
            let off2 = (i + 1) * ks;
            let off3 = (i + 2) * ks;

            if off3 >= ct.len() {
                n_dists = i;
                break;
            }

            dist_sum += hamming_dist(&ct[off1..off2], &ct[off2..off3]) as f64;
        }

        let av_dist = dist_sum / (n_dists as f64);
        let norm_dist = av_dist / (ks as f64);

        if min_dist > norm_dist {
            key_sz = ks;
            min_dist = norm_dist;
        }
    }

    // determine key
    let n_blocks = ((ct.len() as f64) / (key_sz as f64)).ceil() as usize;
    let mut key = Vec::<u8>::new();

    for i in 0..key_sz {
        let mut ct_block = Vec::<u8>::new();

        for j in 0..n_blocks {
            let idx = (j * key_sz) + i;

            if idx < ct.len() {
                ct_block.push(ct[idx]);
            }
        }

        let mut max_score = 0.;
        let mut best_k = 0u8;

        for k in 0x00..0xff {
            let pt = byte_xor(&ct_block[..], k);
            let score = en_score(&pt[..], unigram_score);

            if score > max_score {
                max_score = score;
                best_k = k;
            }
        }

        key.push(best_k)
    }

    let pt = repeating_key_xor(&ct[..], &key[..]);
    let s = String::from_utf8(pt).unwrap().replace("\n", "\n\t     ");
    println!("\tKey: 0x{}", hex::encode(&key[..]));
    println!("\t     ({})", bytes_to_printable_str(&key[..]));
    println!("\tOut: {}", s);
}

fn aes_128_ecb_decrypt(k: &[u8], ct: &[u8]) -> Vec<u8> {
    let cipher = botan::BlockCipher::new("AES-128").unwrap();
    cipher.set_key(k).unwrap();
    cipher.decrypt_blocks(&ct[..]).unwrap()
}

fn challenge7() {
    println!("Challenge 7");
    let b64_bytes = fs::read(format!("{}/7.txt", DATA_ROOT)).unwrap();
    let b64_str = String::from_utf8(b64_bytes).unwrap().replace("\n", "");
    let ct = base64::decode(&b64_str).unwrap();
    let k = b"YELLOW SUBMARINE";
    let pt = aes_128_ecb_decrypt(&k[..], &ct[..]);
    println!(
        "\tOut: {}",
        String::from_utf8(pt).unwrap().replace("\n", "\n\t     ")
    );
}

fn challenge8() {
    println!("Challenge 8");
    let hex_bytes = fs::read(format!("{}/8.txt", DATA_ROOT)).unwrap();
    let hex_strs = String::from_utf8(hex_bytes).unwrap();
    let hex_str_vec: Vec<&str> = hex_strs.split('\n').collect();

    for hs in hex_str_vec {
        let mut map = HashMap::<[u8; 16], u64>::new();
        let ct = hex::decode(hs).unwrap();
        let n_blocks = (ct.len() as f64 / 16.).ceil() as usize;

        for i in 0..n_blocks {
            let fst = i * 16;
            let lst = cmp::min((i + 1) * 16, ct.len());
            let mut block = [0u8; 16];

            for j in fst..lst {
                block[j - fst] = ct[j];
            }

            let ctr = match map.get(&block) {
                Some(x) => *x + 1,
                None => 1,
            };

            map.insert(block, ctr);
        }

        for ctr in map.values() {
            if *ctr > 1 {
                for i in 0..n_blocks {
                    let fst = i * 16;
                    let lst = cmp::min((i + 1) * 16, ct.len());

                    if i == 0 {
                        println!("\tOut: {:02x?}", &ct[fst..lst]);
                    } else {
                        println!("\t     {:02x?}", &ct[fst..lst]);
                    }
                }

                break;
            }
        }
    }
}

fn pkcs7_pad(m: &[u8], block_len: usize) -> Vec<u8> {
    assert!(block_len <= 0xFF);
    assert!(m.len() <= block_len);
    let pad_len = block_len - m.len();
    let mut padded_m = vec![pad_len as u8; block_len];
    padded_m[..m.len()].copy_from_slice(m);
    padded_m
}

fn pkcs7_unpad(m: &[u8]) -> Vec<u8> {
    let lst = m.len();
    let pad_len = m[lst - 1];
    let fst = lst - (pad_len as usize);
    let mut unpadded_m = Vec::<u8>::new();

    if botan::const_time_compare(&m[fst..lst], &vec![pad_len; lst - fst][..]) {
        unpadded_m.extend_from_slice(&m[..fst]);
    } else {
        unpadded_m.extend_from_slice(m);
    }

    unpadded_m
}

fn challenge9() {
    println!("Challenge 9");
    assert_eq!(
        String::from("YELLOW SUBMARINE\x04\x04\x04\x04").into_bytes(),
        pkcs7_pad(b"YELLOW SUBMARINE", 20)
    );
    println!("\tOk");
}

fn aes_128_cbc_decrypt(k: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
    let blk_sz = 16;
    assert_eq!(iv.len(), blk_sz);
    let cipher = botan::BlockCipher::new("AES-128").unwrap();
    cipher.set_key(k).unwrap();

    let tmp_pt = cipher.decrypt_blocks(ct).unwrap();
    let mut tmp_iv = Vec::<u8>::new();
    tmp_iv.extend_from_slice(iv);
    tmp_iv.extend_from_slice(&ct[..ct.len() - blk_sz]);
    pkcs7_unpad(&xor(&tmp_iv[..], &tmp_pt[..])[..])
}

fn aes_128_cbc_encrypt(k: &[u8], iv: &[u8], pt: &[u8]) -> Vec<u8> {
    let blk_sz = 16;
    assert_eq!(iv.len(), blk_sz);
    let cipher = botan::BlockCipher::new("AES-128").unwrap();
    let n_blks = (pt.len() as f64 / (blk_sz as f64)).ceil() as usize;
    let mut cbc_ct = vec![0u8; n_blks * 16];
    let mut blk_ct = iv.to_vec();
    cipher.set_key(k).unwrap();

    for i in 0..n_blks {
        let fst = i * 16;
        let lst = cmp::min(fst + 16, pt.len());
        let blk_pt = xor(&blk_ct[..], &pkcs7_pad(&pt[fst..lst], 16)[..]);
        blk_ct = cipher.encrypt_blocks(&blk_pt[..]).unwrap();
        cbc_ct[fst..fst + 16].copy_from_slice(&blk_ct[..]);
    }

    cbc_ct
}

fn challenge10() {
    println!("Challenge 10");
    let b64_bytes = fs::read(format!("{}/10.txt", DATA_ROOT)).unwrap();
    let b64_str = String::from_utf8(b64_bytes).unwrap().replace("\n", "");
    let ct = base64::decode(&b64_str).unwrap();
    let k = b"YELLOW SUBMARINE";
    let iv = [0u8; 16];
    let pt = aes_128_cbc_decrypt(&k[..], &iv[..], &ct[..]);
    assert_eq!(ct, aes_128_cbc_encrypt(&k[..], &iv[..], &pt[..]));
    println!(
        "\tOut: {}",
        String::from_utf8(pt).unwrap().replace("\n", "\n\t     "),
    );
}

fn generate_aes_key() -> Vec<u8> {
    botan::RandomNumberGenerator::new().unwrap().read(16).unwrap()
}

fn encryption_oracle(m: &[u8]) -> Vec<u8> {
    generate_aes_key()
}

fn challenge11() {
    println!("Challenge 11");
}

fn main() {
    let en_unigram_freq = build_en_unigram_freq_map();
    challenge1();
    challenge2();
    challenge3(&en_unigram_freq);
    challenge4(&en_unigram_freq);
    challenge5();
    challenge6(&en_unigram_freq);
    challenge7();
    challenge8();
    challenge9();
    challenge10();
    challenge11();
}
