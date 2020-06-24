use anyhow::*;
use itertools::Itertools;
use openssl::aes::{unwrap_key, AesKey};
use openssl::symm::{decrypt, Cipher};
use pnet_packet::ipv4::{checksum as ip_checksum, Ipv4Packet};
use pnet_packet::udp::{ipv4_checksum as udp_checksum, UdpPacket};
use pnet_packet::{Packet, PacketSize};
use smallvec::SmallVec;
use std::convert::TryInto;
use std::fs::{read_to_string, write};
use std::net::Ipv4Addr;
use std::time::Instant;

// TODO: Replace SmallVec with #![feature(array_value_iter)] when stable.

fn main() -> Result<()> {
    let parts: Vec<&dyn Fn(&[u8]) -> Result<Vec<u8>>> =
        vec![&part0, &part1, &part2, &part3, &part4, &part5];

    for (i, f) in parts.into_iter().enumerate() {
        let input = read(i)?;
        let start_time = Instant::now();
        let output = f(&input)?;
        let final_time = Instant::now();
        println!("Part {} took {:?}.", i, final_time - start_time);
        write(get_path(i + 1), output)?;
    }

    Ok(())
}

fn get_path(i: usize) -> String {
    format!("onion/{}.txt", i)
}

fn read(i: usize) -> Result<Vec<u8>> {
    let file_contents = read_to_string(get_path(i)).context("Failed reading input file.")?;

    let payload_index = file_contents
        .find("<~")
        .context("Failed finding payload marker.")?;

    let payload = file_contents[payload_index..].trim();

    ensure!(
        &payload[0..2] == "<~",
        anyhow!("Start token not at start of string.")
    );

    ensure!(
        &payload[payload.len() - 2..] == "~>",
        anyhow!("End token not at end of string.")
    );

    Ok(payload[2..payload.len() - 2]
        .as_bytes()
        .iter()
        .copied()
        .filter(|x| !x.is_ascii_whitespace())
        .collect())
}

fn decode_ascii85_chunk(x: &[u8]) -> impl Iterator<Item = u8> {
    assert!(x.len() <= 5 && !x.is_empty());
    let padding_count = 5 - x.len();

    let value: u32 = x
        .iter()
        .chain(std::iter::repeat(&b'u').take(padding_count))
        .enumerate()
        .map(|(i, &v)| (v as u32 - 33) * 85u32.pow(4 - i as u32))
        .sum();

    SmallVec::from_buf(value.to_be_bytes())
        .into_iter()
        .take(4 - padding_count)
}

fn decode_ascii85(input: &[u8]) -> impl Iterator<Item = u8> + '_ {
    input.chunks(5).flat_map(decode_ascii85_chunk)
}

fn part0(input: &[u8]) -> Result<Vec<u8>> {
    Ok(decode_ascii85(input).collect())
}

fn part1(input: &[u8]) -> Result<Vec<u8>> {
    Ok(decode_ascii85(input)
        .map(|x| (x ^ 0x55).rotate_right(1))
        .collect())
}

fn part2(input: &[u8]) -> Result<Vec<u8>> {
    Ok(decode_ascii85(input)
        .filter(|x| x.count_ones() % 2 == 0)
        .chunks(8)
        .into_iter()
        .flat_map(|c| {
            let value: u64 = c
                .enumerate()
                .map(|(i, x)| ((x & 0xFE) as u64) << (56 - (i * 7)))
                .sum();

            SmallVec::from_buf(value.to_be_bytes()).into_iter().take(7)
        })
        .collect())
}

fn part3(input: &[u8]) -> Result<Vec<u8>> {
    const KEY_SIZE: usize = 32;
    const KNOWN_PLAINTEXT: &[u8] = b"==[ Payload ]===================";
    assert!(KNOWN_PLAINTEXT.len() == KEY_SIZE);
    const VERIFY_TEXT: &[u8] = b"==[ Payload ]===============================================";

    let cipher_text: Vec<_> = decode_ascii85(input).collect();

    for (i, w) in cipher_text.windows(KEY_SIZE).enumerate() {
        let mut possible_key: Vec<_> = w
            .iter()
            .zip(KNOWN_PLAINTEXT)
            .map(|(x1, x2)| x1 ^ x2)
            .collect();
        possible_key.rotate_right(i % KEY_SIZE);

        let decoded_text: Vec<_> = cipher_text
            .iter()
            .zip(possible_key.iter().cycle())
            .map(|(x1, x2)| x1 ^ x2)
            .collect();

        if decoded_text[i..].starts_with(VERIFY_TEXT) {
            return Ok(decoded_text);
        }
    }

    unreachable!()
}

fn part4(input: &[u8]) -> Result<Vec<u8>> {
    const VALID_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 1, 1, 10);
    const VALID_DEST: Ipv4Addr = Ipv4Addr::new(10, 1, 1, 200);
    const VALID_DEST_PORT: u16 = 42069;

    let mut data = vec![];
    let input: Vec<_> = decode_ascii85(input).collect();
    let mut unread: &[u8] = &input;

    while !unread.is_empty() {
        let ip_packet = Ipv4Packet::new(unread).context("Failed to parse IP packet.")?;
        let udp_packet =
            UdpPacket::new(ip_packet.payload()).context("Failed to parse UDP packet.")?;

        unread = &unread[ip_packet.packet_size() as usize..];

        let source_ip = ip_packet.get_source();
        let dest_ip = ip_packet.get_destination();

        if source_ip == VALID_SOURCE
            && dest_ip == VALID_DEST
            && udp_packet.get_destination() == VALID_DEST_PORT
            && ip_packet.get_checksum() == ip_checksum(&ip_packet)
            && udp_packet.get_checksum() == udp_checksum(&udp_packet, &source_ip, &dest_ip)
        {
            data.extend_from_slice(&udp_packet.payload());
        }
    }

    ensure!(unread.is_empty(), anyhow!("Did not consume all input."));
    Ok(data)
}

fn part5(input: &[u8]) -> Result<Vec<u8>> {
    let input: Vec<_> = decode_ascii85(input).collect();
    let kek = &input[..32];
    let kek_iv = &input[32..40];
    let encrypted_key = &input[40..80];
    let payload_iv = &input[80..96];
    let payload = &input[96..];

    // TODO: When openssl has `impl Error for aes::KeyError` change below unwraps into ?
    let mut decrypted_key = [0; 32];
    let kek = AesKey::new_decrypt(kek).unwrap();
    let decrypted_len = unwrap_key(
        &kek,
        Some(kek_iv.try_into().unwrap()),
        &mut decrypted_key,
        encrypted_key,
    )
    .unwrap();
    assert!(decrypted_len == decrypted_key.len());

    Ok(decrypt(
        Cipher::aes_256_cbc(),
        &decrypted_key,
        Some(payload_iv),
        payload,
    )?)
}
