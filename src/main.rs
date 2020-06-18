#![feature(array_value_iter)]

use anyhow::*;
use itertools::Itertools;
use std::fs::{read_to_string, write};

fn main() -> Result<()> {
    for i in 0..=3 {
        let input = read(i)?;
        let output = match i {
            0 => part0(&input),
            1 => part1(&input),
            2 => part2(&input),
            3 => part3(&input),
            _ => unreachable!(),
        };
        write(get_path(i + 1), output)?;
    }

    Ok(())
}

fn get_path(i: u8) -> String {
    format!("onion/{}.txt", i)
}

fn read(i: u8) -> Result<Vec<u8>> {
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
    let padding_count = 5 - x.len();
    let value: u32 = x
        .iter()
        .chain(std::iter::repeat(&b'u').take(padding_count))
        .enumerate()
        .map(|(i, &v)| (v as u32 - 33) * 85u32.pow(4 - i as u32))
        .sum();

    std::array::IntoIter::new(value.to_be_bytes()).take(4 - padding_count)
}

fn decode_ascii85(input: &[u8]) -> impl Iterator<Item = u8> + '_ {
    input.chunks(5).flat_map(decode_ascii85_chunk)
}

fn part0(input: &[u8]) -> Vec<u8> {
    decode_ascii85(input).collect()
}

fn part1(input: &[u8]) -> Vec<u8> {
    decode_ascii85(input)
        .map(|x| (x ^ 0x55).rotate_right(1))
        .collect()
}

fn part2(input: &[u8]) -> Vec<u8> {
    decode_ascii85(input)
        .filter(|x| x.count_ones() % 2 == 0)
        .chunks(8)
        .into_iter()
        .flat_map(|c| {
            let mut value: u64 = 0;
            for (i, x) in c.enumerate() {
                value |= ((x & 0xFE) as u64) << (56 - (i * 7));
            }

            std::array::IntoIter::new(value.to_be_bytes()).take(7)
        })
        .collect()
}

fn part3(input: &[u8]) -> Vec<u8> {
    const KEY_SIZE: usize = 32;
    const KNOWN_PLAINTEXT: &[u8] = b"==[ Payload ]===================";
    assert!(KNOWN_PLAINTEXT.len() == KEY_SIZE);
    const VERIFY_TEXT: &[u8] = b"==[ Payload ]===============================================";

    let cipher_text: Vec<_> = part0(input);

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
            return decoded_text;
        }
    }

    unreachable!()
}
