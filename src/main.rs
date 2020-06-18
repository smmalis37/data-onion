#![feature(array_value_iter)]

use anyhow::*;
use std::fs::{read_to_string, write};

fn main() -> Result<()> {
    for i in 0..=1 {
        let input = read(i)?;
        let output: Vec<_> = match i {
            0 => part0(&input).collect(),
            1 => part1(&input).collect(),
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

fn part0(input: &[u8]) -> impl Iterator<Item = u8> + '_ {
    input.chunks(5).flat_map(decode_ascii85_chunk)
}

fn part1(input: &[u8]) -> impl Iterator<Item = u8> + '_ {
    part0(input).map(|x| (x ^ 0x55).rotate_right(1))
}
