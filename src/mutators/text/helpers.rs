use lazy_static::lazy_static;
use rand::distributions::{Alphanumeric, DistString};
use rand::prelude::Distribution;
use rand::seq::{IteratorRandom, SliceRandom};
use regex::bytes::Regex;

use crate::mutators::bytes::helpers::INTERESTING_U64;
use crate::utils;

lazy_static! {
    pub static ref INTERESTING_INTEGERS: Vec<String> = {
        INTERESTING_U64
            .iter()
            .copied()
            .map(|i| [format!("{i}"), format!("-{i}")])
            .flatten()
            .collect()
    };
    pub static ref INTERESTING_HEX_INTEGERS: Vec<String> = {
        INTERESTING_U64
            .iter()
            .copied()
            .map(|i| format!("{:#x}", i))
            .collect()
    };
    pub static ref INTEGER_REGEX: Regex = Regex::new(r"[^\d][\d]+[^\d]").unwrap();
    pub static ref HEX_INTEGER_REGEX: Regex =
        Regex::new(r"[^\da-fA-F][\da-fA-F][^\da-fA-F]").unwrap();
}

#[derive(Hash, PartialEq, Debug, Copy, Clone)]
pub enum DelimiterDirection {
    Forward,
    Backward,
}

pub fn other_delimiter(delim: u8) -> Option<(u8, DelimiterDirection)> {
    match delim {
        b'<' => Some((b'>', DelimiterDirection::Forward)),
        b'>' => Some((b'<', DelimiterDirection::Backward)),
        b'(' => Some((b')', DelimiterDirection::Forward)),
        b')' => Some((b'(', DelimiterDirection::Backward)),
        b'{' => Some((b'}', DelimiterDirection::Forward)),
        b'}' => Some((b'{', DelimiterDirection::Backward)),
        b'[' => Some((b']', DelimiterDirection::Forward)),
        b']' => Some((b'[', DelimiterDirection::Backward)),
        b'"' => Some((b'"', DelimiterDirection::Forward)),
        b'\'' => Some((b'\'', DelimiterDirection::Forward)),
        _ => None,
    }
}

// pub fn pseudo_parse(data: &[u8]) ->

pub fn get_delimited_block(
    _data: &[u8],
    _rng: &mut impl rand::Rng,
) -> Option<std::ops::Range<usize>> {
    todo!();

    // None
}

pub fn get_delimited_block_quickly(
    _data: &[u8],
    _rng: &mut impl rand::Rng,
) -> Option<std::ops::Range<usize>> {
    todo!();
    // other.iter().copied().
    // None
}

/// Generate a random ascii string with the exact length.
pub fn random_ascii_string_exact(rng: &mut impl rand::Rng, max_length: usize) -> String {
    Alphanumeric.sample_string(rng, max_length)
}

/// Generate a random ascii string with a length up to max_length.
pub fn random_ascii_string(rng: &mut impl rand::Rng, max_length: usize) -> String {
    assert!(max_length > 1);
    let start = if max_length > 5 { 5 } else { 1 };
    let size = rng.gen_range(start..max_length);
    Alphanumeric.sample_string(rng, size)
}

/// Identify an integer in the text input and replace it with the given replacement bytes.
pub fn replace_integer_with(
    data: &mut Vec<u8>,
    repl: &[u8],
    rng: &mut impl rand::Rng,
) -> Option<std::ops::Range<usize>> {
    if let Some(irange) = INTEGER_REGEX
        .find_iter(&data)
        .choose(rng)
        .map(|m| (m.start() + 1)..m.end())
    {
        utils::vec::splice_into(data, irange.clone(), repl);
        Some(irange)
    } else {
        None
    }
}

/// Identify a hex integer in the text input and replace it with the given replacement bytes.
pub fn replace_hex_integer_with(
    data: &mut Vec<u8>,
    repl: &[u8],
    rng: &mut impl rand::Rng,
) -> Option<std::ops::Range<usize>> {
    if let Some(irange) = HEX_INTEGER_REGEX
        .find_iter(&data)
        .choose(rng)
        .map(|m| m.range())
    {
        utils::vec::splice_into(data, irange.clone(), repl);
        Some(irange)
    } else {
        None
    }
}

/// Identify an integer and replace it with a random u64.
pub fn replace_integer_with_rand(
    data: &mut Vec<u8>,
    rng: &mut impl rand::Rng,
) -> Option<std::ops::Range<usize>> {
    let i: u64 = rng.gen();
    let repl = format!("{}", i).into_bytes();
    replace_integer_with(data, &repl, rng)
}

/// Identify a hex integer and replace it with a random u64.
pub fn replace_hex_integer_with_rand(
    data: &mut Vec<u8>,
    rng: &mut impl rand::Rng,
) -> Option<std::ops::Range<usize>> {
    let i: u64 = rng.gen();
    let repl = format!("{:#x}", i).into_bytes();
    replace_integer_with(data, &repl, rng)
}

/// Identify an integer and replace it with an interesting integer value.
/// See [`INTERESTING_U64`] for the set of values.
pub fn replace_integer_with_interesting(
    data: &mut Vec<u8>,
    rng: &mut impl rand::Rng,
) -> Option<std::ops::Range<usize>> {
    let repl = INTERESTING_INTEGERS.choose(rng).unwrap().as_bytes();
    replace_integer_with(data, repl, rng)
}

/// Identify a hex integer and replace it with an interesting integer value.
/// See [`INTERESTING_U64`] for the set of values.
pub fn replace_hex_integer_with_interesting(
    data: &mut Vec<u8>,
    rng: &mut impl rand::Rng,
) -> Option<std::ops::Range<usize>> {
    let repl = INTERESTING_HEX_INTEGERS.choose(rng).unwrap().as_bytes();
    replace_integer_with(data, repl, rng)
}

/// Replace a random char in the input - more likely with another ascii value.
pub fn char_replace<T: AsMut<[u8]>>(
    input: &mut T,
    rng: &mut impl rand::Rng,
) -> Option<(usize, u8)> {
    let input = input.as_mut();
    if input.is_empty() {
        return None;
    }
    let idx = rng.gen_range(0..input.len());
    let ascii = rng.gen_bool(0.8);
    let r: u8 = if ascii {
        Alphanumeric.sample(rng)
    } else {
        rng.gen()
    };
    input[idx] = r;
    Some((idx, r))
}

/// Insert a random ascii string at random offset.
/// returns `(offset, inserted_len)`.
pub fn insert_random_string<const N: usize>(
    input: &mut Vec<u8>,
    rng: &mut impl rand::Rng,
) -> Option<(usize, usize)> {
    if input.is_empty() {
        return None;
    }
    let s = random_ascii_string(rng, N);
    let idx = rng.gen_range(0..=input.len());
    utils::vec::fast_insert_at(input, idx, s.as_bytes());
    Some((idx, s.len()))
}

/// Insert up to N random ascii chars at a random offset.
pub fn insert_repeated_chars<const N: usize>(
    input: &mut Vec<u8>,
    rng: &mut impl rand::Rng,
) -> Option<(usize, u8, usize)> {
    if input.is_empty() {
        return None;
    }

    let count = rng.gen_range(0..N);
    let c: u8 = Alphanumeric.sample(rng);
    let data = [c; N];
    let idx = rng.gen_range(0..=input.len());
    utils::vec::fast_insert_at(input, idx, &data[..count]);
    Some((idx, c, count))
}

/// Insert data after a separator and add another separator.
///
/// ```rust,ignore
/// let mut v = b"asdf; asdf";
/// insert_separated(v, ';', "XXXX", rng);
/// assert_eq!(v, b"asdf;XXXX; asdf");
/// ```
pub fn insert_separated<T>(
    input: &mut Vec<u8>,
    sep: T,
    other: &[u8],
    rng: &mut impl rand::Rng,
) -> Option<usize>
where
    T: TryInto<u8>,
    <T as TryInto<u8>>::Error: std::fmt::Debug,
{
    let sep: u8 = sep.try_into().unwrap();
    input.reserve(other.len() + 2);

    // if the target input is empty, just insert everything and add a separator before and after.
    if input.is_empty() {
        input.push(sep);
        input.extend_from_slice(other);
        input.push(sep);
        return Some(0);
    }

    // select a random occurence of the separator char or otherwise append.
    if let Some(index) = input
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(i, c)| if c == sep { Some(i) } else { None })
        .choose(rng)
    {
        // insert after the seperator and append another separator.
        let sep = [sep];
        utils::vec::fast_insert_two_at(input, index + 1, other, &sep);
        Some(index)
    } else {
        // insert (separator + other + separator) into the input
        let l = input.len();
        // or append separator + other at the end of the testcase
        input.push(sep);
        input.extend_from_slice(other);
        input.push(sep);
        Some(l)
    }
}

/// Splice data between a separator.
///
/// ```rust,ignore
/// let mut v = b"asdf; asdf".to_vec();
/// splice_separated(&mut v, ';', "XXXX; AAAA", rng);
/// assert_eq!(v, b"XXXX; asdf");
/// ```
pub fn splice_separated<T>(
    input: &mut Vec<u8>,
    sep: T,
    other: &[u8],
    rng: &mut impl rand::Rng,
) -> Option<(usize, usize)>
where
    T: TryInto<u8>,
    <T as TryInto<u8>>::Error: std::fmt::Debug,
{
    let sep: u8 = sep.try_into().unwrap();

    // find separator in the other slice
    let other_seps: Vec<usize> = other
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(i, c)| if c == sep { Some(i) } else { None })
        .collect();
    let input_seps: Vec<usize> = input
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(i, c)| if c == sep { Some(i) } else { None })
        .collect();

    // now attempt choose a random sublice that is enclosed with the separator
    let (other_data, other_start) = if other_seps.is_empty() {
        // if there is no separator splice the whole other
        (other, 0)
    } else {
        // choose a random subslice separated by a separator
        let sep_idx = rng.gen_range(0..other_seps.len());
        let (from, to) = if sep_idx > 0 {
            if rng.gen_bool(0.7) {
                // with higher prob choose a "single line"
                (other_seps[sep_idx - 1] + 1, other_seps[sep_idx])
            } else {
                // with lower prob choose a subslice spanning "multiple lines"
                let start = other_seps[..sep_idx].choose(rng).unwrap().clone();
                (start, other_seps[sep_idx])
            }
        } else {
            (0, other_seps[sep_idx])
        };
        (&other[from..to], from)
    };

    if input_seps.is_empty() {
        input.clear();
        input.extend_from_slice(other_data);
        Some((0, other_start))
    } else {
        // choose a random subslice separated by a separator
        let sep_idx = rng.gen_range(0..input_seps.len());
        let (from, to) = if sep_idx > 0 {
            if rng.gen_bool(0.8) {
                // with higher prob choose a "single line"
                (input_seps[sep_idx - 1] + 1, input_seps[sep_idx])
            } else {
                // with lower prob choose a subslice spanning "multiple lines"
                let start = input_seps[..sep_idx].choose(rng).unwrap().clone();
                (start, input_seps[sep_idx])
            }
        } else {
            (0, input_seps[sep_idx])
        };

        // splice
        utils::vec::splice_into(input, from..to, other_data);

        Some((from, other_start))
    }
}

/// Insert data after a separator.
///
/// ```rust,ignore
/// let mut v = b"asdf; asdf";
/// insert_separated(v, ';', "XXXX", rng);
/// assert_eq!(v, b"asdf;XXXX asdf");
///
/// let mut v = b"var asdf = \"asdf\";";
/// insert_at_separator(v, '"', "XXXX", rng);
/// assert!(&v == b"var asdf = \"XXXXasdf\";" || &v == b"var asdf = \"asdf\"XXXX;");
/// ```
pub fn insert_after_separator<T>(
    input: &mut Vec<u8>,
    sep: T,
    other: &[u8],
    rng: &mut impl rand::Rng,
) -> Option<usize>
where
    T: TryInto<u8>,
    <T as TryInto<u8>>::Error: std::fmt::Debug,
{
    let sep: u8 = sep.try_into().unwrap();
    input.reserve(other.len() + 1);

    if input.is_empty() {
        input.push(sep);
        input.extend_from_slice(other);
        return Some(0);
    }

    // select a random occurence of the separator char or otherwise append.
    if let Some(index) = input
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(i, c)| if c == sep { Some(i) } else { None })
        .choose(rng)
    {
        // insert after the seperator
        utils::vec::fast_insert_at(input, index + 1, other);
        Some(index)
    } else {
        // or append separator + other at the end of the testcase
        let l = input.len();
        input.push(sep);
        input.extend_from_slice(other);
        Some(l)
    }
}

/// Insert data before a separator.
///
/// ```rust,ignore
/// let mut v = b"asdf; asdf";
/// insert_separated(v, ';', "XXXX", rng);
/// assert_eq!(v, b"asdfXXXX; asdf");
///
/// let mut v = b"var asdf = \"asdf\";";
/// insert_at_separator(v, '"', "XXXX", rng);
/// assert!(&v == b"var asdf = XXXX\"asdf\";" || &v == b"var asdf = \"asdfXXXX\";");
/// ```
pub fn insert_before_separator<T>(
    input: &mut Vec<u8>,
    sep: T,
    other: &[u8],
    rng: &mut impl rand::Rng,
) -> Option<usize>
where
    T: TryInto<u8>,
    <T as TryInto<u8>>::Error: std::fmt::Debug,
{
    let sep: u8 = sep.try_into().unwrap();
    input.reserve(other.len() + 1);

    if input.is_empty() {
        input.push(sep);
        input.extend_from_slice(other);
        return Some(0);
    }

    // select a random occurence of the separator char or otherwise append.
    if let Some(index) = input
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(i, c)| if c == sep { Some(i) } else { None })
        .choose(rng)
    {
        // insert after the seperator
        utils::vec::fast_insert_at(input, index, other);
        Some(index)
    } else {
        // or just append
        let l = input.len();
        input.extend_from_slice(other);
        input.push(sep);
        Some(l)
    }
}

/// Delete data between two separators
/// Returns range of deleted data.
///
/// ```rust,ignore
/// let mut v = b"asdf\nbsdf\n".to_vec();
/// delete_between_separator(&mut v, b'\n', rng);
/// assert!(v == b"asdf\n" || v == b"bsdf\n");
/// ```
#[inline]
pub fn delete_between_separator<T>(
    input: &mut Vec<u8>,
    sep: T,
    rng: &mut impl rand::Rng,
) -> Option<(usize, usize)>
where
    T: TryInto<u8>,
    <T as TryInto<u8>>::Error: std::fmt::Debug,
{
    let sep: u8 = sep.try_into().unwrap();
    if input.is_empty() {
        return None;
    }

    let sep_idx: Vec<usize> = input
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(i, c)| if c == sep { Some(i) } else { None })
        .collect();
    if sep_idx.is_empty() {
        return None;
    }
    let start = rng.gen_range(0_usize..sep_idx.len());
    let start_offset = sep_idx[start];
    let end_offset = if let Some(o) = sep_idx.get(start + 1) {
        *o
    } else {
        input.len()
    };

    input.splice(start_offset..end_offset, []);

    Some((start_offset, end_offset))
}

/// Duplicate data between two separators.
///
/// ```rust,ignore
/// let mut v = b"asdf\nbsdf\n".to_vec();
/// dup_between_separator(&mut v, b'\n', rng);
/// assert!(v == b"asdf\nasdf\nbsdf\n" || v == b"asdf\nbsdf\nbsdf\n");
/// ```
#[inline]
pub fn dup_between_separator<T>(
    input: &mut Vec<u8>,
    sep: T,
    rng: &mut impl rand::Rng,
) -> Option<(usize, usize)>
where
    T: TryInto<u8>,
    <T as TryInto<u8>>::Error: std::fmt::Debug,
{
    let sep: u8 = sep.try_into().unwrap();
    if input.is_empty() {
        return None;
    }

    let sep_idx: Vec<usize> = input
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(i, c)| if c == sep { Some(i) } else { None })
        .collect();
    if sep_idx.is_empty() {
        return None;
    }
    let start = rng.gen_range(0_usize..sep_idx.len());
    let start_offset = sep_idx[start];
    let end_offset = if let Some(o) = sep_idx.get(start + 1) {
        *o
    } else {
        input.push(sep);
        input.len()
    };

    // let src = &input[start_offset..end_offset];
    // input.splice(end_offset..end_offset, src.iter().copied());
    crate::utils::vec::insert_from_within(input, end_offset, start_offset..end_offset);

    Some((start_offset, end_offset))
}

/// Insert from dictionary at a given separator.
/// returns `(dict_index, offset_in_input)`.
pub fn insert_from_dictionary_at_const_separator<const C: char>(
    input: &mut Vec<u8>,
    rng: &mut impl rand::Rng,
    dictionary: Option<&Vec<Vec<u8>>>,
) -> Option<(usize, usize)> {
    if let Some(dictionary) = dictionary {
        if !dictionary.is_empty() {
            let sep: u8 = C.try_into().unwrap();
            // select another corpus item
            let dict_idx = rng.gen_range(0..dictionary.len());
            let other = &dictionary[dict_idx];

            let offset = insert_after_separator(input, sep, other, rng)?;

            return Some((dict_idx, offset));
        }
    }

    None
}
