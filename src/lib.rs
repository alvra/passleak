//! This crate provides an interface to the database of breached passwords
//! provided by "Have I Been Pwned".
//!
//! Features:
//!   * Async using [`tokio`](https://tokio.rs/) and [`reqwest`].
//!   * Brotli compression for reduced data usage.
//!   * Password hash prefix leak prevention by padding responses.
//!   * Constant time base16 encoding and password suffix comparison
//!     to prevent any timing atacks.
//!
//! # Examples
//!
//! ```
//! # tokio_test::block_on(async {
//! use passleak::Api;
//!
//! let api = Api::new();
//!
//! // count the number of known breache
//! let breaches = api.count_breaches("secret").await.expect("api error");
//! assert!(breaches > 0);
//!
//! // only check if any breaches are known
//! let is_breached = api.is_breached("secret").await.expect("api error");
//! assert!(is_breached);
//! # })
//! ```

use sha1::{Digest, Sha1};
use bytes::Bytes;
use subtle::ConstantTimeEq;
use reqwest::Client;

/// these sizes are in base16 characters (ie. twice the size in bytes)
const HASH_SIZE: usize = 40;
const PREFIX_SIZE: usize = 5;
const SUFFIX_SIZE: usize = HASH_SIZE - PREFIX_SIZE;

/// the character in a range response that separates the suffix from the count
const LINE_SEPARATOR: u8 = b':';

/// The first 5 characters of a password hash.
///
/// Comparing values is **not** a constant-time operation.
///
/// This value is hashable and orderable so it can be used
/// in hashmaps and btrees as a caching key for lookups.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Prefix([u8; PREFIX_SIZE]);

/// The last 35 characters of a password hash.
///
/// Comparing values is a constant-time operation.
pub struct Suffix([u8; SUFFIX_SIZE]);

impl Prefix {
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap()
    }
}

impl std::cmp::PartialEq for Suffix {
    fn eq(&self, other: &Self) -> bool {
        <[u8] as ConstantTimeEq>::ct_eq(&self.0, &other.0).into()
    }
}

impl std::cmp::Eq for Suffix {}

/// Split an array into two arrays.
fn split_array<T, const LEN: usize, const LEN1: usize, const LEN2: usize>(
    array: [T; LEN]
) -> ([T; LEN1], [T; LEN2])
where
    T: Copy + Default,
{
    assert_eq!(LEN, LEN1 + LEN2);
    let mut part1 = [T::default(); LEN1];
    let mut part2 = [T::default(); LEN2];
    part1.copy_from_slice(&array[..LEN1]);
    part2.copy_from_slice(&array[LEN1..]);
    (part1, part2)
}

/// Hash a password into a prefix and suffix.
pub fn hash(password: &str) -> (Prefix, Suffix) {
    let mut chars = [0; HASH_SIZE];
    let hash = Sha1::digest(password.as_bytes());
    base16ct::upper::encode(&hash, &mut chars).unwrap();
    let (prefix, suffix) = split_array(chars);
    (Prefix(prefix), Suffix(suffix))
}

/// The API configuration.
pub struct Api {
    client: Client,
    add_padding: bool,
}

impl Api {
    /// Create a new instance.
    pub fn new() -> Self {
        Self::with_client(Client::new())
    }

    /// Create a new instance with a custom [`reqwest::Client`].
    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            add_padding: true,
        }
    }

    /// Set whether to enable padded responses.
    ///
    /// This is turned on (`true`) by default, which prevents leaking
    /// the password hash prefix through the response size
    /// by including a number of random hashes with zero breaches.
    ///
    /// Setting this to `false` reduces data usage.
    /// 
    /// **Reference:**
    /// <https://www.troyhunt.com/enhancing-pwned-passwords-privacy-with-padding/>
    pub fn add_padding(&mut self, add_padding: bool) {
        self.add_padding = add_padding
    }

    /// Create the API request for a password range.
    fn range_request(&self, prefix: Prefix) -> reqwest::RequestBuilder {
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix.as_str());
        let mut request = self.client.get(&url);
        if self.add_padding {
            request = request.header("Add-Padding", "true");
        }
        request
    }

    /// Get the API response for a password range.
    async fn range_response(&self, prefix: Prefix) -> reqwest::Result<reqwest::Response> {
        let request = self.range_request(prefix);
        let response = request.send().await?;
        Ok(response)
    }

    /// Get the API response body bytes for a password range.
    ///
    /// Use this method if you want to parse the response body yourself.
    pub async fn range_bytes(&self, prefix: Prefix) -> reqwest::Result<Bytes> {
        let response = self.range_response(prefix).await?;
        let body = response.bytes().await?;
        Ok(body)
    }

    /// Get the API response body text for a password range.
    ///
    /// Use this method if you want to parse the response body yourself.
    pub async fn range_text(&self, prefix: Prefix) -> reqwest::Result<String> {
        let response = self.range_response(prefix).await?;
        let body = response.text().await?;
        Ok(body)
    }

    /// Get the API response for a password range,
    /// and parse it into an iterator of password hash suffixes and
    /// corresponding breach counts.
    ///
    /// Lines that cannot be parsed yield `Err(Bytes)`.
    pub async fn range_raw(&self, prefix: Prefix) -> reqwest::Result<impl Iterator<Item=Result<(Suffix, u32), Bytes>>> {
        let body = self.range_bytes(prefix).await?;
        Ok(RangeIter::new(body))
    }

    /// Get the API response for a password range,
    /// and parse it into an iterator of password hash suffixes and
    /// corresponding breach counts.
    ///
    /// Lines that cannot be parsed are omitted.
    pub async fn range(&self, prefix: Prefix) -> reqwest::Result<impl Iterator<Item=(Suffix, u32)>> {
        let body = self.range_bytes(prefix).await?;
        Ok(RangeIter::new(body).filter_map(|result| result.ok()))
    }

    /// Count the number of known breaches for a password.
    ///
    /// This function ignores lines in the API response
    /// that cannot be parsed.
    pub async fn count_breaches(&self, password: &str) -> reqwest::Result<u32> {
        let (prefix, suffix) = hash(password);
        for (range_suffix, count) in self.range(prefix).await? {
            if suffix == range_suffix {
                return Ok(count)
            }
        }
        Ok(0)
    }

    /// Check if there exist known breaches for a password.
    ///
    /// This function ignores lines in the API response
    /// that cannot be parsed.
    pub async fn is_breached(&self, password: &str) -> reqwest::Result<bool> {
        let count = self.count_breaches(password).await?;
        Ok(count > 0)
    }
}

fn rstrip<'a>(bytes: &'a [u8], last: &[u8]) -> &'a [u8] {
    bytes.strip_suffix(last).unwrap_or(bytes)
}

fn parse_range_line(line: &[u8]) -> Option<(Suffix, u32)> {
    if line.get(SUFFIX_SIZE) == Some(&LINE_SEPARATOR) {
        let suffix = Suffix(line[..SUFFIX_SIZE].try_into().unwrap());
        let count = std::str::from_utf8(&line[(SUFFIX_SIZE + 1)..]).ok()?.parse().ok()?;
        Some((suffix, count))
    } else {
        None
    }
}

struct RangeIter {
    bytes: Bytes,
    index: usize,
}

impl RangeIter {
    fn new(bytes: Bytes) -> Self {
        Self { bytes, index: 0 }
    }
}

impl Iterator for RangeIter {
    type Item = Result<(Suffix, u32), Bytes>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.bytes.len() {
            let index = self.bytes.iter()
                .skip(self.index)
                .position(|byte| *byte == b'\n');
            if let Some(index) = index {
                let start = self.index;
                let end = self.index + index;
                let line = rstrip(&self.bytes[start..end], b"\r");
                self.index = end + 1;  // step beyond the newline
                let end = start + line.len();
                if let Some(item) = parse_range_line(line) {
                    return Some(Ok(item))
                } else {
                    return Some(Err(self.bytes.slice(start..end)))
                }
            } else {
                self.index = self.bytes.len();
                return None
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Bytes, hash, RangeIter};

    #[test]
    fn test_hash() {
        let (prefix, suffix) = hash("P@ssw0rd");
        assert_eq!(&prefix.0, b"21BD1");
        assert_eq!(&suffix.0, b"2DC183F740EE76F27B78EB39C8AD972A757");
    }

    #[test]
    fn test_parse() {
        let iter = RangeIter::new(Bytes::from_static(concat!(
            "2D6980B9098804E7A83DC5831BFBAF3927F:1\r\n",
            "2DEA2B1D02714099E4B7A874B4364D518F6:?\r\n",
            "2DC183F740EE76F27B78EB39C8AD972A757:52579\r\n",
            "xxx\r\n",
            "2DE4C0087846D223DBBCCF071614590F300:0\r\n",
        ).as_bytes()));
        let vec = iter
            .map(|result| result.map(|(suffix, count)| (
                std::str::from_utf8(&suffix.0).unwrap().to_string(),
                count,
            )))
            .collect::<Vec<_>>();
        assert_eq!(vec, vec![
            Ok(("2D6980B9098804E7A83DC5831BFBAF3927F".to_string(), 1)),
            Err(Bytes::from_static(b"2DEA2B1D02714099E4B7A874B4364D518F6:?")),
            Ok(("2DC183F740EE76F27B78EB39C8AD972A757".to_string(), 52579)),
            Err(Bytes::from_static(b"xxx")),
            Ok(("2DE4C0087846D223DBBCCF071614590F300".to_string(), 0)),
        ]);
    }
}