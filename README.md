# PassLeak

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Interface to the database of breached passwords
provided by "Have I Been Pwned".

## Features

  * Async using tokio and reqwest.
  * Brotli compression for reduced data usage.
  * Password hash prefix leak prevention by padding responses.
  * Constant time base16 encoding and password suffix comparison
    to prevent any timing atacks.

## Example

```rust
use passleak::Api;

let api = Api::new();

// count the number of known breache
let breaches = api.count_breaches("secret").await.expect("api error");
assert!(breaches > 0);

// only check if any breaches are known
let is_breached = api.is_breached("secret").await.expect("api error");
assert!(is_breached);
```

## Documentation

[Documentation](https://lib.rs/crates/passleak)

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
