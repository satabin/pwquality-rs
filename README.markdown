# pwquality

[pwquality](https://github.com/libpwquality/libpwquality/) binding for [rust](https://www.rust-lang.org/).

[Documentation](https://satabin.github.io/pwquality-rs/pwquality/)


## Usage

Add the dependency to your `Cargo.toml` file.

```toml
[dependencies]
pwquality = "0.1"
```

Then import it in your code.

```rust
extern crate pwquality;
```

For example:
```rust
use pwquality::PWQuality;

let pwq = PWQuality::new();

pwq.set_min_length(32);

let generated = pwq.generate_password(256);
```
