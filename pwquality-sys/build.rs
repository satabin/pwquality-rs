extern crate pkg_config;

fn main() {

    pkg_config::Config::new().atleast_version("1.4.0").probe("pwquality").unwrap();

}
