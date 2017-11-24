extern crate pwquality;

use pwquality::PWQuality;

fn main() {
    let pwq = PWQuality::new();
    println!("{:?}", pwq.get_enforcing());
    pwq.set_enforcing(false);
    println!("{:?}", pwq.get_enforcing());
    println!("generated: {:?}", pwq.generate_password(1));
    println!("score: {:?}", pwq.check("fdsi40trrg=()/5423nfds".to_owned(), None, None));
}
