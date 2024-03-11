use proxy_reencryption_lib::pg;

use aes::cipher::generic_array::{typenum::U16, GenericArray};

use std::fs::File;
use std::io::{self, prelude::*, BufReader};
fn main() -> io::Result<()> {
    println!("{:?}", pg(10, GenericArray::from([31u8; 16])));

    // let file = File::open("foo.txt")?;
    // let reader = BufReader::new(file);

    // for line in reader.lines() {
    //     println!("{}", line?);
    // }

    Ok(())
}
