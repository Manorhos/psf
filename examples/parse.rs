extern crate psf;

use psf::Psf;
use std::fs::File;
use std::io::Write;

fn main() {
    let psf = Psf::from_file(std::env::args().nth(1).unwrap()).unwrap();

    for (key, value) in psf.tags().iter() {
        println!("{}: {}", key, value);
    }

    let exe = psf.fancy_exe().unwrap();
    let mut out_file = File::create("lol.exe").unwrap();
    out_file.write_all(&exe).unwrap();

    println!("");

    println!("Checksum valid: {}", psf.is_checksum_valid());
}
