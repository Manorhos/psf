extern crate log;
extern crate env_logger;

extern crate psf;

use log::LevelFilter;

use psf::Psf;

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::Write;

fn main() {
    env_logger::builder()
        .default_format_timestamp(false)
        .filter_level(LevelFilter::Debug)
        .init();

    if std::env::args().len() != 2 {
        println!("PSF to PS-EXE Converter");
        let exe_path =
            std::env::current_exe()
                .ok()
                .as_ref()
                .map(Path::new)
                .and_then(Path::file_name)
                .and_then(OsStr::to_str)
                .map(String::from)
                .unwrap_or("<Path to this program>".to_owned());
        println!("Usage: {} <Path to PSF>", exe_path);
        std::process::exit(1);
    }

    let psf_path_string = std::env::args().nth(1).unwrap();
    let psf_path = Path::new(&psf_path_string);
    let psf = Psf::from_file(psf_path).unwrap();

    println!("Tags:");
    for (key, value) in psf.tags().iter() {
        println!("{}: {}", key, value);
    }

    let exe = psf.fancy_exe().unwrap();
    let out_path = if let Some(stem) = psf_path.file_stem() {
        let mut pb = PathBuf::from(stem);
        pb.set_extension("exe");
        pb
    } else {
        PathBuf::from("psf.exe")
    };
    println!("{:?}", out_path);
    let mut out_file = File::create(out_path).unwrap();
    out_file.write_all(&exe).unwrap();

    println!("");

    println!("Checksum valid: {}", psf.is_checksum_valid());
}
