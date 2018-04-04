#[macro_use]
extern crate nom;
#[macro_use]
extern crate quick_error;
extern crate crc;
extern crate flate2;
extern crate byteorder;

use std::io::{Read, Write};
use std::fs::File;
use std::path::{PathBuf, Path};
use std::collections::HashMap;
use std::cmp::{min, max};

use nom::*;
use nom::IResult::Done;

use flate2::read::{ZlibDecoder};
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

quick_error! {
    #[derive(Debug)]
    pub enum PsfError {
        Io(err: std::io::Error) {
            cause(err)
            description(err.description())
            display("I/O error: {}", err)
            from()
        }
        Utf8(err: std::str::Utf8Error) {
            cause(err)
            description(err.description())
            display("UTF8 error: {}", err)
            from()
        }
        ParseError {
            description("General PSF parse error")
        }
        ExeMergeError {
            description("Cannot merge EXEs")
        }
    }
}

fn is_whitespace(c: char) -> bool {
    c as u8 >= 1 && c as u8 <= 0x20
}

named!(rawpsf <&[u8], Psf>,
    do_parse!(
        tag!(b"PSF") >>
        tag!([0x01]) >> // PS1 only at the moment
        reserved_len: le_u32 >>
        exe_len: le_u32 >>
        exe_crc32: le_u32 >>
        reserved: take!(reserved_len) >>
        exe: take!(exe_len) >>
        (
            Psf {
                path: PathBuf::new(),
                exe_crc32: exe_crc32,
                reserved_area: exe.to_vec(),
                compressed_exe: exe.to_vec(),
                tags: HashMap::new(),
            }
        )
    )
);

named!(tag_header, tag!("[TAG]"));

#[derive(Copy, Clone, Debug)]
struct ExeHeader {
    pc: u32,
    _gp: u32,
    dst: u32,
    len: u32, // Length of text+data section
    _bss_start: u32,
    _bss_len: u32,
    sp: u32,
}

impl ExeHeader {
    fn from_slice(data: &[u8]) -> Option<ExeHeader> {
        // TODO: Check header validity?
        if data.len() < 0x800 {
            return None;
        }
        let pc = LittleEndian::read_u32(&data[16..20]);
        let _gp = LittleEndian::read_u32(&data[20..24]);
        let dst = LittleEndian::read_u32(&data[24..28]);
        let len = LittleEndian::read_u32(&data[28..32]);
        let bss_start = LittleEndian::read_u32(&data[40..44]);
        let bss_len = LittleEndian::read_u32(&data[44..48]);
        let sp = LittleEndian::read_u32(&data[48..52]);
        Some( ExeHeader {
            pc: pc,
            _gp: _gp,
            dst: dst,
            len: len,
            _bss_start: bss_start,
            _bss_len: bss_len,
            sp: sp,
        })
    }


}

// "Superimposes" b upon a, thus merges the text sections of both into one,
// with b taking priority over a and using b's initial register values.
// a_data and b_data must contain exactly all of the text data for that specific EXE.
fn merge_exes(a_data: &[u8], a_header: ExeHeader, b_data: &[u8], b_header: ExeHeader) -> (Vec<u8>, ExeHeader) {
    let mut new_header = a_header;
    let new_dst = min(a_header.dst, b_header.dst);
    let new_text_end = max(a_header.dst + a_header.len, b_header.dst + b_header.len);
    let new_len = new_text_end - new_dst;
    let mut new_data = vec![0u8; new_len as usize];
    new_header.len = new_len;

    let a_start = a_header.dst as usize - new_dst as usize;
    (&mut new_data[a_start..]).write_all(&a_data[0..a_header.len as usize]).unwrap();

    let b_start = b_header.dst as usize - new_dst as usize;
    (&mut new_data[b_start..]).write_all(&b_data[0..b_header.len as usize]).unwrap();
    (new_data, new_header)
}

pub struct Psf {
    path: PathBuf,
    exe_crc32: u32,
    reserved_area: Vec<u8>,
    compressed_exe: Vec<u8>,
    tags: HashMap<String, String>,
}

impl Psf {
    pub fn from_file<P>(path: P) -> Result<Psf, PsfError>
        where P: AsRef<Path>
    {
        let path_buf = path.as_ref().to_path_buf();
        let mut file = File::open(&path_buf)?; 
        let mut file_contents = Vec::new();
        file.read_to_end(&mut file_contents)?;

        if let Done(tags_bytes, mut psf) = rawpsf(&file_contents) {
            if let Done(tags_bytes, _) = tag_header(tags_bytes) {
                let tags_str = std::str::from_utf8(tags_bytes)?;
                for line in tags_str.lines() {
                    let split_pos;
                    if let Some(pos) = line.find('=') {
                        split_pos = pos;
                    } else {
                        continue;
                    }
                    let (variable, value) = line.split_at(split_pos);
                    let value = &value[1..];

                    let variable = variable.trim_matches(is_whitespace);
                    let value = value.trim_matches(is_whitespace);

                    let entry = psf.tags.entry(variable.to_owned()).or_insert(String::new());

                    // TODO: Dunno how the lines of the multi-line comments should be concatenated,
                    // so we'll just use spaces for now.
                    if !entry.is_empty() {
                        entry.push_str(" ");
                    }
                    entry.push_str(value);
                }
            }
            psf.path = path_buf;
            Ok(psf)
        } else {
            Err(PsfError::ParseError)
        }
    }

    pub fn exe(&self) -> Vec<u8> {
        let mut decompress = ZlibDecoder::new(&self.compressed_exe[..]);
        let mut exe = Vec::new();
        decompress.read_to_end(&mut exe).unwrap();
        exe
    }

    pub fn fancy_exe(&self) -> Result<Vec<u8>, PsfError> {
        // TODO: Do a buncha shit
        let initial_exe = self.exe();
        let initial_exe_header = ExeHeader::from_slice(&initial_exe);
        if initial_exe_header.is_none() {
            return Err(PsfError::ExeMergeError);
        }
        let initial_exe_header = initial_exe_header.unwrap();
        let initial_exe_text = &initial_exe[0x800..0x800 + initial_exe_header.len as usize];

        //println!("Initial EXE: dst {:x}, len {:x}, sp {:x}", initial_exe_header.dst, initial_exe_header.len, initial_exe_header.sp);

        let mut working_exe_header = initial_exe_header;
        let mut working_exe_text = initial_exe_text.to_vec();

        // TODO: Support _libN tags and recursion
        if let Some(psf_or_error) = self.next_psf() {
            let psf = psf_or_error?;
            let lib_exe = psf.exe();
            let lib_exe_header = ExeHeader::from_slice(&lib_exe);
            if lib_exe_header.is_none() {
                return Err(PsfError::ExeMergeError);
            }
            let lib_exe_header = lib_exe_header.unwrap();
            //println!("Lib EXE: dst {:x}, len {:x}, sp {:x}", lib_exe_header.dst, lib_exe_header.len, lib_exe_header.sp);
            let lib_exe_text = &lib_exe[0x800..0x800 + lib_exe_header.len as usize];
            let new_exe = merge_exes(lib_exe_text, lib_exe_header,
                                     initial_exe_text, initial_exe_header);
            working_exe_header = new_exe.1;
            working_exe_text = new_exe.0;
        }

        // Build complete EXE from header and text
        let mut final_exe = vec![0; 0x800 + working_exe_header.len as usize];
        (&mut final_exe[0..0x800]).write_all(&initial_exe[0..0x800]).unwrap();
        (&mut final_exe[16..20]).write_u32::<LittleEndian>(working_exe_header.pc).unwrap();
        (&mut final_exe[24..28]).write_u32::<LittleEndian>(working_exe_header.dst).unwrap();
        (&mut final_exe[28..32]).write_u32::<LittleEndian>(working_exe_header.len).unwrap();
        (&mut final_exe[48..52]).write_u32::<LittleEndian>(working_exe_header.sp).unwrap();
        (&mut final_exe[0x800..]).write_all(&working_exe_text);
        Ok(final_exe)
    }

    pub fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }

    pub fn is_checksum_valid(&self) -> bool {
        crc::crc32::checksum_ieee(&self.compressed_exe) == self.exe_crc32
    }

    pub fn next_psf(&self) -> Option<Result<Psf, PsfError>> {
        if let Some(next_file_name) = self.tags.get("_lib") {
            let mut path_to_file = 
                if let Some(folder) = self.path.parent() {
                    folder.to_path_buf()
                } else {
                    PathBuf::new()
                };
            path_to_file.push(next_file_name);
            Some(Psf::from_file(path_to_file))
        } else {
            None
        }
    }

    pub fn get_reserved_area(&self) -> &[u8] {
        &self.reserved_area
    }
}

#[cfg(test)]
mod tests {
    // TODO
}