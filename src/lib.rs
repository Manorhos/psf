extern crate nom;
#[macro_use]
extern crate quick_error;
extern crate crc;
extern crate flate2;
extern crate byteorder;
#[macro_use]
extern crate log;
extern crate chardetng;
extern crate encoding_rs;

use std::io::{Read, Write};
use std::fs::File;
use std::path::{PathBuf, Path};
use std::collections::HashMap;
use std::cmp::{min, max};

use nom::bytes::complete::{tag, take};
use nom::number::complete::le_u32;
use nom::{IResult, Finish};

use flate2::read::ZlibDecoder;
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

use chardetng::EncodingDetector;

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
        RecursionError {
            description("Maximum recursion depth exceeded")
        }
    }
}

fn is_whitespace(c: char) -> bool {
    c as u8 >= 1 && c as u8 <= 0x20
}

fn rawpsf(input: &[u8]) -> IResult<&[u8], Psf> {
    let (input, _) = tag(b"PSF")(input)?;

    // PS1 only at the moment
    let (input, _) = tag([0x01])(input)?;

    let (input, reserved_len) = le_u32(input)?;
    let (input, exe_len) = le_u32(input)?;
    let (input, exe_crc32) = le_u32(input)?;

    let (input, reserved) = take(reserved_len)(input)?;
    let (input, exe) = take(exe_len)(input)?;

    let psf = Psf {
        path: PathBuf::new(),
        exe_crc32: exe_crc32,
        _reserved_area: reserved.to_vec(),
        compressed_exe: exe.to_vec(),
        tags: HashMap::new(),
    };

    Ok((input, psf))
}

fn tag_header(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = tag("[TAG]")(input)?;

    Ok((input, ()))
}

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
// with b taking priority over a. Destination address and length in the header
// are adapted to the new, possibly larger EXE. PC and SP will carry over from "a".
// a_data and b_data must contain exactly all of the text data for that specific EXE.
fn merge_exes(a_data: &[u8], a_header: ExeHeader,
              b_data: &[u8], b_header: ExeHeader) -> (Vec<u8>, ExeHeader)
{
    let mut new_header = a_header;
    debug!("merging {:x?} and {:x?}", a_header, b_header);
    let new_dst = min(a_header.dst, b_header.dst);
    let new_text_end = max(a_header.dst + a_header.len, b_header.dst + b_header.len);
    let new_len = new_text_end - new_dst;
    let mut new_data = vec![0u8; new_len as usize];
    new_header.dst = new_dst;
    new_header.len = new_len;

    let a_start = a_header.dst as usize - new_dst as usize;
    (&mut new_data[a_start..]).write_all(&a_data[0..a_header.len as usize]).unwrap();

    let b_start = b_header.dst as usize - new_dst as usize;
    (&mut new_data[b_start..]).write_all(&b_data[0..b_header.len as usize]).unwrap();
    debug!("new header: {:x?}", new_header);
    (new_data, new_header)
}

pub struct Psf {
    path: PathBuf,
    exe_crc32: u32,
    _reserved_area: Vec<u8>,
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

        if let Ok((tags_bytes, mut psf)) = rawpsf(&file_contents).finish() {
            if let Ok((tags_bytes, _)) = tag_header(tags_bytes).finish() {
                // Check if the encoding is UTF-8 and if not, transcode to UTF-8.
                let tags_str_utf8 = {
                    let tmp_tags_str = String::from_utf8_lossy(tags_bytes);
                    let is_utf8 = tmp_tags_str.lines().any(|x| x.starts_with("utf8="));
                    if is_utf8 {
                        tmp_tags_str.to_string()
                    } else {
                        let mut detector = EncodingDetector::new();
                        detector.feed(&tags_bytes, true);
                        let encoding = detector.guess(None, true);

                        debug!("Detected encoding: {:?}", encoding);

                        if encoding == encoding_rs::UTF_8 {
                            tmp_tags_str.to_string()
                        } else {
                            let (cow, _, had_errors) = encoding.decode(&tags_bytes);
                            if had_errors {
                                warn!("Errors occurred during decoding.");
                            }
                            cow.to_string()
                        }
                    }
                };

                for line in tags_str_utf8.lines() {
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

    /// Returns `true` if the contained CRC32 checksum matches the one we calculate
    /// from the compressed EXE, `false` otherwise.
    pub fn is_checksum_valid(&self) -> bool {
        crc::crc32::checksum_ieee(&self.compressed_exe) == self.exe_crc32
    }

    /// Converts the PSF file into a ready-to-run PS-EXE, merging possibly
    /// referenced library PSFs together according to spec.
    ///
    /// # Note
    /// Unfortunately, very large EXEs (nearing the 2 MB mark) appear to fail to load
    /// using Caetla and the SYSTEM.CNF loading mechanism of the PSX BIOS. In my case
    /// they still worked in emulators or when burning them to disc as "PSX.EXE" though.
    pub fn fancy_exe(&self) -> Result<Vec<u8>, PsfError> {
        self.fancy_exe_inner(0)
    }

    /// Decompresses the raw PS-EXE contained in this single PSF file and returns
    /// it, untouched. Use `fancy_exe` if you want a PS-EXE ready to run in an emulator
    /// or on console.
    pub fn exe(&self) -> Vec<u8> {
        let mut decompress = ZlibDecoder::new(&self.compressed_exe[..]);
        let mut exe = Vec::new();
        decompress.read_to_end(&mut exe).unwrap();
        exe
    }

    fn fancy_exe_inner(&self, recursion_depth: u8) -> Result<Vec<u8>, PsfError> {
        if recursion_depth > 10 {
            return Err(PsfError::RecursionError);
        }

        let initial_exe = self.exe();
        let initial_exe_header = match ExeHeader::from_slice(&initial_exe) {
            Some(x) => x,
            None => return Err(PsfError::ExeMergeError),
        };
        let initial_exe_text = &initial_exe[0x800..0x800 + initial_exe_header.len as usize];

        let mut working_exe_header = initial_exe_header;
        let mut working_exe_text = initial_exe_text.to_vec();

        // Process "_lib" tag, use resulting EXE as new working EXE,
        // including its initial register values
        if let Some(psf_or_error) = self.open_lib(0) {
            let psf = psf_or_error?;
            let lib_exe = psf.fancy_exe_inner(recursion_depth + 1)?;
            let lib_exe_header = match ExeHeader::from_slice(&lib_exe) {
                Some(x) => x,
                None => return Err(PsfError::ExeMergeError),
            };
            let lib_exe_text = &lib_exe[0x800..0x800 + lib_exe_header.len as usize];

            // We want to use the PC and SP from the first _lib EXE we encounter,
            // so we have to avoid letting _lib EXEs from overriding the
            // PC and SP when recursing deeper.
            let (new_exe_text, new_exe_header) = if recursion_depth == 0 {
                merge_exes(lib_exe_text, lib_exe_header,
                           initial_exe_text, initial_exe_header)
            } else {
                merge_exes(initial_exe_text, initial_exe_header,
                           lib_exe_text, lib_exe_header)
            };
            working_exe_header = new_exe_header;
            working_exe_text = new_exe_text;
        }

        // Process "_libN" tags, preserving the old PC and SP.
        // Uh... up to "_lib9" is quite arbitrary, but we have to limit it to
        // something, right?
        for i in 2..10 {
            if let Some(psf_or_error) = self.open_lib(i) {
                let psf = psf_or_error?;
                let lib_exe = psf.fancy_exe_inner(recursion_depth + 1)?;
                let lib_exe_header = match ExeHeader::from_slice(&lib_exe) {
                    Some(x) => x,
                    None => return Err(PsfError::ExeMergeError),
                };
                let lib_exe_text = &lib_exe[0x800..0x800 + lib_exe_header.len as usize];
                let (new_exe_text, new_exe_header) = merge_exes(&working_exe_text, working_exe_header,
                        lib_exe_text, lib_exe_header);
                working_exe_header = new_exe_header;
                working_exe_text = new_exe_text;
            } else {
                break;
            }
        }

        // Build complete EXE from header and text
        let remainder = working_exe_header.len % 0x800;
        if remainder != 0 {
            working_exe_header.len += 0x800 - remainder;
        }
        let mut final_exe = vec![0; 0x800 + working_exe_header.len as usize];
        (&mut final_exe[0..0x800]).write_all(&initial_exe[0..0x800]).unwrap();
        (&mut final_exe[16..20]).write_u32::<LittleEndian>(working_exe_header.pc)?;
        (&mut final_exe[24..28]).write_u32::<LittleEndian>(working_exe_header.dst)?;
        (&mut final_exe[28..32]).write_u32::<LittleEndian>(working_exe_header.len)?;
        (&mut final_exe[48..52]).write_u32::<LittleEndian>(working_exe_header.sp)?;
        (&mut final_exe[0x800..]).write_all(&working_exe_text)?;
        Ok(final_exe)
    }

    /// Returns a reference to a [HashMap](std::collections::HashMap) mapping all tags contained in the PSF
    /// to their values.
    ///
    /// # Example
    /// If the PSF contains a `title` tag, you can extract the title using `psf.tags.get("title")`.
    pub fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }

    fn open_lib(&self, n: u8) -> Option<Result<Psf, PsfError>> {
        let tag = if n < 2 {
            "_lib".to_owned()
        } else {
            format!("_lib{}", n)
        };
        if let Some(next_file_name) = self.tags.get(&tag) {
            let mut path_to_file =
                if let Some(folder) = self.path.parent() {
                    folder.to_path_buf()
                } else {
                    PathBuf::new()
                };
            path_to_file.push(next_file_name);
            debug!("loading lib {} with path {:?}", n, path_to_file);
            Some(Psf::from_file(path_to_file))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO
}
