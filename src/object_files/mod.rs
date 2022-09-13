pub mod coff;
pub mod elf;
pub mod pecoff;

use coff::*;
use elf::*;
use pecoff::*;

use crate::binary_file::*;
use std::io::Error;

pub enum ObjectFile {
    ELF(ELFFile),
    COFF(COFFFile),
    PECOFF(PECOFFFile),
    NOTOBJ,
}

pub fn read_object_file(path: String) -> Result<ObjectFile, Error> {
    let mut bin_file = match BinaryFile::from_path(path) {
        Ok(f) => f,
        Err(err) => return Err(err),
    };

    let magic_number = bin_file.read_u32();
    match magic_number {
        ELF_MN => parse_elf_file(&mut bin_file),
        COFF_MN => parse_coff_file(&mut bin_file),
        _ => parse_pecoff_file(&mut bin_file),
    }
}
