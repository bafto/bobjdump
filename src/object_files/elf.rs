use crate::binary_file::*;
use crate::object_files::*;

pub const ELF_MN: u32 = 0x7f454C46;

pub struct ELFFile {}

pub fn parse_elf_file(_file: &mut BinaryFile) -> Result<ObjectFile, Error> {
    Ok(ObjectFile::ELF(ELFFile {}))
}
