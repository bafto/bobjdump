use crate::binary_file::*;
use crate::object_files::*;

pub const COFF_MN: u32 = 0x14c;

pub struct COFFFile {}

pub fn parse_coff_file(_file: &mut BinaryFile) -> Result<ObjectFile, Error> {
    Ok(ObjectFile::COFF(COFFFile {}))
}
