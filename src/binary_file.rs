use byteorder::{ByteOrder, LittleEndian};

pub struct BinaryFile {
    pub bytes: Vec<u8>,
    pub index: usize,
}

impl BinaryFile {
    pub fn from_path(path: String) -> Result<BinaryFile, std::io::Error> {
        use std::fs;
        let file = match fs::read(path) {
            Ok(vec) => vec,
            Err(error) => return Err(error),
        };
        Ok(BinaryFile {
            bytes: file,
            index: 0,
        })
    }

    pub fn move_fp_by(&mut self, offset: usize) {
        self.index += offset;
        if self.index >= self.bytes.len() {
            panic!("Index {} out of Range in BinaryFile", self.index);
        }
    }
    pub fn move_fp_to(&mut self, addr: usize) {
        self.index = addr;
        if self.index >= self.bytes.len() {
            panic!("Index {} out of Range in BinaryFile", self.index);
        }
    }

    pub fn read_bytes(&mut self, n: usize) -> Vec<u8> {
        self.index += n;
        if self.index >= self.bytes.len() {
            panic!("Index {} out of Range in BinaryFile", self.index);
        }
        self.bytes[self.index - n..self.index].to_vec()
    }

    pub fn read_u16(&mut self) -> u16 {
        LittleEndian::read_u16(self.read_bytes(2).as_slice())
    }
    pub fn read_u32(&mut self) -> u32 {
        LittleEndian::read_u32(self.read_bytes(4).as_slice())
    }
}
