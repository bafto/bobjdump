use crate::binary_file::*;
use std::io::Error;

pub enum ObjectFile {
    ELF(ELFFile),
    COFF(COFFFile),
    PECOFF(PECOFFFile),
    NOTOBJ,
}

const ELF_MN: u32 = 0x7f454C46;
const COFF_MN: u32 = 0x14c;
// const DOS_MN: u16 = 0x5A4D;
const PE_IMG_MN: u32 = 0x00004550;

pub struct ELFFile {}

pub struct COFFFile {}

pub struct PECOFFFile {
    pub is_img: bool,
    pub dos_header: Option<DosHeader>,
    pub pe_header: PeHeader,
}

pub struct DosHeader {}

#[allow(non_snake_case)]
pub struct PeHeader {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

impl PeHeader {
    fn get_machine_string(&self) -> &str {
        match self.Machine {
            0x0 => "IMAGE_FILE_MACHINE_UNKNOWN",
            0x1d3 => "IMAGE_FILE_MACHINE_AM33",
            0x8664 => "IMAGE_FILE_MACHINE_AMD64",
            0x1c0 => "IMAGE_FILE_MACHINE_ARM",
            0xaa64 => "IMAGE_FILE_MACHINE_ARM64",
            0x1c4 => "IMAGE_FILE_MACHINE_ARMNT",
            0xebc => "IMAGE_FILE_MACHINE_EBC",
            0x14c => "IMAGE_FILE_MACHINE_I386",
            0x200 => "IMAGE_FILE_MACHINE_IA64",
            0x6232 => "IMAGE_FILE_MACHINE_LOONGARCH32",
            0x6264 => " IMAGE_FILE_MACHINE_LOONGARCH64",
            0x9041 => " IMAGE_FILE_MACHINE_M32R",
            0x266 => " IMAGE_FILE_MACHINE_MIPS16",
            0x366 => " IMAGE_FILE_MACHINE_MIPSFPU",
            0x466 => " IMAGE_FILE_MACHINE_MIPSFPU16",
            0x1f0 => " IMAGE_FILE_MACHINE_POWERPC",
            0x1f1 => " IMAGE_FILE_MACHINE_POWERPCFP",
            0x166 => " IMAGE_FILE_MACHINE_R4000",
            0x5032 => "IMAGE_FILE_MACHINE_RISCV32",
            0x5064 => "IMAGE_FILE_MACHINE_RISCV64",
            0x5128 => "IMAGE_FILE_MACHINE_RISCV128",
            0x1a2 => "IMAGE_FILE_MACHINE_SH3",
            0x1a3 => "IMAGE_FILE_MACHINE_SH3DSP",
            0x1a6 => "IMAGE_FILE_MACHINE_SH4",
            0x1a8 => "IMAGE_FILE_MACHINE_SH5",
            0x1c2 => "IMAGE_FILE_MACHINE_THUMB",
            0x169 => "IMAGE_FILE_MACHINE_WCEMIPSV2",
            _ => "Invalid Machine",
        }
    }

    fn get_characteristics_string(&self) -> String {
        let mut result = String::new();
        for i in 0..16 {
            if (self.Characteristics >> i) % 2 == 1 {
                result.push_str(match i {
                    0 => "\nIMAGE_FILE_RELOCS_STRIPPED",
                    1 => "\nIMAGE_FILE_EXECUTABLE_IMAGE",
                    2 => "\nIMAGE_FILE_LINE_NUMS_STRIPPED",
                    3 => "\nIMAGE_FILE_LOCAL_SYMS_STRIPPED",
                    4 => "\nIMAGE_FILE_AGGRESSIVE_WS_TRIM",
                    5 => "\nIMAGE_FILE_LARGE_ADDRESS_AWARE",
                    6 => "\nreserved for future use",
                    7 => "\nIMAGE_FILE_BYTES_REVERSED_LO",
                    8 => "\nIMAGE_FILE_32BIT_MACHINE",
                    9 => "\nIMAGE_FILE_DEBUG_STRIPPED",
                    10 => "\nIMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP",
                    11 => "\nIMAGE_FILE_NET_RUN_FROM_SWAP",
                    12 => "\nIMAGE_FILE_SYSTEM",
                    13 => "\nIMAGE_FILE_DLL",
                    14 => "\nIMAGE_FILE_UP_SYSTEM_ONLY",
                    15 => "\nIMAGE_FILE_BYTES_REVERSED_HI",
                    _ => "unknown",
                })
            }
        }
        result
            .strip_prefix(" | ")
            .unwrap_or(result.as_str())
            .to_string()
    }

    pub fn to_string(&self) -> String {
        format!(
            "\
Machine:                {}
NumberOfSections:       {}
TimeDateStamp:          {}
PointerToSymbolTable:   {:#X}
NumberOfSymbols:        {}
SizeOfOptionalHeader:   {:#X}
Characteristics:        {:#X}{}\
		",
            self.get_machine_string(),
            self.NumberOfSections,
            chrono::NaiveDateTime::from_timestamp(self.TimeDateStamp.into(), 0).to_string(),
            self.PointerToSymbolTable,
            self.NumberOfSymbols,
            self.SizeOfOptionalHeader,
            self.Characteristics,
            self.get_characteristics_string()
                .replace("\n", "\n                        ")
        )
    }
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

fn parse_elf_file(_file: &mut BinaryFile) -> Result<ObjectFile, Error> {
    Ok(ObjectFile::ELF(ELFFile {}))
}

fn parse_coff_file(_file: &mut BinaryFile) -> Result<ObjectFile, Error> {
    Ok(ObjectFile::COFF(COFFFile {}))
}

fn parse_pecoff_file(file: &mut BinaryFile) -> Result<ObjectFile, Error> {
    // check microsoft PE
    // assume image file
    file.move_fp_to(0x3C);
    let mut off = file.read_u32() as usize;
    if off > file.bytes.len() {
        off = 0
    }
    file.move_fp_to(off);
    let img = file.read_u32() == PE_IMG_MN;

    if !img {
        file.move_fp_to(0)
    }

    // read PE header
    let header = PeHeader {
        Machine: file.read_u16(),
        NumberOfSections: file.read_u16(),
        TimeDateStamp: file.read_u32(),
        PointerToSymbolTable: file.read_u32(),
        NumberOfSymbols: file.read_u32(),
        SizeOfOptionalHeader: file.read_u16(),
        Characteristics: file.read_u16(),
    };

    Ok(ObjectFile::PECOFF(PECOFFFile {
        is_img: img,
        dos_header: Some(DosHeader {}),
        pe_header: header,
    }))
}
