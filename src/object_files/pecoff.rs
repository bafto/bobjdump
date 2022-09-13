use crate::binary_file::*;
use crate::object_files::*;

const PE_IMG_MN: u32 = 0x00004550;
// const DOS_MN: u16 = 0x5A4D;

pub struct PECOFFFile {
    pub is_img: bool,
    pub dos_header: Option<DosHeader>,
    pub pe_header: PeHeader,
    pub img_header: Option<ImgHeader>,
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

#[repr(u16)]
#[derive(Copy, Clone)]
pub enum ImgMagic {
    PE32 = 0x010b,
    PE32p = 0x020b,
    ROM = 0x107,
    INVALID = 0,
}

pub enum PESizeType {
    PE32(u32),
    PE32p(u64),
}

#[allow(non_snake_case)]
pub struct ImageDataDirectory {
    VirtualAddress: u32,
    Size: u32,
}

#[allow(non_snake_case)]
pub struct ImgHeader {
    MagicNumber: ImgMagic,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInizializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: Option<u32>, // only for PE32

    ImageBase: PESizeType,
    SectionAlignement: u32,
    FileAlignement: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: PESizeType,
    SizeOfStackCommit: PESizeType,
    SizeOfHeapReserve: PESizeType,
    SizeOfHeapCommit: PESizeType,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,

    DataDirectories: [Option<ImageDataDirectory>; 16],
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
PointerToSymbolTable:   {:#08X}
NumberOfSymbols:        {}
SizeOfOptionalHeader:   {:#08X}
Characteristics:        {:#08X}{}\
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

impl ImgMagic {
    pub fn to_string(&self) -> String {
        match *self {
            ImgMagic::PE32 => "PE32".to_string(),
            ImgMagic::PE32p => "PE32+".to_string(),
            ImgMagic::ROM => "ROM".to_string(),
            ImgMagic::INVALID => "Invalid".to_string(),
        }
    }
}

impl PESizeType {
    pub fn to_string(&self) -> String {
        match *self {
            PESizeType::PE32(s) => format!("{:#08X}", s),
            PESizeType::PE32p(s) => format!("{:#016X}", s),
        }
    }
}

impl ImgHeader {
    fn get_subsystem_string(&self) -> String {
        match self.Subsystem {
            0 => "Unknown".to_string(),
            1 => "Device drivers and native Windows processes".to_string(),
            2 => "The Windows graphical user interface (GUI) subsystem".to_string(),
            3 => "The Windows character subsystem".to_string(),
            5 => "The OS/2 character subsystem".to_string(),
            7 => "The Posix character subsystem".to_string(),
            8 => "Native Win9x driver".to_string(),
            9 => "Windows CE".to_string(),
            10 => "An Extensible Firmware Interface (EFI) application".to_string(),
            11 => "An EFI driver with boot services".to_string(),
            12 => "An EFI driver with run-time services".to_string(),
            13 => "An EFI ROM image".to_string(),
            14 => "XBOX".to_string(),
            16 => "Windows boot application".to_string(),
            _ => "unknown".to_string(),
        }
    }

    fn get_dllcharecteristics_string(&self) -> String {
        let mut result = String::new();
        for i in 0..16 {
            if (self.DllCharacteristics >> i) % 2 == 1 {
                result.push_str(match i {
                    5 => "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
                    6 => "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                    7 => "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
                    8 => "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
                    9 => "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
                    10 => "IMAGE_DLLCHARACTERISTICS_NO_SEH",
                    11 => "IMAGE_DLLCHARACTERISTICS_NO_BIND",
                    12 => "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
                    13 => "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
                    14 => "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
                    15 => "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
                    _ => "reserved",
                })
            }
        }
        result
            .strip_prefix(" | ")
            .unwrap_or(result.as_str())
            .to_string()
    }

    fn get_data_directoreis_string(&self) -> String {
        let mut result = String::new();
        for i in 0..self.NumberOfRvaAndSizes {
            result.push_str(format!("Entry {:#X}", i).as_str());
            result.push_str(
                if self.DataDirectories[i as usize].is_none() {
                    "invalid".to_string()
                } else {
                    let dir = self.DataDirectories[i as usize].as_ref().unwrap();
                    let addr = dir.VirtualAddress;
                    let size = dir.Size;
                    let name = match i {
                        0 => "Export Table",
                        1 => "Import Table",
                        2 => "Resource Table",
                        3 => "Exception Table",
                        4 => "Certificate Table",
                        5 => "Base Relocation Table",
                        6 => "Debug",
                        7 => "Architecture",
                        8 => "Global Ptr",
                        9 => "TLS Table",
                        10 => "Load Config Table",
                        11 => "Bound Import",
                        12 => "IAT",
                        13 => "Delay Import Descriptor",
                        14 => "CLR Runtime Header",
                        15 => "reserved",
                        _ => "invalid",
                    };
                    format!(" {:#016X} {:#08X} {}\n", addr, size, name)
                }
                .as_str(),
            )
        }
        result
    }

    pub fn to_string(&self) -> String {
        format!(
            "\
Magic                   {:#04X}    ({})

--- Standard fields ---

MajorLinkerVersion          {}
MinorLinkerVersion          {}
SizeOfCode                  {:#08X}
SizeOfInitializedData       {:#08X}
SizeOfUninitializedData     {:#08X}
AddressOfEntryPoint         {:#08X}
BaseOfCode                  {:#08X}
{}
--- Windows-specific fields ---

ImageBase                   {}
SectionAlignement           {:#08X}
FileAlignement              {:#08X}
MajorOperatingSystemVersion {}
MinorOperatingSystemVersion {}
MajorImageVersion           {}
MinorImageVersion           {}
MajorSubsystemVersion       {}
MinorSubsystemVersion       {}
Win32Version                {}
SizeOfImage                 {:#08X}
SizeOfHeaders               {:#08X}
CheckSum                    {:#08X}
Subsystem                   {:#08X}        {}
DllCharacteristics          {:#08X}{}
SizeOfStackReserve          {}
SizeOfStackCommit           {}
SizeOfHeapReserve           {}
SizeOfHeapCommit            {}
LoaderFlags                 {:#08X}
NumberOfRvaAndSizes         {}

--- Data directoreis ---
{}
",
            self.MagicNumber as u16,
            self.MagicNumber.to_string(),
            self.MajorLinkerVersion,
            self.MinorLinkerVersion,
            self.SizeOfCode,
            self.SizeOfInizializedData,
            self.SizeOfUninitializedData,
            self.AddressOfEntryPoint,
            self.BaseOfCode,
            match self.BaseOfData {
                Some(bod) => format!("BaseOfData                  {:08X}\n", bod),
                None => "".to_string(),
            },
            self.ImageBase.to_string(),
            self.SectionAlignement,
            self.FileAlignement,
            self.MajorOperatingSystemVersion,
            self.MinorOperatingSystemVersion,
            self.MajorImageVersion,
            self.MinorImageVersion,
            self.MajorSubsystemVersion,
            self.MinorSubsystemVersion,
            self.Win32VersionValue,
            self.SizeOfImage,
            self.SizeOfHeaders,
            self.CheckSum,
            self.Subsystem,
            self.get_subsystem_string(),
            self.DllCharacteristics,
            self.get_dllcharecteristics_string()
                .replace("\n", "\n                            "),
            self.SizeOfStackReserve.to_string(),
            self.SizeOfStackCommit.to_string(),
            self.SizeOfHeapReserve.to_string(),
            self.SizeOfHeapCommit.to_string(),
            self.LoaderFlags,
            self.NumberOfRvaAndSizes,
            self.get_data_directoreis_string(),
        )
    }
}

pub fn parse_pecoff_file(file: &mut BinaryFile) -> Result<ObjectFile, Error> {
    // assume image file
    file.move_fp_to(0x3C);
    let mut off = file.read_u32() as usize;

    if off > file.bytes.len() {
        // if the offset is invalid, prevent the crash
        off = 0
    }
    file.move_fp_to(off);
    let img = file.read_u32() == PE_IMG_MN; // check if it is an image file

    if !img {
        file.move_fp_to(0) // for non-image files, the header is at the file start, for image file we are already at the header position
    }

    // read PE header
    let pe_header = PeHeader {
        Machine: file.read_u16(),
        NumberOfSections: file.read_u16(),
        TimeDateStamp: file.read_u32(),
        PointerToSymbolTable: file.read_u32(),
        NumberOfSymbols: file.read_u32(),
        SizeOfOptionalHeader: file.read_u16(),
        Characteristics: file.read_u16(),
    };

    let img_header = if img {
        let magic_number = file.read_u16();
        let is_pe_32 = magic_number == ImgMagic::PE32 as u16;
        let read_pe_size = |file: &mut BinaryFile| {
            if is_pe_32 {
                PESizeType::PE32(file.read_u32())
            } else {
                PESizeType::PE32p(file.read_u64())
            }
        };

        let major_linker_version = file.read_u8();
        let minor_linker_version = file.read_u8();
        let size_of_code = file.read_u32();
        let size_of_initialized_data = file.read_u32();
        let size_of_uninitialized_data = file.read_u32();
        let address_of_entry_point = file.read_u32();
        let base_of_code = file.read_u32();
        let base_of_data = if is_pe_32 {
            Some(file.read_u32())
        } else {
            None
        };

        let image_base = read_pe_size(file);
        let section_alignement = file.read_u32();
        let file_alignement = file.read_u32();
        let major_operating_system_version = file.read_u16();
        let minor_operating_system_version = file.read_u16();
        let major_image_version = file.read_u16();
        let minor_image_version = file.read_u16();
        let major_subsystem_version = file.read_u16();
        let minor_subsystem_version = file.read_u16();
        let win32_version_value = file.read_u32();
        let size_of_image = file.read_u32();
        let size_of_headers = file.read_u32();
        let checksum = file.read_u32();
        let subsystem = file.read_u16();
        let dll_characteristics = file.read_u16();
        let size_of_stack_reserve = read_pe_size(file);
        let size_of_stack_commit = read_pe_size(file);
        let size_of_heap_reserve = read_pe_size(file);
        let size_of_heap_commit = read_pe_size(file);
        let loader_flags = file.read_u32();
        let number_of_rva_and_sizes = file.read_u32();

        let read_img_data_dir = |file: &mut BinaryFile| ImageDataDirectory {
            VirtualAddress: file.read_u32(),
            Size: file.read_u32(),
        };
        const INIT: Option<ImageDataDirectory> = None;
        let mut data_directories: [Option<ImageDataDirectory>; 16] = [INIT; 16];
        for i in 0..number_of_rva_and_sizes as usize {
            data_directories[i] = Some(read_img_data_dir(file));
        }

        Some(ImgHeader {
            MagicNumber: match magic_number {
                magic_number if magic_number == ImgMagic::PE32 as u16 => ImgMagic::PE32,
                magic_number if magic_number == ImgMagic::PE32p as u16 => ImgMagic::PE32p,
                magic_number if magic_number == ImgMagic::ROM as u16 => ImgMagic::ROM,
                _ => ImgMagic::INVALID,
            },
            MajorLinkerVersion: major_linker_version,
            MinorLinkerVersion: minor_linker_version,
            SizeOfCode: size_of_code,
            SizeOfInizializedData: size_of_initialized_data,
            SizeOfUninitializedData: size_of_uninitialized_data,
            AddressOfEntryPoint: address_of_entry_point,
            BaseOfCode: base_of_code,
            BaseOfData: base_of_data,
            ImageBase: image_base,
            SectionAlignement: section_alignement,
            FileAlignement: file_alignement,
            MajorOperatingSystemVersion: major_operating_system_version,
            MinorOperatingSystemVersion: minor_operating_system_version,
            MajorImageVersion: major_image_version,
            MinorImageVersion: minor_image_version,
            MajorSubsystemVersion: major_subsystem_version,
            MinorSubsystemVersion: minor_subsystem_version,
            Win32VersionValue: win32_version_value,
            SizeOfImage: size_of_image,
            SizeOfHeaders: size_of_headers,
            CheckSum: checksum,
            Subsystem: subsystem,
            DllCharacteristics: dll_characteristics,
            SizeOfStackReserve: size_of_stack_reserve,
            SizeOfStackCommit: size_of_stack_commit,
            SizeOfHeapReserve: size_of_heap_reserve,
            SizeOfHeapCommit: size_of_heap_commit,
            LoaderFlags: loader_flags,
            NumberOfRvaAndSizes: number_of_rva_and_sizes,
            DataDirectories: data_directories,
        })
    } else {
        None
    };

    Ok(ObjectFile::PECOFF(PECOFFFile {
        is_img: img,
        dos_header: Some(DosHeader {}),
        pe_header: pe_header,
        img_header: img_header,
    }))
}
