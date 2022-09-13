pub mod binary_file;
pub mod object_files;

use crate::object_files::*;

use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long)]
    file_format: bool,
    #[clap(short, long)]
    header: bool,

    file: Option<String>,
}

// checks that all required arguments are present
// and exits if not
fn validate_cli(cli: &Cli) {
    if cli.file.is_none() {
        exit_with_err("no input file".to_owned());
    }
}

fn exit_with_err(error: String) -> ! {
    println!("{error}");
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();
    validate_cli(&cli);

    let obj_file = match read_object_file(cli.file.unwrap()) {
        Ok(f) => f,
        Err(error) => exit_with_err(error.to_string()),
    };
    if matches!(obj_file, ObjectFile::NOTOBJ) {
        println!("Not an object file");
        return;
    }

    if cli.file_format {
        println!(
            "{}",
            match &obj_file {
                ObjectFile::ELF(_) => "ELF file",
                ObjectFile::COFF(_) => "COFF file",
                ObjectFile::PECOFF(obj) =>
                    if obj.is_img {
                        "PE/COFF image file"
                    } else {
                        "PE/COFF object file"
                    },
                ObjectFile::NOTOBJ => "",
            }
        )
    }
    if cli.header {
        println!(
            "{}",
            match &obj_file {
                ObjectFile::ELF(_) => "no header available".to_string(),
                ObjectFile::COFF(_) => "no header available".to_string(),
                ObjectFile::PECOFF(obj) => obj.pe_header.to_string(),
                ObjectFile::NOTOBJ => "".to_string(),
            }
        );
        println!(
            "{}",
            match &obj_file {
                ObjectFile::ELF(_) => "".to_string(),
                ObjectFile::COFF(_) => "".to_string(),
                ObjectFile::PECOFF(obj) => match &obj.img_header {
                    Some(header) => header.to_string(),
                    None => "".to_string(),
                },
                ObjectFile::NOTOBJ => "".to_string(),
            }
        )
    }
}
