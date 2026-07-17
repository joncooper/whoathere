use std::path::{Path, PathBuf};
use whoathere_macos_vm::pack_npm_closure_frame_v1;

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere npm closure frame pack failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() < 4 {
        return Err(
            "usage: whoathere-npm-closure-frame-pack RECIPE OUTPUT ARTIFACT [ARTIFACT ...]".into(),
        );
    }
    let artifacts = arguments[3..].iter().map(PathBuf::from).collect::<Vec<_>>();
    let result = pack_npm_closure_frame_v1(
        Path::new(&arguments[1]),
        &artifacts,
        Path::new(&arguments[2]),
    )?;
    println!("{}", String::from_utf8(result.canonical_json_v1()?)?);
    Ok(())
}
