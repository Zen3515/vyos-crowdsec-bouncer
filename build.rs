use std::fs;
use std::path::Path;

fn main() {
    const VERSION_FILE: &str = "build/version.txt";

    println!("cargo:rerun-if-changed={VERSION_FILE}");

    let version = read_version_override(Path::new(VERSION_FILE))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").expect("missing package version"));

    println!("cargo:rustc-env=APP_VERSION={version}");
}

fn read_version_override(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;

    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
}
