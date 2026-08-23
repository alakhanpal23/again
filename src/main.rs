fn main() {
    match again::run_cli() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("again: {error:#}");
            std::process::exit(1);
        }
    }
}
