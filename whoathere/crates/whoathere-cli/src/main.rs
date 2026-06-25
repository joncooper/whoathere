use whoathere_cli::{evaluate_command, parse_command};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = evaluate_command(parse_command(&args));
    println!("{}", result.output);
    std::process::exit(result.exit_code);
}
