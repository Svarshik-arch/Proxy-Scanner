//! Консольная версия Proxy Scanner: `proxy-scanner-cli <команда> …` (см. `help`).

fn main() {
    std::process::exit(proxy_scanner::cli::main_from_env());
}
