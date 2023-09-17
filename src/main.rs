mod config;
mod crypto;
mod tripwirs;

use config::{gen_config, get_config, Config};
use tripwirs::*;

use std::env;
use std::process::exit;

use std::io::{self, Write};

#[inline]
fn print_help(progname: &str) {
    eprintln!("Usage: {} [command] [args...]\n", progname);
    eprintln!(
        "\tcreate_config [plain config input path] [config output path]
\tgenerate_db [config input path] [db output path]
\tcompare_db [config input path] [db]"
    );
}

#[inline]
fn get_passphrase() -> String {
    let mut passphrase = String::new();
    print!("Passphrase: ");
    io::stdout().flush().ok();

    match io::stdin().read_line(&mut passphrase) {
        Ok(_) => {
            match passphrase.pop() {
                Some('\n') => (),
                Some(c) => passphrase.push(c),
                None => (),
            }

            passphrase
        }
        Err(_) => std::process::exit(1),
    }
}

fn blame<T, E: std::fmt::Debug>(r: Result<T, E>, s: &str) -> T {
    match r {
        Err(e) => {
            eprintln!("{}: {:?}", s, e);
            exit(1);
        }
        Ok(v) => v,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help(&args[0]);
        return;
    }

    match args[1].as_str() {
        "create_config" => {
            blame(
                gen_config(&args[2], &args[3], &get_passphrase()),
                "Could not generate config",
            );
        }
        "generate_db" => {
            let p = get_passphrase();
            let conf: Config = blame(get_config(&args[2], &p), "Could not get config");
            blame(gen_db(&conf, &args[3], &p), "Could not create database");
        }
        "compare_db" => {
            let p = get_passphrase();
            let conf: Config = blame(get_config(&args[2], &p), "Could not get config");
            blame(
                compare_db(&conf, &args[3], &p),
                "Could not compare database",
            );
        }
        "show_db" => {
            let p = get_passphrase();
            blame(print_db(&args[2], &p), "Could not show database");
        }
        _ => {
            print_help(&args[0]);
            exit(1);
        }
    }
}
