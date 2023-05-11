mod tripwirs;

use tripwirs::*;

use std::env;

use std::io;

#[inline]
fn print_help(progname: &str) {
    eprintln!("Usage: {} [command] args...]", progname);
    eprintln!(
        r"    create_config [plain config input path] [config output path]
    generate_db [config input path] [db output path]
    compare_db [config input path] [db]"
    );
}

#[inline]
fn get_passphrase() -> String {
    let mut passphrase = String::new();

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

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "create_config" => {
            gen_config(&args[2], &args[3], &get_passphrase())?;
        }
        "generate_db" => {
            let p = get_passphrase();
            let conf: Config = get_config(&args[2], &p)?;
            gen_db(&conf, &args[3], &p)?;
        }
        "compare_db" => {
            let p = get_passphrase();
            let conf: Config = get_config(&args[2], &p)?;
            compare_db(&conf, &args[3], &p)?;
        }
        "show_db" => {
            let p = get_passphrase();
            print_db(&args[2], &p)?;
        }
        _ => {
            print_help(&args[0]);
            std::process::exit(1);
        }
    }

    Ok(())
}
