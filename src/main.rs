mod tripwirs;

use tripwirs::*;

use std::env;

#[inline]
fn print_help(progname: &str) {
    eprintln!("Usage: {} [command] args...]", progname);
    eprintln!(
        r"    create_config [plain config input path] [config output path]
    generate_db [config input path] [db output path]
    compare_db [config input path] [db]
    "
    );
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "create_config" => {
            gen_config(&args[2], &args[3], "test")?;
        }
        "generate_db" => {
            let conf: Config = get_config(&args[2], "test")?;
            gen_db(&conf, &args[3])?;
        }
        "compare_db" => {
            let conf: Config = get_config(&args[2], "test")?;
            compare_db(&conf, &args[3])?;
        }
        _ => {
            print_help(&args[0]);
            std::process::exit(1);
        }
    }

    Ok(())
}
