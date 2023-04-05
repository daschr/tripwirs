use std::env;
use std::path::{Path, PathBuf};

/*
    createconfig [plain conf] [conf out] <password from stdin>
    gen_db [conf in] [db out] <password from stdin>
    compare_db [db] <password from stdin>
*/

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [path]", args[0]);
        return Ok(());
    }

    let mut pathstack: Vec<PathBuf> = Vec::new();
    pathstack.push(PathBuf::from(&args[1]));

    while pathstack.len() != 0 {
        let e = pathstack.pop().unwrap();
        let path: &Path = e.as_path();

        if path.is_file() {
            println!("{:?}", &e);
            continue;
        }

        let it = match path.read_dir() {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut n_elems = 0;

        for i in it {
            n_elems += 1;
            if let Ok(e) = i {
                pathstack.push(e.path());
            }
        }

        if n_elems == 0 {
            println!("[dir] {:?}", &e);
        }
    }

    Ok(())
}
