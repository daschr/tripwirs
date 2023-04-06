use std::path::Path;

enum Level<T> {
    File(T),
    Dir(Vec<Level<T>>),
}

struct FSIterator {
    rootpath: Path,
    dirstack: Level<Path>,
}

impl FSIterator {
    fn next_level(path: Path) -> Level<Path> {
        if path.isfile() {
            return File(path);
        }

        Dir(path.readdir().unwrap().collect())
    }

    fn new(path: Path) -> Self {
        FSIterator {
            path,
            dirstack: Self::next_level(path),
        }
    }
}

impl Iterator for FSIterator {
    type Item = Path;

    fn next(&mut self) -> Item {}
}
