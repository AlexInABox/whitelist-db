use rusqlite::Connection;
use std::collections::HashSet;
use std::path::Path;

pub fn start() {
    let mut all_hashes: HashSet<String> = HashSet::with_capacity(400_000_000);

    extract_md5_hashes_from_db(Path::new("./RDS_2025.03.1_ios_minimal.db"), &mut all_hashes);

    println!(
        "Collected {} / {} hashes.",
        all_hashes.len(),
        all_hashes.capacity()
    )
}

fn extract_md5_hashes_from_db(filepath: &Path, hashset: &mut HashSet<String>) {
    if !is_valid_sqlite_db(filepath) {
        println!("Theres no valid SQLITE DATABASE at the location you provided...");
        return;
    }

    let conn = match Connection::open(filepath) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Could'nt open the DATABASE: {err}");
            return;
        }
    };

    let mut statement = match conn.prepare("SELECT COUNT(md5) FROM FILE;") {
        Ok(s) => s,
        Err(err) => {
            eprintln!("I couldnt prepare the sql query: {err}");
            return;
        }
    };

    let row_count = match statement.query_one([], |row| {
        let length: i64 = row.get(0)?;
        Ok(length)
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("I couldnt query your database. Fix your query!: {e}");
            return;
        }
    };

    println!("We have a row count of {row_count}");
    let mut statement = match conn.prepare("SELECT md5 FROM FILE") {
        Ok(s) => s,
        Err(err) => {
            eprintln!("Failed to prepare query: {err}");
            return;
        }
    };

    let mut rows = match statement.query([]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to query the database: {e}");
            return;
        }
    };

    let mut processed = 0;
    while let Ok(Some(row)) = rows.next() {
        let md5: String = match row.get(0) {
            Ok(val) => val,
            Err(e) => {
                eprintln!("Failed to get row: {e}");
                continue;
            }
        };
        hashset.insert(md5);
        processed += 1;

        if processed % (row_count / 100).max(1) == 0 {
            println!("Progress: {}%", processed * 100 / row_count);
        }
    }
}

fn is_valid_sqlite_db(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }

    if let Ok(conn) = Connection::open(path) {
        let result: rusqlite::Result<i32> = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table';",
            [],
            |row| row.get(0),
        );
        matches!(result, Ok(n) if n > 0)
    } else {
        false
    }
}
