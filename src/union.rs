use std::{path::Path};

use rusqlite::{Connection};

pub fn start() {
    println!("Hello from union.rs!");

    let hashes: Vec<String> = extract_from_dbfile(Path::new("./mydatabase.db"));
    for hash in hashes{
        println!("pretty hash: {hash}");
    }
}

fn extract_from_dbfile(filepath: &Path) -> Vec<String>{
    let mut found_hashes: Vec<String> = vec![];

    if !is_valid_sqlite_db(filepath){
        println!("I dont feel so good...");
        return found_hashes;
    }

    let conn = match Connection::open(filepath) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("I don't feel so good...");
            return found_hashes;
        }
    };

    let mut statement = match conn.prepare("SELECT md5 FROM star") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("I feel terrible");
            return found_hashes;
        }
    };


    let result = match statement.query_map([], |row| {
        let md5: String = row.get(0)?;
        Ok(md5)
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("I feel terrible: {}", e);
            return found_hashes;
        }
    };

    println!("I queried the database and got:");
    for row in result {
        match row {
            Ok(md5) => {
                found_hashes.push(md5);
            },
            Err(e) => eprintln!("Row error: {}", e),            
        }
    }
    





    println!("I love america!!");
    



    return found_hashes;
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
