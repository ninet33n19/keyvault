use rusqlite::Connection;
use std::fs;
use tauri::{AppHandle, Manager};

// This is the function that will set up our database
pub fn init_database(app_handle: &AppHandle) -> Result<Connection, rusqlite::Error> {
    // Get the path to the app's data directory
    let app_dir = app_handle
        .path()
        .app_data_dir()
        .expect("The app data directory should exist.");

    // Create the directory if it doesn't exist
    fs::create_dir_all(&app_dir).expect("The app data directory should be created.");

    // Define the database path
    let db_path = app_dir.join("keyvault.db");

    // Open a connection to the database file
    let conn = Connection::open(db_path)?;

    // SQL to create our 'credentials' table
    let sql = "
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            provider_name TEXT NOT NULL,
            notes TEXT,
            status TEXT NOT NULL,
            encrypted_key BLOB NOT NULL,
            encrypted_secret BLOB,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
        )
    ";

    // Execute the SQL command
    conn.execute(sql, [])?;

    Ok(conn)
}
