mod command;
mod database;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            database::init_database(&app.handle()).expect("Database initialization failed");
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            command::add_credential,
            command::search_credentials,
            command::get_single_credential,
            command::update_credential,
            command::delete_credential,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
