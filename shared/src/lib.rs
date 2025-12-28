pub mod encryption;
pub mod storage;
pub mod users;
pub mod messages;
pub mod shellio;
pub mod utils;

use std::{
    io,
    process::Command,
};


pub fn get_version() -> String {
    "0".to_owned()
}

pub fn get_server_port_no() -> String {
    "43210".to_owned()
}

pub fn get_buf_size() -> usize {
    8192
}

pub fn get_tailscale_ip() -> Result<String, io::Error> {
    // Run the `tailscale ip` command
    let output = Command::new("sh")
        .arg("-c")
        .arg("tailscale ip | head -n 1")
        .output()?; // Capture the command's output


    if output.status.success() {
        // Convert the output to a string
        let ip = String::from_utf8_lossy(&output.stdout);
        Ok(ip.trim().to_string()) // Trim whitespace and return
    } else {
        // Handle errors
        let error_message = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to get Tailscale IP: {}", error_message),
        ))
    }
}

pub fn get_server_address() -> String {
    "127.0.0.1:43210".to_string()
}

pub fn get_verification_message() -> String {
    "verified".to_owned()
}

pub fn get_key_updated_message() -> String {
    "verified".to_owned()
}

pub fn get_client_buffer_size() -> usize {
    128
}
