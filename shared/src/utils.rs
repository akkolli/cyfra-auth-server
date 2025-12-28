use chrono::{DateTime, Local};

//Fix these functions

pub fn vec_to_hex(vec: &Vec<u8>) -> String {
    vec.iter().map(|byte| format!("{:02x}", byte))
    .collect()
}


// //fix this
pub fn hex_to_vec(hex_str: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i+2], 16))
        .collect()
}


pub fn get_current_time_string() -> String {
    let date = chrono::Local::now();
    format!("{}", date.format("%Y-%m-%d||%H:%M:%S"))
}

pub fn get_current_time_from_unix(unix_time: u64) -> Option<String> {
    let date = chrono::DateTime::from_timestamp(unix_time.try_into().unwrap(),0 );
    match date {
        Some(date) => {
            let local: DateTime<Local> = chrono::DateTime::from(date);
            Some(format!("{}", local.format("%Y-%m-%d||%H:%M:%S")))
        },
        None => None
    }

}

pub fn is_numeric_integer(s: &str) -> bool {
    s.parse::<i64>().is_ok() // Try parsing as a 64-bit integer
}
