// Contains all api calls for accessing the storage
// Create db, destroy db, check-db-exists, check-key-exists, add-key, destroy-key, get-key, set-key

use sled;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type DB = sled::Db;
pub type DBError = sled::Error;



// Checks if the path is valid
pub fn check_db_exists(path_to_db: &str) -> bool {
    std::path::Path::new(path_to_db).exists()
}

// Returns a connection to the DB
pub fn get_db<P>(path_to_db: P) -> Result<DB, DBError> where P: AsRef<std::path::Path> {
    return sled::open(path_to_db);
}


//Deletes a file at the path. Returns an error if not a file.
pub fn delete_db(path_to_db: &str) -> std::io::Result<()> {
    // Very dangerous, there fore check if name ends in db
    if path_to_db.ends_with("_db") {
        std::fs::remove_dir_all(path_to_db)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "The path does not end with _db, deletion aborted.",
        ))
    }
}

// Gets a value from the Database.
pub fn get_value_from_db(key: &[u8], db: &DB) -> Result<Option<Vec<u8>>, DBError> {
    return db
        .get(key)
        .map(|opt_ivec| opt_ivec.map(|ivec| ivec.to_vec()));
}

pub async fn async_get_value_from_db(key: &[u8], db: Arc<RwLock<DB>>) -> Result<Option<Vec<u8>>, DBError> {
    let db_lock = db.read().await;
    get_value_from_db(key, &db_lock)
}


//Sets a value in the Database, returns the previous value if it exists.
pub fn set_value_in_db(key: &[u8], value: &[u8], db: &DB) -> Result<Option<Vec<u8>>, DBError> {
    let result = db
        .insert(key, value)
        .map(|opt_ivec| opt_ivec.map(|vec| vec.to_vec()));

    db.flush()?;
    result
}

pub async fn async_set_value_in_db(key: &[u8], value: &[u8], db: Arc<RwLock<DB>>) -> Result<Option<Vec<u8>>, DBError> {
    let db_lock = db.write().await;
    set_value_in_db(key, value, &db_lock)
}


#[cfg(test)]
mod tests {

    use super::*;

    //Checks if we can create db, check for db, and destroy db
    #[test]
    fn db_creation_and_destroy() {
        let db_path = "./test_db";

        //Checking if test db already exists
        assert!(!check_db_exists(db_path)); // Should evaluate to false

        // Create a new test db
        get_db(db_path).unwrap();

        //Checking if test db exists
        assert!(check_db_exists(db_path)); // Should evaluate to true

        //Delete test database
        delete_db(db_path).unwrap();

        //Check if test database exists
        assert!(!check_db_exists(db_path)); // Should evaluate to false
    }

    //Checks to see if we can set and get values from the db
    #[test]
    fn db_set_and_get_values() {
        let db_path = "./2test_db";

        //Checking if test db already exists
        assert!(!check_db_exists(db_path)); // Should evaluate to false

        // Create a new test db
        let db = get_db(db_path).unwrap();

        //Checking if test db exists
        assert!(check_db_exists(db_path)); // Should evaluate to true

        //Set a value in the db
        let key = "I want to".as_bytes();
        let value = "change messaging.".as_bytes();
        let first_value = set_value_in_db(key, value, &db).unwrap();


        //There shouldn't be an original value
        assert_eq!(first_value, None);

        //Get the value from db
        let stored_value = get_value_from_db(key, &db).unwrap();

        //Checks if the value stored and value returned are the same.
        assert_eq!(stored_value, Some(value.to_vec()));

        //Delete test database
        delete_db(db_path).unwrap();

        //Check if test database exists
        assert!(!check_db_exists(db_path)); // Should evaluate to false
    }

    #[test]
    fn check_empty_value() {
        let db_path = "./3test_db";

        //Checking if test db already exists
        assert!(!check_db_exists(db_path)); // Should evaluate to false

        // Create a new test db
        let db = get_db(db_path).unwrap();

        //Checking if test db exists
        assert!(check_db_exists(db_path)); // Should evaluate to true

        let key = "I want to".as_bytes();
        let _ = get_value_from_db(key, &db).unwrap();


        //Delete test database
        delete_db(db_path).unwrap();

        //Check if test database exists
        assert!(!check_db_exists(db_path)); // Should evaluate to false
    }
}
