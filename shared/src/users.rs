use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use crate::{
    encryption::{self, generate_enc_keypair}, messages,
    storage::{self, get_value_from_db},
    users,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub version: String,
    pub username: Vec<u8>,
    pub id_pkcs8: Vec<u8>,
    pub enc_pub: [u8; 32],
    pub enc_priv: [u8; 32],
    pub chats: Vec<messages::Chat>,
    pub unread: u64,
}

impl User {
    pub fn get_version(&self) -> String {
        return self.version.to_owned();
    }

    pub fn get_chats(&self) -> Vec<messages::Chat> {
        return self.chats.to_vec();
    }

    pub fn get_unread(&self) -> u64 {
        return self.unread;
    }

    pub fn get_pubkey(&self) -> Vec<u8> {
        let key_pair  = encryption::generate_longterm_keypair(&self.id_pkcs8).unwrap();
        let public_key = encryption::get_public_key_from_longterm_keypair(&key_pair);
        public_key.to_vec()
    }
}

fn get_hashes(username: &[u8], password: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key_hash = encryption::hash([username, password].concat().as_ref());
    let enc_hash = encryption::hash(password);

    (key_hash, enc_hash)
}

pub fn check_user_exists(
    username: &[u8],
    password: &[u8],
    db: &storage::DB,
) -> Result<bool, storage::DBError> {
    let (key_hash, _) = get_hashes(username, password);

    match get_value_from_db(&key_hash, &db) {
        Ok(value) => match value {
            Some(_) => return Ok(true),
            None => return Ok(false),
        },
        Err(_) => {
            return Err(storage::DBError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Error checking for user data",
            )))
        }
    };
}

pub async fn async_check_user_exists(username: &[u8], password: &[u8], db: Arc<Mutex<storage::DB>>) -> Result<bool, storage::DBError>{
    let db_clone = db.clone();
    let db_locked = db_clone.lock().await;

    check_user_exists(username, password, &db_locked)

}







pub fn add_new_user(username: &[u8], password: &[u8], db: &storage::DB) -> Result<bool, storage::DBError>{
    //Check if the user already exists
    match check_user_exists(username, password, db)? {
        true => {return Ok(false);},
        false => {},
    };

    let pkcs8 = encryption::generate_pkcs8_bytes().unwrap();
    let (enc_priv, enc_pub) = generate_enc_keypair();

    // Create new user
    let new_user: User = User {
        version: "0.0.0".to_string(),
        username: username.to_vec(),
        id_pkcs8: pkcs8,
        enc_priv: enc_priv.to_bytes(),
        enc_pub: enc_pub.to_bytes(),
        chats: Vec::new(),
        unread: 0,

    };

    set_user_data(username, password, new_user, db)?;

    Ok(true)
}

pub async fn async_add_new_user(username: &[u8], password: &[u8], db: Arc<Mutex<storage::DB>>) -> Result<bool, storage::DBError> {
    let db_clone = db.clone();
    let db_locked = db_clone.lock().await;
    add_new_user(username, password, &db_locked)
}


//Fix this code, used unwraps
pub fn set_user_data(
    username: &[u8],
    password: &[u8],
    user: users::User,
    db: &storage::DB,
) -> Result<Option<Vec<u8>>, storage::DBError> {
    let (key_hash, enc_hash) = get_hashes(username, password);

    let serialized_user_data = serde_json::to_string(&user).unwrap();

    let encoded_user_data =
        encryption::encrypt_data(&enc_hash, serialized_user_data.as_ref(), "".as_bytes()).unwrap();

    storage::set_value_in_db(&key_hash, &encoded_user_data, &db)
}
pub async fn async_set_user_data(
    username: &[u8],
    password: &[u8],
    user: users::User,
    db: Arc<Mutex<storage::DB>>,
) -> Result<Option<Vec<u8>>, storage::DBError> {
    let db_clone = db.clone();
    let db_locked = db_clone.lock().await;

    set_user_data(username, password, user, &db_locked)
}



fn get_user_data(
    username: &[u8],
    password: &[u8],
    db: &storage::DB,
) -> Result<User, storage::DBError> {
    match check_user_exists(&username, &password, db) {
        Ok(value) => match value {
            true => {}
            false => {
                return Err(storage::DBError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Error retrieving user data",
                )))
            }
        },

        Err(_) => {
            return Err(storage::DBError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Error retrieving user data",
            )))
        }
    }

    let (key_hash, enc_hash) = get_hashes(username, password);

    // Get key from storage
    let mut enc_user_data: Vec<u8>;
    match get_value_from_db(&key_hash, &db)? {
        Some(value) => {
            enc_user_data = value;
        }
        None => {
            return Err(storage::DBError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Error retrieving user data",
            )))
        }
    };

    //Decrypt data
    let user_data = encryption::decrypt_data(&enc_hash, &mut enc_user_data, "".as_ref());

    //Return deserialized user data
    match user_data {
        Ok(serialized_user_data) => match serde_json::from_slice(&serialized_user_data) {
            Ok(user) => Ok(user),
            Err(_) => Err(storage::DBError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "User data corrupted",
            ))),
        },
        Err(_) => Err(storage::DBError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "User data corrupted",
        ))),
    }
}

pub async fn async_get_user_data(username: &[u8], password: &[u8],
db: Arc<Mutex<storage::DB>>,
) -> Result<User, storage::DBError> {
    let db_clone = db.clone();
    let db_locked = db_clone.lock().await;

    get_user_data(username, password, &db_locked)
}

pub async fn check_for_chat_in_db_w_name(username: &[u8], password: &[u8], name: String, db: Arc<Mutex<storage::DB>>) -> bool {
    let user_data = async_get_user_data(username, password, db).await.unwrap();

    for chat in user_data.chats.iter() {
        if chat.peer_name == name {
            return true;
        }
    };

    return false;
}


// #[cfg(test)]
// // mod tests {

// //     use super::{storage, encryption, User, set_user_data, get_user_data};

// //     #[test]
// //     fn set_and_get_user_data() {
// //         let username = "lepton".as_bytes();
// //         let password = "ketchup".as_bytes();

// //         let db_path = "users1_test_db";
// //         let db = storage::get_db(db_path).unwrap();

// //         let pkcs8 = encryption::generate_pkcs8_bytes().unwrap();

// //         let _ = encryption::generate_longterm_keypair(&pkcs8).unwrap();

// //         let (enc_priv, enc_pub) = encryption::generate_enc_keypair();

// //         let user_data = User {
// //             version: "1.0.0".to_string(),
// //             username: "lepton".as_bytes().to_vec(),
// //             id_pkcs8: pkcs8,
// //             enc_priv: *enc_priv.as_bytes(),
// //             enc_pub: *enc_pub.as_bytes(),
// //             chats: Vec::new(),
// //             unread: 0,
// //         };

// //         set_user_data(username, password, user_data.clone(), &db).unwrap();

// //         let retreieved_user_data = get_user_data(username, password, &db).unwrap();

// //         assert_eq!(retreieved_user_data, user_data);

// //         //Delete test database
// //         storage::delete_db(db_path).unwrap();

// //         //Check if test database exists
// //         assert!(!storage::check_db_exists(db_path)); // Should evaluate to false
// //     }
// }
