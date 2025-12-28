use rand::Rng;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::get_version;

use crate::users;

// Finish this structure, contains a bunch of envelopes so that the server can send it all over at once.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Satchel {
    pub id: u64,
    pub time: u64,
    pub server_name: String,
    pub server_pub_key: Vec<u8>,
    pub server_address: Vec<u8>,
    pub recipient_id_pubkey: Vec<u8>,
    pub envelopes: Vec<Envelope>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Envelope {
    pub id: u32,
    pub time: u64,
    pub sender_name: String,
    pub sender_pub_key: Vec<u8>,
    pub sender_enc_pub_key: [u8; 32],
    pub recipient_name: String,
    pub recipient_pubkey: Vec<u8>,
    pub recipient_enc_pubkey: Vec<u8>,
    pub kind: u8, // 0 --> regular encrypted text message | 1 --> request for enc keys | 2 --> request for outstanding messages | 3 --> clear outstanding messages  | 404 --> No messages to return
    pub encrypted_message: Vec<u8>,
}

impl Envelope {
    pub fn new(user_data: users::User, recipient_name: Vec<u8>, recipient_pubkey: Vec<u8>, recipient_enc_pubkey: Vec<u8>, message: Vec<u8>, kind: u8) -> Envelope {
        let new_id: u32 = {
                        let mut rng = rand::thread_rng();
                        rng.gen()
                    };

        let username = &user_data.username;
        let my_pub_key = user_data.get_pubkey();


        let envelope = Envelope {
                        id: new_id,
                        time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                        sender_name: String::from_utf8(username.to_owned()).unwrap(),
                        sender_pub_key: my_pub_key,
                        sender_enc_pub_key: user_data.enc_pub,
                        recipient_name: String::from_utf8(recipient_name.to_vec()).unwrap(),
                        recipient_pubkey,
                        recipient_enc_pubkey,
                        kind,
                        encrypted_message: message,        };

        envelope

    }
}


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Message {
    pub chat_id: u32,
    pub version: String,
    pub id: u32,
    pub time: u64,
    pub sender_name: String,
    pub sender_pub_key: Vec<u8>,
    pub recipient_name: String,
    pub recipient_pub_key: Vec<u8>,
    pub data: Vec<u8>,
    pub additional_data: Vec<u8>,
}



#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Chat {
   pub version: String,
   pub id: u32,
   pub name: String,
   pub peer_name: String,
   pub public_key: Vec<u8>,
   pub peer_id_pubkey: Vec<u8>,
   pub peer_enc_pubkey: Option<Vec<u8>>,
   pub additional_data : Vec<u8>,
   pub messages: Vec<Message>,
   pub unread: u32,
}

impl Chat {

    pub fn new(peer_public_key: &[u8], peer_name: &String) -> Chat {

        let mut rng = rand::thread_rng();
        let id_ = rng.gen();
        let empty_chat_vec: Vec<Message> = Vec::new();
        let new_chat = Chat {
            version: get_version(),
            id: id_,
            name: String::from("Me"),
            peer_name: peer_name.clone(),
            public_key: Vec::new(),
            peer_id_pubkey: peer_public_key.to_vec(),
            peer_enc_pubkey: None,
            messages : empty_chat_vec,
            additional_data: Vec::new(),
            unread: 0,
        };

        new_chat

    }

    pub fn new_message(&mut self,
        sender_name: String,
        sender_pub_key: Vec<u8>,
        recipient_name: String,
        recipient_pub_key: Vec<u8>,
        data: Vec<u8>,
        additional_data: Vec<u8>,
    ) -> Message{

        let mut rng = rand::thread_rng();

        let new_message = Message {
            chat_id : self.id,
            version : self.version.clone(),
            id : rng.gen(),
            time : SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            sender_name,
            sender_pub_key,
            recipient_name,
            recipient_pub_key,
            data,
            additional_data,
        };

        new_message
    }
}


// impl Message {

//     pub fn new(owner_chat_id: u32, content: Vec<u8>,
//             sender_name: String,
//             sender_pub_key: Vec<u8>,
//             recipient_name: String,
//             recipient_pub_key: Vec<u8>,


//     ) -> Message {
//         let mut rng = rand::thread_rng();
//         let id_ = rng.gen();
//         Message {
//             chat_id : owner_chat_id,
//             version : get_version(),
//             id : id_,
//             time : SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
//             sender_name : sender_name,
//             sender_pub_key : sender_pub_key,
//             recipient_name : recipient_name,
//             recipient_pub_key : recipient_pub_key,
//             data : content,
//             additional_data : Vec::<u8>::new(),
//         }
//     }
// }
