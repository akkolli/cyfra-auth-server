mod post_officer;

use mr_pusher::handle_connection;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

use shared::storage;



const MAX_CONNECTIONS: u64 = 16000; // atleast greater than 4
const SERVER_DB_PATH: &str = "./server_db";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // bind to all interfaces at port 43210
    let listener = TcpListener::bind("0.0.0.0:32613").await?;
    println!("Server listening on 0.0.0.0:32613, Max connections: {}", MAX_CONNECTIONS);

    let current_connections = Arc::new(Mutex::new(0_u64)); //Mutex to keep track of current connections

    // get server database
    let db = storage::get_db(SERVER_DB_PATH).unwrap();
    let shareable_db = Arc::new(RwLock::new(db));


    loop {
        let db_copy = shareable_db.clone(); //clone of db handle for each new connection

        let (stream, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        //Check if current connections is near the max lim
        let mut current_connections_value = current_connections.lock().await; // get the value of current connections
        // Dont spawn new thread if number of connections is close to max.
        if *current_connections_value >= MAX_CONNECTIONS - 2 {
            continue;
        }
        // Increment current connections
        *current_connections_value += 1;

        let cloned_current_connections = current_connections.clone();
        println!("Current connecitons: {}", *current_connections_value);
        // Spawn a new task for each client
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, db_copy).await {
                eprintln!("Error handling connection: {}", e);
            }

            // Decrement current connections counter
            let  mut cloned_current_connections = cloned_current_connections.lock().await;
            *cloned_current_connections -= 1;
            println!("Current connections: {}", *cloned_current_connections);
        });
    }
}
