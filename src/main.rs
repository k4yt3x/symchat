use std::{
    io::{self, BufRead, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Key, Nonce,
};
use clap::{Parser, ValueEnum};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Action to perform: connect or bind
    #[arg(value_enum, required = true)]
    action: Action,

    /// IP address to connect/bind to (default: 127.0.0.1)
    #[arg(short = 'a', long, default_value = "127.0.0.1:4444")]
    address: String,

    /// Password for encryption
    #[arg(short, long, required = true)]
    password: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Action {
    Connect,
    Bind,
}

fn main() -> io::Result<()> {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt::init();

    // Parse command-line arguments
    let args = Args::parse();

    let password = match args.password {
        Some(pw) => pw,
        None => {
            error!("Password is required. Use -p <password> to provide it.");
            std::process::exit(1);
        }
    };
    let password = password.as_bytes();

    // Refactored to call specific functions based on action
    match args.action {
        Action::Bind => start_bind(&args.address, password)?,
        Action::Connect => start_connect(&args.address, password)?,
    }

    Ok(())
}

fn start_bind(address: &str, password: &[u8]) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    info!("Listening on {}...", address);
    info!("Waiting for a remote host to connect...");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                error!("Connection failed: {:?}", e);
                continue;
            }
        };

        info!("Remote host connected: {}", stream.peer_addr().unwrap());

        // Generate a random salt and send it to the client
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        stream.write_all(&salt)?;

        // Derive key from password and salt using PBKDF2
        let cipher = derive_cipher(password, &salt);

        handle_connection_with_reconnect(address, stream, cipher);
    }

    Ok(())
}

fn start_connect(address: &str, password: &[u8]) -> io::Result<()> {
    loop {
        let mut stream = match TcpStream::connect(address) {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to connect to {}: {:?}", address, e);
                warn!("Waiting for the remote host to come back online...");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        info!("Connected to {}", address);

        // Receive the salt from the server
        let mut salt = [0u8; 16];
        if let Err(e) = stream.read_exact(&mut salt) {
            error!("Failed to receive salt: {:?}", e);
            continue;
        }

        // Derive key from password and salt using PBKDF2
        let cipher = derive_cipher(password, &salt);

        // Handle the connection and keep trying if disconnected
        handle_connection_with_reconnect(address, stream, cipher);
    }
}

// Extracted key derivation into a function
fn derive_cipher(password: &[u8], salt: &[u8]) -> Arc<Aes256GcmSiv> {
    let mut key_bytes = [0u8; 32]; // 256-bit key
    pbkdf2::<Hmac<Sha256>>(password, salt, 100_000, &mut key_bytes);
    let key = Key::<Aes256GcmSiv>::from_slice(&key_bytes);
    Arc::new(Aes256GcmSiv::new(key))
}

fn handle_connection_with_reconnect(
    address: &str,
    mut stream: TcpStream,
    cipher: Arc<Aes256GcmSiv>,
) {
    loop {
        let cloned_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => {
                error!("Failed to clone TCP stream. Exiting...");
                break;
            }
        };

        // Spawn threads for receiving and sending messages
        let recv_thread = spawn_recv_thread(cloned_stream, cipher.clone());
        let send_thread = spawn_send_thread(stream.try_clone().unwrap(), cipher.clone());

        // Wait for both threads to finish
        let _ = recv_thread.join();
        let _ = send_thread.join();

        warn!("Disconnected. Attempting to reconnect...");
        stream = match reconnect(address) {
            Some(s) => s,
            None => break,
        };
    }
}

// Extracted reconnection logic into a function
fn reconnect(address: &str) -> Option<TcpStream> {
    loop {
        match TcpStream::connect(address) {
            Ok(new_stream) => {
                info!("Reconnected to {}", address);
                return Some(new_stream);
            }
            Err(_) => {
                warn!("Retrying connection to {}...", address);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

// Extracted receive thread logic into a function
fn spawn_recv_thread(mut stream: TcpStream, cipher: Arc<Aes256GcmSiv>) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        if let Err(e) = receive_message(&mut stream, &cipher) {
            print!("\r\x1b[K");
            error!("Receive error: {:?}", e);
            return;
        }
    })
}

fn receive_message(stream: &mut TcpStream, cipher: &Aes256GcmSiv) -> io::Result<()> {
    // Read nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    stream.read_exact(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Read message length (8 bytes)
    let mut len_bytes = [0u8; 8];
    stream.read_exact(&mut len_bytes)?;
    let msg_len = u64::from_le_bytes(len_bytes) as usize;

    // Read ciphertext
    let mut ciphertext = vec![0u8; msg_len];
    stream.read_exact(&mut ciphertext)?;

    // Decrypt and display the message
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|e| {
        println!("\r\x1b[K");
        error!("Decryption error: {:?}", e);
        io::Error::new(io::ErrorKind::Other, "Decryption error")
    })?;

    print!("\r\x1b[K");
    println!("\rReceived: {}", String::from_utf8_lossy(&plaintext));
    print!("Send message: ");
    io::stdout().flush().unwrap();

    Ok(())
}

// Extracted send thread logic into a function
fn spawn_send_thread(mut stream: TcpStream, cipher: Arc<Aes256GcmSiv>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdin_lock = stdin.lock();

        loop {
            print!("\rSend message: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            if stdin_lock.read_line(&mut input).is_err() {
                error!("Failed to read from stdin.");
                return;
            }

            if let Err(e) = send_message(&mut stream, &cipher, input.trim_end().as_bytes()) {
                error!("Send error: {:?}", e);
                return;
            }
        }
    })
}

fn send_message(stream: &mut TcpStream, cipher: &Aes256GcmSiv, plaintext: &[u8]) -> io::Result<()> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the message
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
        error!("Encryption error: {:?}", e);
        io::Error::new(io::ErrorKind::Other, "Encryption error")
    })?;

    let msg_len = ciphertext.len() as u64;

    // Send nonce, message length, and ciphertext
    stream.write_all(&nonce_bytes)?;
    stream.write_all(&msg_len.to_le_bytes())?;
    stream.write_all(&ciphertext)?;

    Ok(())
}
