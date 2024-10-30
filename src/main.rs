use std::{
    io::{self, BufRead, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
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

const SALT: &[u8] = b"ko3eev1Iuraid8Rait3h";

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Action to perform: connect or bind
    #[arg(value_enum)]
    action: Action,

    /// IP address to connect/bind to (default: 127.0.0.1)
    #[arg(short = 'a', long, default_value = "127.0.0.1:4444")]
    address: String,

    /// Password for encryption
    #[arg(short, long)]
    password: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Action {
    Connect,
    Bind,
}

fn main() -> io::Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    let password = if let Some(pw) = args.password {
        pw
    }
    else {
        eprintln!("Password is required. Use -p <password> to provide it.");
        std::process::exit(1);
    };

    let password = password.as_bytes();

    // Derive key from password using PBKDF2
    let mut key_bytes = [0u8; 32]; // 256-bit key
    pbkdf2::<Hmac<Sha256>>(password, SALT, 100_000, &mut key_bytes);
    let key = Key::<Aes256GcmSiv>::from_slice(&key_bytes);
    let cipher = Arc::new(Aes256GcmSiv::new(key));

    match args.action {
        Action::Bind => {
            let listener = TcpListener::bind(&args.address)?;
            println!("Listening on {}...", &args.address);

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let cipher_clone = cipher.clone();
                        handle_connection(stream, cipher_clone);
                    }
                    Err(e) => {
                        eprintln!("Connection failed: {:?}", e);
                    }
                }
            }
        }
        Action::Connect => {
            let stream = TcpStream::connect(&args.address)?;
            println!("Connected to {}", &args.address);
            let cipher_clone = cipher.clone();
            handle_connection(stream, cipher_clone);
        }
    }

    Ok(())
}

fn handle_connection(stream: TcpStream, cipher: Arc<Aes256GcmSiv>) {
    let mut stream_clone = stream.try_clone().expect("Failed to clone stream");

    // Thread for receiving messages
    let cipher_recv = cipher.clone();
    let mut stream_recv = stream
        .try_clone()
        .expect("Failed to clone stream for receiving");
    thread::spawn(move || {
        loop {
            // Read nonce (12 bytes)
            let mut nonce_bytes = [0u8; 12];
            if stream_recv.read_exact(&mut nonce_bytes).is_err() {
                eprintln!("Connection closed by peer.");
                break;
            }
            let nonce = Nonce::from_slice(&nonce_bytes);

            // Read message length (8 bytes)
            let mut len_bytes = [0u8; 8];
            if stream_recv.read_exact(&mut len_bytes).is_err() {
                eprintln!("Connection closed by peer.");
                break;
            }
            let msg_len = u64::from_le_bytes(len_bytes) as usize;

            // Read ciphertext
            let mut ciphertext = vec![0u8; msg_len];
            if stream_recv.read_exact(&mut ciphertext).is_err() {
                eprintln!("Connection closed by peer.");
                break;
            }

            // Decrypt and display the message
            match cipher_recv.decrypt(nonce, ciphertext.as_ref()) {
                Ok(plaintext) => {
                    println!("Peer: {}", String::from_utf8_lossy(&plaintext));
                }
                Err(e) => {
                    eprintln!("Decryption error: {:?}", e);
                    break;
                }
            }
        }
    });

    // Thread for sending messages
    let cipher_send = cipher.clone();
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdin_lock = stdin.lock();

        loop {
            let mut input = String::new();
            if stdin_lock.read_line(&mut input).is_err() {
                eprintln!("Failed to read from stdin.");
                break;
            }

            let plaintext = input.trim_end().as_bytes();
            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            // Encrypt the message
            match cipher_send.encrypt(nonce, plaintext) {
                Ok(ciphertext) => {
                    let msg_len = ciphertext.len() as u64;

                    // Send nonce, message length, and ciphertext
                    if stream_clone
                        .write_all(&nonce_bytes)
                        .and_then(|_| stream_clone.write_all(&msg_len.to_le_bytes()))
                        .and_then(|_| stream_clone.write_all(&ciphertext))
                        .is_err()
                    {
                        eprintln!("Failed to send message.");
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Encryption error: {:?}", e);
                }
            }
        }
    })
    .join()
    .expect("Failed to join send thread");
}
