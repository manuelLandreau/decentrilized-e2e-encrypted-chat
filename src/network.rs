use crate::crypto::{decrypt_message, derive_shared_secret, encrypt_message, KeyPair};
use crate::storage::{Contact, update_contact_public_key};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use x25519_dalek::PublicKey;

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    Handshake {
        public_key: [u8; 32],
    },
    Text {
        content: Vec<u8>, // Contenu chiffré
    },
}

#[derive(Debug)]
pub struct ChatMessage {
    pub from: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct NetworkManager {
    keypair: Arc<KeyPair>,
    message_tx: Sender<ChatMessage>,
    outgoing_tx: Sender<(String, String)>,
}

impl NetworkManager {
    pub fn new(
        keypair: KeyPair,
        message_tx: Sender<ChatMessage>,
    ) -> (Self, Receiver<(String, String)>) {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(100);
        
        (
            Self {
                keypair: Arc::new(keypair),
                message_tx,
                outgoing_tx,
            },
            outgoing_rx,
        )
    }
    
    pub async fn start_server(&self, port: u16) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("Serveur démarré sur le port {}", port);
        
        let keypair = Arc::clone(&self.keypair);
        let message_tx = self.message_tx.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        println!("Nouvelle connexion: {}", addr);
                        let keypair_clone = Arc::clone(&keypair);
                        let message_tx_clone = message_tx.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(socket, keypair_clone, message_tx_clone).await {
                                eprintln!("Erreur de connexion: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Erreur d'acceptation de connexion: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    pub async fn start_outgoing_handler(
        &self,
        mut outgoing_rx: Receiver<(String, String)>,
    ) -> Result<(), Box<dyn Error>> {
        let keypair = Arc::clone(&self.keypair);
        
        tokio::spawn(async move {
            while let Some((contact_name, message)) = outgoing_rx.recv().await {
                match send_message(contact_name, message, keypair.clone()).await {
                    Ok(_) => {}
                    Err(e) => eprintln!("Erreur d'envoi de message: {}", e),
                }
            }
        });
        
        Ok(())
    }
    
    pub async fn send_message(&self, contact_name: String, message: String) -> Result<(), Box<dyn Error>> {
        self.outgoing_tx.send((contact_name, message)).await?;
        Ok(())
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    keypair: Arc<KeyPair>,
    message_tx: Sender<ChatMessage>,
) -> Result<(), Box<dyn Error>> {
    // Échange de clés
    let handshake = Message::Handshake {
        public_key: keypair.public_key.to_bytes(),
    };
    
    let handshake_bytes = serde_json::to_vec(&handshake)?;
    let handshake_len = handshake_bytes.len() as u32;
    
    socket.write_all(&handshake_len.to_be_bytes()).await?;
    socket.write_all(&handshake_bytes).await?;
    
    // Recevoir la clé publique du contact
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    
    let mut msg_buf = vec![0u8; msg_len];
    socket.read_exact(&mut msg_buf).await?;
    
    let their_handshake: Message = serde_json::from_slice(&msg_buf)?;
    
    let their_public_key = match their_handshake {
        Message::Handshake { public_key } => public_key,
        _ => return Err("Protocole de handshake invalide".into()),
    };
    
    let their_public_key = PublicKey::from(their_public_key);
    let shared_secret = derive_shared_secret(&keypair.private_key, &their_public_key);
    
    // Boucle de réception des messages
    loop {
        let mut len_buf = [0u8; 4];
        if socket.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        
        if socket.read_exact(&mut msg_buf).await.is_err() {
            break;
        }
        
        let message: Message = serde_json::from_slice(&msg_buf)?;
        
        match message {
            Message::Text { content } => {
                let decrypted = decrypt_message(&content, &shared_secret)?;
                let text = String::from_utf8(decrypted)?;
                
                let chat_message = ChatMessage {
                    from: "Contact".to_string(), // Idéalement, identifiez le contact
                    content: text,
                    timestamp: chrono::Utc::now(),
                };
                
                message_tx.send(chat_message).await?;
            }
            _ => return Err("Message inattendu après handshake".into()),
        }
    }
    
    Ok(())
}

async fn send_message(
    contact_name: String,
    message: String,
    keypair: Arc<KeyPair>,
) -> Result<(), Box<dyn Error>> {
    use crate::storage::list_contacts;
    
    let contacts = list_contacts()?;
    let contact = contacts
        .iter()
        .find(|c| c.name == contact_name)
        .ok_or(format!("Contact non trouvé: {}", contact_name))?;
    
    let mut socket = TcpStream::connect(format!("{}:{}", contact.ip, contact.port)).await?;
    
    // Échange de clés
    let handshake = Message::Handshake {
        public_key: keypair.public_key.to_bytes(),
    };
    
    let handshake_bytes = serde_json::to_vec(&handshake)?;
    let handshake_len = handshake_bytes.len() as u32;
    
    socket.write_all(&handshake_len.to_be_bytes()).await?;
    socket.write_all(&handshake_bytes).await?;
    
    // Recevoir la clé publique du contact
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    
    let mut msg_buf = vec![0u8; msg_len];
    socket.read_exact(&mut msg_buf).await?;
    
    let their_handshake: Message = serde_json::from_slice(&msg_buf)?;
    
    let their_public_key = match their_handshake {
        Message::Handshake { public_key } => {
            // Mettre à jour la clé publique du contact si nécessaire
            if contact.public_key.is_none() || contact.public_key.unwrap() != public_key {
                update_contact_public_key(&contact_name, public_key)?;
            }
            public_key
        }
        _ => return Err("Protocole de handshake invalide".into()),
    };
    
    let their_public_key = PublicKey::from(their_public_key);
    let shared_secret = derive_shared_secret(&keypair.private_key, &their_public_key);
    
    // Chiffrer et envoyer le message
    let encrypted = encrypt_message(message.as_bytes(), &shared_secret)?;
    
    let message = Message::Text {
        content: encrypted,
    };
    
    let message_bytes = serde_json::to_vec(&message)?;
    let message_len = message_bytes.len() as u32;
    
    socket.write_all(&message_len.to_be_bytes()).await?;
    socket.write_all(&message_bytes).await?;
    
    Ok(())
} 