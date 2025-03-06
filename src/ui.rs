use crate::crypto::KeyPair;
use crate::network::{ChatMessage, NetworkManager};
use crate::storage::{list_contacts, load_or_create_keypair};
use std::error::Error;
use std::io::{self, Write};
use tokio::sync::mpsc;

pub async fn start_chat(port: u16) -> Result<(), Box<dyn Error>> {
    println!("Démarrage de l'application de chat sécurisée...");
    
    // Charger ou créer une paire de clés
    let keypair = load_or_create_keypair()?;
    println!("Clé publique: {:?}", keypair.public_key.to_bytes());
    
    // Configurer les canaux de communication
    let (message_tx, mut message_rx) = mpsc::channel(100);
    let (network_manager, outgoing_rx) = NetworkManager::new(keypair, message_tx.clone());
    
    // Démarrer le serveur
    network_manager.start_server(port).await?;
    
    // Démarrer le gestionnaire de messages sortants
    network_manager.start_outgoing_handler(outgoing_rx).await?;
    
    // Afficher les contacts disponibles
    let contacts = list_contacts()?;
    println!("Contacts disponibles:");
    if contacts.is_empty() {
        println!("  Aucun contact. Ajoutez-en avec 'secure_chat add-contact'");
    } else {
        for contact in contacts {
            println!("  - {} ({}:{})", contact.name, contact.ip, contact.port);
        }
    }
    
    // Démarrer l'interface utilisateur
    println!("\nEntrez votre message au format 'contact: message'");
    println!("Ou tapez 'exit' pour quitter");
    
    // Gérer les messages entrants
    tokio::spawn(async move {
        while let Some(message) = message_rx.recv().await {
            println!(
                "\r[{}] {}: {}\nVous > ",
                message.timestamp.format("%H:%M:%S"),
                message.from,
                message.content
            );
            io::stdout().flush().unwrap();
        }
    });
    
    // Boucle principale pour l'entrée utilisateur
    loop {
        print!("Vous > ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input == "exit" {
            break;
        }
        
        if let Some(colon_pos) = input.find(':') {
            let contact_name = input[..colon_pos].trim();
            let message = input[colon_pos + 1..].trim();
            
            if !message.is_empty() {
                match network_manager.send_message(contact_name.to_string(), message.to_string()).await {
                    Ok(_) => {
                        let timestamp = chrono::Utc::now();
                        println!(
                            "[{}] Vous -> {}: {}",
                            timestamp.format("%H:%M:%S"),
                            contact_name,
                            message
                        );
                    }
                    Err(e) => {
                        eprintln!("Erreur d'envoi: {}", e);
                    }
                }
            }
        } else {
            println!("Format invalide. Utilisez 'contact: message'");
        }
    }
    
    Ok(())
} 