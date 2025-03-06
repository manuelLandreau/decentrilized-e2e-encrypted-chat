use clap::{Parser, Subcommand};
use std::error::Error;

mod crypto;
mod network;
mod storage;
mod ui;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Démarrer l'application de chat
    Start {
        /// Port d'écoute
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
    /// Ajouter un nouveau contact
    AddContact {
        /// Nom du contact
        #[arg(short, long)]
        name: String,
        /// Adresse IP du contact
        #[arg(short, long)]
        ip: String,
        /// Port du contact
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
    /// Lister tous les contacts
    ListContacts,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Start { port }) => {
            ui::start_chat(*port).await?;
        }
        Some(Commands::AddContact { name, ip, port }) => {
            storage::add_contact(name, ip, *port)?;
            println!("Contact ajouté avec succès: {} à {}:{}", name, ip, port);
        }
        Some(Commands::ListContacts) => {
            let contacts = storage::list_contacts()?;
            if contacts.is_empty() {
                println!("Aucun contact trouvé.");
            } else {
                println!("Contacts:");
                for contact in contacts {
                    println!("- {} ({}:{})", contact.name, contact.ip, contact.port);
                }
            }
        }
        None => {
            ui::start_chat(8080).await?;
        }
    }

    Ok(())
} 