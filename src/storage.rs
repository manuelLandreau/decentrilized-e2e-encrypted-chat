use crate::crypto::KeyPair;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use x25519_dalek::StaticSecret;

#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub public_key: Option<[u8; 32]>,
}

fn get_data_dir() -> Result<PathBuf, Box<dyn Error>> {
    let proj_dirs = ProjectDirs::from("com", "secure_chat", "secure_chat")
        .ok_or("Impossible de déterminer le répertoire de données")?;
    
    let data_dir = proj_dirs.data_dir();
    if !data_dir.exists() {
        fs::create_dir_all(data_dir)?;
    }
    
    Ok(data_dir.to_path_buf())
}

fn get_contacts_path() -> Result<PathBuf, Box<dyn Error>> {
    let data_dir = get_data_dir()?;
    Ok(data_dir.join("contacts.json"))
}

fn get_keys_path() -> Result<PathBuf, Box<dyn Error>> {
    let data_dir = get_data_dir()?;
    Ok(data_dir.join("keys.bin"))
}

pub fn add_contact(name: &str, ip: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let mut contacts = list_contacts()?;
    
    // Vérifier si le contact existe déjà
    if contacts.iter().any(|c| c.name == name) {
        return Err("Un contact avec ce nom existe déjà".into());
    }
    
    contacts.push(Contact {
        name: name.to_string(),
        ip: ip.to_string(),
        port,
        public_key: None,
    });
    
    save_contacts(&contacts)?;
    Ok(())
}

pub fn list_contacts() -> Result<Vec<Contact>, Box<dyn Error>> {
    let contacts_path = get_contacts_path()?;
    
    if !contacts_path.exists() {
        return Ok(Vec::new());
    }
    
    let file = File::open(contacts_path)?;
    let contacts: Vec<Contact> = serde_json::from_reader(file)?;
    
    Ok(contacts)
}

fn save_contacts(contacts: &[Contact]) -> Result<(), Box<dyn Error>> {
    let contacts_path = get_contacts_path()?;
    let file = File::create(contacts_path)?;
    serde_json::to_writer_pretty(file, contacts)?;
    Ok(())
}

pub fn load_or_create_keypair() -> Result<KeyPair, Box<dyn Error>> {
    let keys_path = get_keys_path()?;
    
    if keys_path.exists() {
        let mut file = File::open(keys_path)?;
        let mut key_bytes = [0u8; 32];
        file.read_exact(&mut key_bytes)?;
        
        let private_key = StaticSecret::from(key_bytes);
        Ok(KeyPair::from_private_key(private_key))
    } else {
        let keypair = KeyPair::new();
        let mut file = File::create(keys_path)?;
        file.write_all(keypair.private_key.to_bytes().as_ref())?;
        Ok(keypair)
    }
}

pub fn update_contact_public_key(
    name: &str,
    public_key: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    let mut contacts = list_contacts()?;
    
    let contact = contacts
        .iter_mut()
        .find(|c| c.name == name)
        .ok_or("Contact non trouvé")?;
    
    contact.public_key = Some(public_key);
    save_contacts(&contacts)?;
    
    Ok(())
} 