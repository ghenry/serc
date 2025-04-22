// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2025 Gavin Henry <ghenry@antnetworks.com>

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use argon2::password_hash::SaltString;
use base64::Engine as _;
use base64::engine::general_purpose;
use clap::Parser;
use dialoguer::{Input, Password, Select};
use dirs::config_dir;
use rand::{Rng, random};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

/// Struct for CLI args
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {}

#[derive(Debug, Serialize, Deserialize)]
struct TrelloCard {
    id: String,
    name: String,
    desc: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrelloAuth {
    key: String,
    token: String,
    board_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WPAuth {
    site: String,
    username: String,
    app_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredAuth {
    trello: TrelloAuth,
    wordpress: WPAuth,
}

fn derive_key_from_passphrase(pass: &str, salt: &[u8]) -> [u8; 32] {
    use argon2::{Argon2, PasswordHasher};
    let argon2 = Argon2::default();

    let salt = SaltString::encode_b64(salt).expect("Failed to encode salt");
    let password_hash = argon2.hash_password(pass.as_bytes(), &salt).unwrap();
    let hash_bytes = password_hash.hash.unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes.as_bytes());
    key
}

fn encrypt_data(data: &[u8], password: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);
    let key = derive_key_from_passphrase(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("invalid key");
    let nonce = random::<[u8; 12]>();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .expect("invalid nonce");
    Ok((ciphertext, nonce.to_vec(), salt.to_vec()))
}

fn decrypt_data(ciphertext: &[u8], nonce: &[u8], salt: &[u8], password: &str) -> Result<Vec<u8>> {
    let key = derive_key_from_passphrase(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("Failed to create cipher");
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .expect("Decryption failed");
    Ok(plaintext)
}

fn get_auth(path: &PathBuf, password: &str) -> Result<StoredAuth> {
    if path.exists() {
        let raw = fs::read(path)?;
        let parts: Vec<&[u8]> = raw.split(|&b| b == b'\n').collect();
        let salt = general_purpose::STANDARD.decode(parts[0])?;
        let nonce = general_purpose::STANDARD.decode(parts[1])?;
        let cipher = general_purpose::STANDARD.decode(parts[2])?;
        let decrypted = decrypt_data(&cipher, &nonce, &salt, password)?;
        Ok(serde_json::from_slice(&decrypted)?)
    } else {
        println!("🔐 First time setup. Please remember the passphrase you enter.");
        let key: String = Input::new().with_prompt("Trello API Key").interact_text()?;
        let token: String = Password::new().with_prompt("Trello Token").interact()?;
        let board_id: String = Input::new()
            .with_prompt("Trello Board ID")
            .interact_text()?;
        let site: String = Input::new()
            .with_prompt("WordPress Site URL")
            .interact_text()?;
        let user: String = Input::new()
            .with_prompt("WordPress Username")
            .interact_text()?;
        let wp_pass: String = Password::new()
            .with_prompt("WordPress Application Password")
            .interact()?;

        let auth = StoredAuth {
            trello: TrelloAuth {
                key,
                token,
                board_id,
            },
            wordpress: WPAuth {
                site,
                username: user,
                app_password: wp_pass,
            },
        };

        let serialized = serde_json::to_vec(&auth)?;
        let (cipher, nonce, salt) = encrypt_data(&serialized, password)?;
        let encoded = format!(
            "{}\n{}\n{}",
            general_purpose::STANDARD.encode(&salt),
            general_purpose::STANDARD.encode(&nonce),
            general_purpose::STANDARD.encode(&cipher)
        );
        fs::write(path, encoded)?;
        Ok(auth)
    }
}

fn list_cards(auth: &TrelloAuth) -> Result<Vec<TrelloCard>> {
    let url = format!(
        "https://api.trello.com/1/boards/{}/cards?key={}&token={}",
        auth.board_id, auth.key, auth.token
    );

    let client = Client::new();
    let res = client.get(&url).send()?.error_for_status()?;
    let cards: Vec<TrelloCard> = res.json()?;
    Ok(cards)
}

fn create_wp_draft_post(
    site: &str,
    username: &str,
    password: &str,
    title: &str,
    content: &str,
) -> Result<String> {
    let url = format!("{}/wp-json/wp/v2/posts", site);

    let client = Client::new();
    let body = serde_json::json!({
        "title": title,
        "content": content,
        "status": "draft"
    });

    let res = client
        .post(&url)
        .basic_auth(username, Some(password))
        .json(&body)
        .send()?
        .error_for_status()?;

    let json: serde_json::Value = res.json()?;
    Ok(json["link"].as_str().unwrap_or("").to_string())
}

fn main() -> Result<()> {
    Args::parse();

    let config_path = config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("serc.enc");

    let password = Password::new()
        .with_prompt("🔑 Enter a passphrase to unlock credentials")
        .interact()?;

    let auth = get_auth(&config_path, &password)?;
    println!("🔑 Credentials loaded successfully!");

    loop {
        let cards = list_cards(&auth.trello)?;
        let titles: Vec<String> = cards.iter().map(|c| c.name.clone()).collect();

        let selection = Select::new()
            .with_prompt("📋 Select a card to post (or refresh)")
            .items(&titles)
            .item("🔄 Refresh list")
            .default(0)
            .interact()?;

        if selection == titles.len() {
            continue; // refresh
        }

        let selected = &cards[selection];
        println!("✍️ Posting draft: {}", selected.name);

        let link = create_wp_draft_post(
            &auth.wordpress.site,
            &auth.wordpress.username,
            &auth.wordpress.app_password,
            &selected.name,
            &selected.desc,
        )?;

        println!("✅ Draft created: {}", link);
        open::that(link)?;

        break;
    }

    Ok(())
}
