# SERC ✍️

Securely fetch cards from a Trello board and post them as draft articles on a WordPress site — from the comfort of your terminal.

![CI](https://github.com/ghenry/serc/actions/workflows/ci.yml/badge.svg)

## 🚀 Features
- Secure credential storage with AES-GCM + Argon2
- Trello card listing & selection
- Creates WordPress draft posts
- Opens draft in browser automatically
- Refresh list support
- GitHub Actions CI

## 🔧 Installation
```sh
cargo install --git https://github.com/ghenry/serc
```

## 🔐 First Time Setup
You'll be prompted to enter:
- Trello API Key, Token, and Board ID
- WordPress Site, Username, and Application Password
- A passphrase to encrypt credentials

Encrypted credentials are stored locally and reused securely.

## 🛠 Usage
```sh
serc
```
- Select a Trello card to post.
- Automatically creates a draft on your WordPress site.
- Opens the draft in your default browser.

## 🧪 Tests
Run with:
```sh
cargo test
```

## 📦 Formatting & Linting
```sh
cargo fmt
cargo clippy -- -D warnings
```

## 🤝 Contributing
Contributions welcome! Please open issues or pull requests.

## 📄 License
GPL-3.0-only — see [LICENSE](./LICENSE).

---

> Made with ❤️  in Rust

