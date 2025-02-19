# Shield-Bash 🔒
**Automated Security Hardening for Linux**

Shield-Bash is a command-line suite of Bash scripts designed to **enhance server security** through automation. It provides tools for **detecting**, **logging**, and **fixing security vulnerabilities** in system files and configurations.

## 📌 Features
✅ **Automatable Security Scanning** – Detects and fixes permission & ownership issues  
✅ **Modular Design** – Easily extendable with additional security scripts  
✅ **Silent Mode for Automation** – Designed to run in cron jobs without disrupting logs  
✅ **Configurable via `/etc/shield-bash/*.conf`** – All security rules are stored in configuration files  

---

## 📥 Installation

Run the following commands to install **Shield-Bash** on your system:

```bash
git clone https://github.com/KBirenheide/ShieldBash
cd shield-bash
chmod +x setup.sh
sudo ./setup.sh
```

This will:  
* Install Shield-Bash in /var/lib/shield-bash/  
* Store configurations in /etc/shield-bash/  
* Create a system-wide command: shield-bash  

## ⌨️ Usage

The shield-bash command is added to your binaries directory during the setup process. 
You can run it directly from the command line:

```bash
shield-bash --help
shield-bash [script-alias] [options]
```

the `-h, --help` flag will give you an overview of available tools. Each tool has their
own help message, which can be shown using the `-h, --help` flag after the tool name.

### Examples

#### 🔍 Running Project Exposure Scan (PES)
```bash
shield-bash pes -v
```
* Scans configured directories for security exposures 
* Lists ownership & permission issues  
* Fixes issues unless --dry-run is specified  

#### 📋 Uninstalling Shield-Bash
```bash
shield-bash uninstall
```
* Removes all installed files, logs, and configurations  

## 📜 Available Scripts
|   Alias   |   Description |  
===
|   pes   |   Project Exposure Scan - Checks & fixes exposed files |  
|   uninstall   |   Uninstall Shield-Bash - Removes all components |  

For help with any script use:  
```bash
shield-bash [script-alias] -h
```

### Logging
Shield-Bash logs all security events to `/var/log/shield-bash/*.log` files, specific to each security tool to ensure compatibility with log monitoring systems. You can review the newest log entries using the following command:
```bash	
tail -f /var/log/shield-bash/*.log
```

## ⚙️ Configuration
All security rules are stored in configuration files located in `/etc/shield-bash/*.conf`. You can customize these files to fit your specific security needs. Each configuration file contains a set of instructions in the initial comment block, explaining
the structure of the configuration file and providing examples on how to add new rules.

## 🕐 Automation
You can run Shield-Bash tools as a cron job to automatically scan your system for security vulnerabilities and fix them.
For example, to run the `pes` tool every 5 minutes, you can add the following commandto your crontab:
`*/5 * * * * /usr/local/bin/shield-bash pes --silent`

## 🛠 Development & Contribution

We welcome contributions! 🚀 If you want to improve Shield-Bash, follow these steps:  

* Fork the repository
* Clone your fork locally:
```bash	
git clone https://github.com/KBirenheide/ShieldBash
cd shield-bash
```
* Create a new feature branch:
```bash
git checkout -b my-feature
```
* Make your changes & commit:
```bash
git add .
git commit -m "Add my new feature"

Push & Create a Pull Request:

git push origin my-feature
```
* Submit a PR through GitHub