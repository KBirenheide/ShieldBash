# Contributing to Shield-Bash 🚀

Thank you for your interest in contributing to **Shield-Bash**! 🔒 This document outlines our contribution process to keep development smooth and efficient.

---

## 📌 Guidelines for Contribution

### 1️⃣ **Getting Started**
Before contributing, **fork the repository** to your GitHub account:

```bash
git clone https://github.com/KBirenheide/ShieldBash
cd ShieldBash
```

### 2️⃣ **Understanding the Structure**

Shield-Bash consists of:  
* Scripts (/var/lib/shield-bash/) → Core automation tools
* Configurations (/etc/shield-bash/) → Security rules
* Logs (/var/log/shield-bash/) → Exposure reports
* Command Framework (shield-bash.sh) → CLI interface

### 3️⃣ **Creating a New Feature or Fix**

Before making changes, create a new branch:  
```bash
git checkout -b feature-branch
```
Make your modifications and commit them with a meaningful message:  
```bash
git add .
git commit -m "Add feature: Auto-update check for shield-bash"
```

### 4️⃣ **Code Style & Best Practices**

✔ Keep it simple – Bash scripts should be readable and maintainable  
✔ Use ANSI variables – For colorized output, use predefined variables  
✔ Follow Linux conventions – Place files in appropriate system directories  
✔ Test your changes – Ensure scripts function correctly before submitting  
✔ Include/Update help messages – If you work on a shield-bash tool, ensure
   the script has a working and up-to-date help message available with the 
   -h/--help flag 

### 5️⃣ **Submitting a Pull Request**

Once your changes are ready, push your branch to GitHub:  
```bash
git push origin feature-branch
```
Then, open a Pull Request (PR) on GitHub:  
* Provide a clear title (Fix: Incorrect Permission Check)
* Include a description of what was changed
* Reference any related issues (if applicable)

After submitting your PR, the I'll review it and provide feedback.

### 6️⃣ **Bug Reports & Feature Requests**

If you find a bug, please open an issue:  
* Describe the problem
* Include steps to reproduce
* Provide any error messages

If you have a feature idea, suggest it in an issue first!  

### 7️⃣ **Testing Your Changes**

Before submitting a PR, test your changes locally.    
```bash
shield-bash [your-tool] --dry-run -v
```
Ensure: 
✔ The script executes without errors  
✔ The logs reflect expected outputs  
✔ Silent mode works (--silent)  

## 📜 License

By contributing to Shield-Bash, you agree that your changes will be licensed under the MIT License.  
🙌 Thank You!  

I appreciate your contribution to Shield-Bash! 🎉  
Your help makes security automation better for everyone.  

🚀 Happy Hardening!