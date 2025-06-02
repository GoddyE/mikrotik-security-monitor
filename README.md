# 🔐 MikroTik Security Monitor

![Python](https://img.shields.io/badge/python-v3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Real-time monitoring tool for MikroTik routers that detects:
- Failed login attempts
- Brute force attacks
- Suspicious activity patterns

## 📥 Installation

git clone https://github.com/GoddyE/mikrotik-security-monitor.git
cd mikrotik-security-monitor
pip install -r requirements.txt


## ⚙️ Configuration
1. Edit `mikrotik_config.json`:

{
  "host": "your_router_ip",
  "username": "api_user",
  "password": "secure_password",
  "port": 8728
}



## 🚦 Usage
### Manual Run

`python main.py` (run in the terminal)


## 🤝 Contributing
Pull requests welcome! For major changes, please open an issue first.

## 📜 License
MIT

## 🔧 Troubleshooting
- **API Connection Failed**: Verify API service is enabled on MikroTik
- **No Logs Found**: Check user has sufficient permissions
- **CSV Errors**: Delete existing `failed_logins_master.csv` to regenerate