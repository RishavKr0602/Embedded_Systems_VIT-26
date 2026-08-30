# 1. Boot Raspberry Pi and complete OS setup
sudo raspi-config
# Set: Locale, Timezone, Enable SSH, I2C, SPI, UART

# 2. Update system
sudo apt update && sudo apt full-upgrade -y

# 3. Install essential packages
sudo apt install -y python3 python3-pip python3-venv openssl libssl-dev git

# 4. Install Python cryptographic libraries
sudo pip3 install cryptography pycryptodome rpi.gpio smbus2 pillow

# 5. Create project directory
mkdir -p ~/ecc_secure_boot
cd ~/ecc_secure_boot

# 6. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 7. Install additional dependencies
pip install ecdsa pycryptodome secrets