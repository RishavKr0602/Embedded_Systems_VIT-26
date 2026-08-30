# 1. Set up ESP-IDF environment
cd ~/esp-idf
source export.sh

# 2. Build and flash
cd ~/ecc_secure_boot/esp32_secure
idf.py set-target esp32
idf.py build
idf.py flash
idf.py monitor