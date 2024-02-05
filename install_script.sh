#!/bin/bash

# ANSI color codes
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

install_web_panel() {
    echo -e "${BLUE}Installing Go and web panel...${NC}"

    # Create a directory for the web panel
    sudo mkdir -p /usr/local/web_panel

    # Update package lists
    sudo apt-get update

    # Install Go using apt-get
    sudo apt-get install -y golang gccgo sqlite3 snapd

    # Clone the repository (replace with your repository URL)
    sudo git clone https://github.com/PyraScript/NovaNex.git /usr/local/web_panel

    # Change to the web panel directory
    cd /usr/local/web_panel

    # Initialize a new Go module
    go mod init web_panel
    go mod tidy
    chmod +x extractor.sh
    chmod +x info_extractor.sh
    ./extractor.sh
    ./info_extractor.sh

    touch telegrambot/config.env
    chmod 600 telegrambot/config.env

# Initialize the SQLite database with the admins table
sqlite3 NovaNex.db <<'EOF'
CREATE TABLE IF NOT EXISTS admins (
    username TEXT NOT NULL,
    password TEXT NOT NULL
);
EOF

# Initialize the SQLite database with the Clients_email_id table
sqlite3 NovaNex.db <<'EOF'
CREATE TABLE IF NOT EXISTS Clients_email_id (
    email TEXT NOT NULL,
    id TEXT NOT NULL
);
EOF

# Initialize the SQLite database with the user_session table
sqlite3 NovaNex.db <<'EOF'
CREATE TABLE IF NOT EXISTS user_session (
    user_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    token TEXT
);
EOF

# Initialize the SQLite database with the user_session table
sqlite3 NovaNex.db <<'EOF'
CREATE TABLE IF NOT EXISTS `client_traffics` (`id` integer PRIMARY KEY AUTOINCREMENT,`inbound_id` integer,`enable` numeric,`email` text UNIQUE,`up` integer,`down` integer,`expiry_time` integer,`total` integer,`reset` integer DEFAULT 0,CONSTRAINT `fk_inbounds_client_stats` FOREIGN KEY (`inbound_id`) REFERENCES `inbounds`(`id`));
EOF

sqlite3 NovaNex.db <<'EOF'
CREATE TABLE IF NOT EXISTS texts_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    text TEXT
);
INSERT INTO texts_table (key, text) VALUES
    ('welcome_logged_in', 'به %s خوش آمدید!'),
    ('welcome_not_logged_in', 'درود👋\nبه %s خوش آمدید!'),
    ('servers', 'درحال حاضر سرور های زیر موجود هستند:'),
    ('bot_status', 'false');
EOF

snap install bcrypt-tool

# Generate random username and password
randomUsername="admin@$(openssl rand -hex 4)"
randomPassword=$(openssl rand -hex 8)
hashedPassword=$(bcrypt-tool hash "$randomPassword")

# Store random username and hashed password in the database
sqlite3 NovaNex.db <<EOF
INSERT INTO admins (username, password) VALUES ('$randomUsername', '$hashedPassword');
EOF

    # Display generated username and password to the administrator
    echo -e "${GREEN}Generated Admin Credentials:${NC}"
    echo -e "Username: ${YELLOW}$randomUsername${NC}"
    echo -e "Password: ${YELLOW}$randomPassword${NC}"

    # Download dependencies using go get
    go get -d ./...

    # Build the Go program
    go build -o web_panel . > output.out 2>&1

    # Create a systemd service file
    sudo tee /etc/systemd/system/web_panel.service > /dev/null <<EOL
[Unit]
Description=Web Panel Service
After=network.target

[Service]
User=root
ExecStart=/usr/local/web_panel/web_panel
WorkingDirectory=/usr/local/web_panel
Restart=on-failure
RestartSec=5
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOL

    # Reload systemd
    sudo systemctl daemon-reload

    # Start the service
    sudo systemctl start web_panel.service
    sudo systemctl enable web_panel.service

cd /usr/local/web_panel/telegrambot

# Build the Go program for the telegrambot
go build -o telegrambot . > telegrambot_output.out 2>&1

# Create a systemd service file for the telegrambot
sudo tee /etc/systemd/system/telegrambot.service > /dev/null <<EOL
[Unit]
Description=Telegram Bot Service
After=network.target

[Service]
User=root
ExecStart=/usr/local/web_panel/telegrambot/telegrambot
WorkingDirectory=/usr/local/web_panel/telegrambot
Restart=on-failure
RestartSec=5
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOL

    # Reload systemd
    sudo systemctl daemon-reload

    # Assuming 'novanex' is an executable file
    sudo mv /usr/local/web_panel/novanex /usr/local/bin/novanex
    sudo chmod +x /usr/local/bin/novanex
    sudo rm /usr/local/web_panel/novanex
    
    echo -e "${GREEN}Telegram Bot service created.${NC}"

    echo -e "${GREEN}Go and web panel installed. Service created.${NC}"
}

start_web_panel() {
    # Add start steps here
    echo -e "${GREEN}Starting web panel...${NC}"
    sudo systemctl start web_panel.service
    echo -e "${GREEN}Web panel started.${NC}"
}

restart_web_panel() {
    # Add restart steps here
    echo -e "${YELLOW}Restarting web panel...${NC}"
    pkill -f "main"
    sudo systemctl restart web_panel.service
    echo -e "${YELLOW}Web panel restarted.${NC}"
}

stop_web_panel() {
    # Add stop steps here
    echo -e "${RED}Stopping web panel...${NC}"
    sudo systemctl stop web_panel.service
    echo -e "${RED}Web panel stopped.${NC}"
}

check_status() {
    echo -e "${CYAN}Checking status of web panel...${NC}"
    sudo systemctl status web_panel.service
}

# Main menu
while true; do
    echo -e "${BLUE}Web Panel Control Panel${NC}"
    echo -e "1. ${YELLOW}Install Web Panel${NC}"
    echo -e "2. ${GREEN}Start Web Panel${NC}"
    echo -e "3. ${YELLOW}Restart Web Panel${NC}"
    echo -e "4. ${RED}Stop Web Panel${NC}"
    echo -e "5. ${CYAN}Check Status${NC}"
    echo -e "6. ${BLUE}Exit${NC}"

    read -p "Enter the number of the desired option: " choice

    case $choice in
        1)
            install_web_panel
            ;;
        2)
            start_web_panel
            ;;
        3)
            restart_web_panel
            ;;
        4)
            stop_web_panel
            ;;
        5)
            check_status
            ;;
        6)
            echo -e "${BLUE}Exiting control panel. Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please enter a valid number.${NC}"
            ;;
    esac
done
