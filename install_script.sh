#!/bin/bash

# ANSI color codes
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

hashPassword() {
    # Use bcrypt for hashing passwords
    hashedPassword=$(echo -n "$1" | bcrypt-cli -c 10)
    echo "$hashedPassword"
}

install_web_panel() {
    echo -e "${BLUE}Installing Go and web panel...${NC}"

    # Create a directory for the web panel
    sudo mkdir -p /usr/local/web_panel

    # Update package lists
    sudo apt-get update

    # Install Go using apt-get
    sudo apt-get install -y golang gccgo sqlite3 bcrypt-cli

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

    # Initialize the SQLite database with the admins table
    sqlite3 NovaNex.db <<EOF
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );
EOF

    # Generate random username and password
    randomUsername="admin@$(openssl rand -hex 4)"
    randomPassword=$(openssl rand -hex 8)
    hashedPassword=$(hashPassword "$randomPassword")

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
