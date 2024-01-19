#!/bin/bash

timestamp_file="/usr/local/web_panel/last_update_timestamp.txt"

current_time=$(date +%s)

if [ -e "$timestamp_file" ]; then
    last_update_time=$(cat "$timestamp_file")
    time_difference=$((current_time - last_update_time))
    if [ "$time_difference" -ge 60 ]; then
	sqlite3 /etc/x-ui/x-ui.db "SELECT * FROM client_traffics;" > info_temp.txt;
        echo "$current_time" > "$timestamp_file"
    fi
else
    touch "$timestamp_file"
    sqlite3 /etc/x-ui/x-ui.db "SELECT * FROM client_traffics;" > info_temp.txt;
    echo "$current_time" > "$timestamp_file"
fi

