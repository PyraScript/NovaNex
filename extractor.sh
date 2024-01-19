#!/bin/bash
# Run SQLite commands and save results to temp files
sqlite3 /etc/x-ui/x-ui.db "SELECT * FROM inbounds;" > temp_up.txt;
grep -E 'email|password|id' temp_up.txt > temp_up_filtered.txt;
cp temp_up_filtered.txt temp_up.txt;
rm temp_up_filtered.txt;
awk -F'[:,]' '{
    if ($1 ~ /"email"/) {
        email = $2;
    } else if ($1 ~ /"password"/) {
        password = $2;
    } else if ($1 ~ /"id"/) {
        id = $2;
    }
    if (email && (password || id)) {
        if (password) {
            pairs[++count] = email " " password;
        } else if (id) {
            pairs[++count] = email " " id;
        }
        email = "";
        password = "";
        id = "";
    }
} 
END {
    for (i = 1; i <= count; i++) {
        print pairs[i];
    }
}' temp_up.txt > temp_up_reformatted.txt
cp temp_up_reformatted.txt temp_up.txt;
rm temp_up_reformatted.txt;

