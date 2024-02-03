package main

import (
	"fmt"
	"database/sql"
 	"log"
	"strings"
	_ "github.com/mattn/go-sqlite3"
	"github.com/go-telegram-bot-api/telegram-bot-api"
	"regexp"
	"errors"
	"time"
	"crypto/rand"
	"github.com/dgrijalva/jwt-go"
	ptime "github.com/yaa110/go-persian-calendar"
	"os"
	"bufio"
        "github.com/google/uuid"
	"math/big"
    "sync"


)

var usersMutex sync.Mutex


// UserSession represents a user session information
type UserSession struct {
	UserID        int
	SessionToken  string
}

func main() {
	botToken := "6915966681:AAH1iORadFeTgoaQLMMkZvqEDbUwJ_T60wU"

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Panic(err)
	}

	// Set up an update configuration
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	// Get updates from the bot
	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		log.Panic(err)
	}

    // Your news message
//    newsMessage := "Hello, dear users! This is an important announcement."

    // Send news to logged-in users
//    sendNewsToLoggedInUsers(bot, newsMessage)


	// Process incoming updates
	for update := range updates {
	    if update.CallbackQuery != nil {
	        // Handle callback queries
	        callbackData := update.CallbackQuery.Data
	        handleInlineButtonPress(bot, update.CallbackQuery.Message, callbackData)
        ShowMenuUpdate(bot, update.CallbackQuery.Message)

	    } else if update.Message != nil {
	        if update.Message.IsCommand() {
	            command := update.Message.Command()
	            switch command {
	            case "login":
	                // Handle the "/login" command
	                params := strings.SplitN(update.Message.Text, " ", 2)
	                if len(params) != 2 {
	                    response := "فرمت دستور ورود اشتباه است!\nلطفا دستور ورود را با فرمت زیر وارد نمایید:\n `/login <v2ray_config>`"
	                    sendMessage(bot, update.Message.Chat.ID, response)
	                    continue
	                }

	                v2rayConfig := params[1]
	                email, id, err := extractCredentialsFromV2rayConfig(v2rayConfig)
	                if err != nil {
	                    response := "کانفیگ وارد شده نامعتبر است!\nلطفا یک کانفیگ معتبر را وارد نمایید!"
	                    sendMessage(bot, update.Message.Chat.ID, response)
	                    continue
	                }

	                userID := update.Message.From.ID
	                if UserLogin(email, id, userID) {
	                    response := "به پنل کاربری خوش آمدید!"
	                    sendMessage(bot, update.Message.Chat.ID, response)
	                    handleCommand(bot, update.Message)
	                } else {
	                    response := "اطلاعات کانفیگ ورودی اشتباه است!"
	                    sendMessage(bot, update.Message.Chat.ID, response)
	                }
	            default:
	                handleCommand(bot, update.Message)
	            }
	        }
	    }
	}

}

func UserLogin(email, id string, userID int) bool {
	// Connect to the database
	db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
	if err != nil {
		log.Println("Error opening database:", err)
		return false
	}
	defer db.Close()

	// Query the database to check the login credentials
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM Clients_email_id WHERE email = ? AND id = ?", email, id).Scan(&count)
	if err != nil {
		fmt.Println("Error querying database:", err)
		return false
	}

	// If email and ID do not exist, recheck after updating the database
	if count == 0 {
		// Run the data transfer/update code
		sourcePath := "/etc/x-ui/x-ui.db"
		destPath := "/usr/local/web_panel/NovaNex.db"
		if err := transferData(sourcePath, destPath); err != nil {
			fmt.Println("Error updating database:", err)
		}

		// Recheck login credentials
		err = db.QueryRow("SELECT COUNT(*) FROM Clients_email_id WHERE email = ? AND id = ?", email, id).Scan(&count)
		if err != nil {
			fmt.Println("Error rechecking database:", err)
			return false
		}
	        if count == 0 {
		return false
		}
	}

	// Generate a session token (replace with your actual token generation logic)
	sessionToken, err_token := generateSessionToken()
        if err_token != nil {
                log.Println("Error generation session token:", err_token)
                return false
        }


	// Store the session information in the database
	_, err = db.Exec("INSERT INTO user_session (user_id, email, token) VALUES (?, ?, ?)", userID, email, sessionToken)
	if err != nil {
		log.Println("Error storing session information:", err)
		return false
	}

	return true
}

func transferData(sourcePath, destPath string) error {
	// Open source database
	sourceDB, err := sql.Open("sqlite3", sourcePath)
	if err != nil {
		return err
	}
	defer sourceDB.Close()

	// Open destination database
	destDB, err := sql.Open("sqlite3", destPath)
	if err != nil {
		return err
	}
	defer destDB.Close()

	// Clear existing data in the destination database
	_, err = destDB.Exec("DELETE FROM Clients_email_id;")
	if err != nil {
		return err
	}

	// Query data from the source database
	rows, err := sourceDB.Query("SELECT json_extract(value, '$.email') AS email, json_extract(value, '$.id') AS client_id FROM inbounds, json_each(settings, '$.clients');")
	if err != nil {
		return err
	}
	defer rows.Close()

	// Prepare insert statement for the destination database
	insertStmt, err := destDB.Prepare("INSERT INTO Clients_email_id (email, id) VALUES (?, ?);")
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	// Iterate over rows and insert into the destination database
	for rows.Next() {
		var email, clientID string
		if err := rows.Scan(&email, &clientID); err != nil {
			return err
		}

		// Insert into the destination database
		_, err := insertStmt.Exec(email, clientID)
		if err != nil {
			return err
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	fmt.Println("Data transfer completed successfully!")
	return nil
}

// Function to extract email and id from v2ray config
func extractCredentialsFromV2rayConfig(config string) (string, string, error) {
	// Extract email and id using regular expressions or string manipulation
	// Replace the following lines with your implementation
	// Example: Using regular expression
	re := regexp.MustCompile(`#([a-zA-Z0-9]+)$`)
	matches := re.FindStringSubmatch(config)
	if len(matches) != 2 {
		return "", "", errors.New("فرمت کانفیگ v2ray وارد شده صحیح نیست!")
	}
	email := matches[1]

	re = regexp.MustCompile(`://([a-fA-F0-9\-]+)@`)
	matches = re.FindStringSubmatch(config)
	if len(matches) != 2 {
		return "", "", errors.New("فرمت کانفیگ v2ray وارد شده صحیح نیست!")
	}
	id := matches[1]

	return email, id, nil
}

// Add a function to generate a random session token
func generateSessionToken() (string, error) {
	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(10 * time.Minute).Unix() // Token expiration time
	claims["iat"] = time.Now().Unix()                      // Token issue time

	// Generate a random 256-bit (32-byte) secret key for signing the token
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	// Sign the token with the secret key
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	// Return the generated token
	return tokenString, nil
}

// Function to check user's login status based on userID
func checkUserLogin(userID int) bool {
	// Replace the database connection details with your actual database connection
	db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
	if err != nil {
		log.Println("Error opening database:", err)
		return false
	}
	defer db.Close()

	// Query the database to check if the user is logged in
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM user_session WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		log.Println("Error querying database:", err)
		return false
	}

	return count > 0
}


func handleLoggedInCommand(bot *tgbotapi.BotAPI, message *tgbotapi.Message) string {
    // Create an inline keyboard
    keyboard := tgbotapi.NewInlineKeyboardMarkup(
        tgbotapi.NewInlineKeyboardRow(
            tgbotapi.NewInlineKeyboardButtonData("وضعیت کانفیگ", "/configinfo"),
            tgbotapi.NewInlineKeyboardButtonData("کانفیگ جدید", "/newconfig"),
        ),
        tgbotapi.NewInlineKeyboardRow(
            tgbotapi.NewInlineKeyboardButtonData("راهنما", "/guide"),
        ),
        tgbotapi.NewInlineKeyboardRow(
            tgbotapi.NewInlineKeyboardButtonData("خروج", "/logout"),
        ),
    )

    respone := fmt.Sprintf("به %s خوش آمدید!                                        \n"+
"این پنل اطلاعات مربوط به اشتراک شما را در اختیارتان قرار می دهد.\n"+
"لطفا یکی از گزینه های زیر را انتخاب نمایید:", bot.Self.UserName)
    // Set the reply markup with the inline keyboard
    replyMarkup := tgbotapi.NewMessage(message.Chat.ID, respone)
    replyMarkup.ReplyMarkup = keyboard

    // Send the message with the inline keyboard
    _, err := bot.Send(replyMarkup)
    if err != nil {
        log.Println("Error sending message:", err)
    }

    return ""
}


func handleNotLoggedInCommand(bot *tgbotapi.BotAPI, message *tgbotapi.Message) string {
    var responseText string

    // Create an inline keyboard
    keyboard := tgbotapi.NewInlineKeyboardMarkup(
        tgbotapi.NewInlineKeyboardRow(
            tgbotapi.NewInlineKeyboardButtonData("ورود", "/login"),
            tgbotapi.NewInlineKeyboardButtonData("🛍️ خرید کانفیگ", "/buyconfig"),
        ),
    )

    respone := fmt.Sprintf("به %s خوش آمدید!                                        \nلطفا یکی از گزینه های زیر را انتخاب نمایید:", bot.Self.UserName)
    // Set the reply markup with the inline keyboard
    replyMarkup := tgbotapi.NewMessage(message.Chat.ID, respone)
    replyMarkup.ReplyMarkup = keyboard

    // Send the message with the inline keyboard
    _, err := bot.Send(replyMarkup)
    if err != nil {
        log.Println("Error sending message:", err)
    }

    return responseText
}

func handleCommand(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
    // Check if the user is logged in
    isLoggedIn := checkUserLogin(message.From.ID)

    // Determine which menu to display based on login status
    if isLoggedIn {
        handleLoggedInCommand(bot, message)
    } else {
        handleNotLoggedInCommand(bot, message)
    }
}


// Function to handle user logout
func logout(userID int) bool {
    // Replace the database connection details with your actual database connection
    db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
    if err != nil {
        log.Println("Error opening database:", err)
        return false
    }
    defer db.Close()

    // Delete the session information from the database
    _, err = db.Exec("DELETE FROM user_session WHERE user_id = ?", userID)
    if err != nil {
        log.Println("Error deleting session information:", err)
        return false
    }

    return true
}


// Function to get user's email from the database
func getUserEmail(userID int) string {
    // Replace the database connection details with your actual database connection
    db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
    if err != nil {
        log.Println("Error opening database:", err)
        return ""
    }
    defer db.Close()

    var email string
    err = db.QueryRow("SELECT email FROM user_session WHERE user_id = ?", userID).Scan(&email)
    if err != nil {
        log.Println("Error querying database:", err)
        return ""
    }

    return email
}

// Function to get client information from the database
func getClientInfo(email string) (*ClientTraffic, int) {
    // Replace the database connection details with your actual database connection
    db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
    if err != nil {
        log.Println("Error opening database:", err)
        return nil, 0
    }
    defer db.Close()

    var clientTraffic ClientTraffic
    var remainingDays int

    err = db.QueryRow("SELECT up, down, expiry_time, total FROM client_traffics WHERE email = ?", email).Scan(&clientTraffic.Up, &clientTraffic.Down, &clientTraffic.ExpiryTime, &clientTraffic.Total)
    if err != nil {
        log.Println("Error querying database:", err)
        return nil, 0
    }

    // Calculate remaining days (replace with your logic)
    remainingDays = calculateRemainingDays(clientTraffic.ExpiryTime)

    return &clientTraffic, remainingDays
}

// Struct to represent client traffic information
type ClientTraffic struct {
    Up         int
    Down       int
    ExpiryTime int
    Total      int
}

// Function to calculate remaining days based on expiry time (replace with your logic)
func calculateRemainingDays(expiryTime int) int {
    // Implement your logic to calculate remaining days
    // This is just a placeholder, replace it with the actual calculation
    remainingDays := (expiryTime/1000 - int(time.Now().Unix())) / (24 * 3600)
    if remainingDays < 0 {
        return 0
    }
    return remainingDays
}

func copyClientTraffics() error {
	// Open source database (/etc/x-ui/x-ui.db)
	sourceDB, err := sql.Open("sqlite3", "/etc/x-ui/x-ui.db")
	if err != nil {
		return err
	}
	defer sourceDB.Close()

	// Open destination database (/usr/local/web_local/NovaNex.db)
	destDB, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
	if err != nil {
		return err
	}
	defer destDB.Close()

	// Read data from source table
	rows, err := sourceDB.Query("SELECT * FROM client_traffics")
	if err != nil {
		return err
	}
	defer rows.Close()

	// Prepare the destination table
	_, err = destDB.Exec(`
		CREATE TABLE IF NOT EXISTS client_traffics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			inbound_id INTEGER,
			enable NUMERIC,
			email TEXT UNIQUE,
			up INTEGER,
			down INTEGER,
			expiry_time INTEGER,
			total INTEGER,
			reset INTEGER DEFAULT 0,
			CONSTRAINT fk_inbounds_client_stats FOREIGN KEY (inbound_id) REFERENCES inbounds(id)
		);
	`)
	if err != nil {
		return err
	}

	// Insert or update data in destination table
	for rows.Next() {
		var id, inboundID, enable, up, down, expiryTime, total, reset int
		var email string
		err := rows.Scan(&id, &inboundID, &enable, &email, &up, &down, &expiryTime, &total, &reset)
		if err != nil {
			return err
		}

		// Try to update the record in case the user already exists
		_, err = destDB.Exec("UPDATE client_traffics SET inbound_id=?, enable=?, up=?, down=?, expiry_time=?, total=?, reset=? WHERE email=?",
			inboundID, enable, up, down, expiryTime, total, reset, email)

		if err != nil {
			// If the user doesn't exist in the destination table, insert a new record
			_, err := destDB.Exec("INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
				inboundID, enable, email, up, down, expiryTime, total, reset)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Function to format time in Persian (Farsi)
func formatTimeInPersian(timestamp int) string {
    // Convert timestamp from milliseconds to seconds
    timestampSeconds := int64(timestamp / 1000)

    // Create a time.Time instance
    expirationTime := time.Unix(timestampSeconds, 0)

    // Convert to Persian (Shamsi) date
    persianDate := ptime.New(expirationTime)

    // Format the Shamsi date
    //formattedTime := fmt.Sprintf("%d/%s/%d", persianDate.Year(), persianDate.Month().String(), persianDate.Day())

formattedTime := fmt.Sprintf("تاریخ:%d/%s/%d ساعت:  %02d:%02d:%02d",
    persianDate.Year(),
    persianDate.Month().String(),
    persianDate.Day(),
    (persianDate.Hour()+3+(persianDate.Minute()+30)/60)%24,
    (persianDate.Minute()+30)%60,
    persianDate.Second(),
)


    return formattedTime
}

func generateV2RayConfig(email string) (string, error) {
    // Read QR code data from the file and replace placeholders
    qrCodeData, err := readQRCodeData("/usr/local/web_panel/qrcodefile.txt", email)
    if err != nil {
        return "", fmt.Errorf("error reading QR code data: %v", err)
    }

    return qrCodeData, nil
}

// Function to read QR code data from a file and replace placeholders
func readQRCodeData(filename, username string) (string, error) {
    content, err := os.ReadFile(filename)
    if err != nil {
        return "", fmt.Errorf("error reading file %s: %v", filename, err)
    }

    // Replace placeholders with actual values
    data := strings.ReplaceAll(string(content), "{username}", username)

    // Find the user password from temp_up.txt
    password, err := findUserPassword(username)
    if err != nil {
        return "", fmt.Errorf("error finding user password: %v", err)
    }

    // Check if the password looks like a UUID
    isUUID := isValidUUID(password)

    // Set the protocol based on the password format
    protocol := "trojan"
    if isUUID {
        protocol = "vless"
    }

    data = strings.ReplaceAll(data, "{password}", password)
    data = strings.ReplaceAll(data, "{protocol}", protocol)

    // Check if {user-agent} is present in data
    if strings.Contains(data, "{user-agent}") {
        // Replace {user-agent} with a random line from user-agent.txt
        userAgent, err := getRandomUserAgent("/usr/local/web_panel/user-agent.txt")
        if err != nil {
            return "", fmt.Errorf("error getting random user agent: %v", err)
        }
        data = strings.ReplaceAll(data, "{user-agent}", userAgent)
    }

    return data, nil
}

// Rest of the provided functions remain unchanged
// ...


// Function to check if a string is a valid UUID
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// Function to get a random line from a file
func getRandomUserAgent(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Count the number of lines in the file
	lineCount, err := countLines(file)
	if err != nil {
		return "", err
	}

	// Generate a random number within the range [1, lineCount]
	randNum, err := rand.Int(rand.Reader, big.NewInt(int64(lineCount)))
	if err != nil {
	    return "", err
	}
	randomLineNumber := int(randNum.Int64()) + 1

	// Rewind the file to the beginning
	file.Seek(0, 0)

	// Read the file until the random line is reached
	scanner := bufio.NewScanner(file)
	currentLineNumber := 0
	var userAgent string

	for scanner.Scan() {
		currentLineNumber++
		if currentLineNumber == randomLineNumber {
			userAgent = scanner.Text()
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return userAgent, nil
}

// Function to count lines in a file
func countLines(file *os.File) (int, error) {
	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() {
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return lineCount, nil
}


// Function to find user password from NovaNex.db
func findUserPassword(username string) (string, error) {
// Open a connection to the SQLite database
db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
if err != nil {
    log.Fatal(err)
}
defer db.Close()
    usersMutex.Lock()
    defer usersMutex.Unlock()

    // Query the database to find the password for the given username
    query := "SELECT id FROM Clients_email_id WHERE email = ?"
    row := db.QueryRow(query, username)

    var password string
    if err := row.Scan(&password); err != nil {
        // Handle the error (e.g., user not found)
        log.Println("Error finding user password:", err)
        return "DefaultPassword", err
    }

    return password, nil
}


func handleInlineButtonPress(bot *tgbotapi.BotAPI, message *tgbotapi.Message, callbackData string) {
    switch callbackData {
    case "/configinfo":
        // Get client information based on email
        userID := int(message.Chat.ID)
        email := getUserEmail(userID)
        if email == "" {
            response := "متاسفانه نام کاربری شما در دیتابیس یافت نشد. برای حل مشکل دوباره به بات وارد شوید!"
            sendMessage(bot, message.Chat.ID, response)
	    break
        }
	copyClientTraffics();

        traffics, remainingDays := getClientInfo(email)
        response := fmt.Sprintf("حجم کل ترافیک: %d GB\nمیزان مصرف کل شما: %d MB\n(آپلود: %d MB, دانلود: %d MB)\n"+
			"روزهای باقی مانده از اشتراک شما: %d \nتاریخ انقضاء اشتراک شما: \n %s",
			 traffics.Total/(1024*1024*1024),(traffics.Up+traffics.Down)/(1024*1024),
			 traffics.Up/(1024*1024), traffics.Down/(1024*1024), remainingDays,
			 formatTimeInPersian(traffics.ExpiryTime))
        sendMessage(bot, message.Chat.ID, response)
    case "/newconfig":
	        // Generate V2Ray configuration for the user
	        userID := int(message.Chat.ID)
	        email := getUserEmail(userID)
	        if email == "" {
	            response := "متاسفانه نام کاربری شما در دیتابیس یافت نشد. برای حل مشکل دوباره به بات وارد شوید!"
	            sendMessage(bot, message.Chat.ID, response)
		    break
	        }
	        v2rayConfig, err := generateV2RayConfig(email)
	        if err != nil {
	            response := "خطا در ایجاد کانفیگ جدید!"
	            sendMessage(bot, message.Chat.ID, response)
                    break
	        }
	        // Send the V2Ray configuration to the user
	        msg := tgbotapi.NewMessage(message.Chat.ID, v2rayConfig)
	        if _, err := bot.Send(msg); err != nil {
	            log.Println("Error sending V2Ray configuration:", err)
	            response := "خطا در ارسال کانفیگ به کاربر!"
	            sendMessage(bot, message.Chat.ID, response)
                    break
	        }
        response := "کانفیگ جدید را کپی کرده و به نرم افزار وارد نمایید!\nدر صورت نیاز به راهنمایی از بخش *راهنما* استفاده نمایید."
        sendMessage(bot, message.Chat.ID, response)
    case "/guide":
	        // Send the guide.pdf file to the user
	        guidePath := "/usr/local/web_panel/templates/guide.pdf"
	        guideFile := tgbotapi.NewDocumentUpload(message.Chat.ID, guidePath)
	        _, err := bot.Send(guideFile)
	        if err != nil {
	            log.Println("Error sending guide:", err)
	            response := "متاسفانه مشکلی در ارسال راهنما به وجود آمده است. لطفاً دوباره تلاش کنید."
	            sendMessage(bot, message.Chat.ID, response)
                    break
	        }
        response := "فایل راهنما برای شما ارسال گردید. با مطالعه این راهنما مشکل شما حل خواهد شد!"
        sendMessage(bot, message.Chat.ID, response)
    case "/logout":
	        // Handle logout
	        userID := int(message.Chat.ID)
	        if logout(userID) {
	            response := "شما از سامانه خارج شدید!\nبدرود👋"
	            sendMessage(bot, message.Chat.ID, response)
	        } else {
        	    response := "متاسفانه خروج شما انجام نشد. لطفاً دوباره تلاش کنید."
	            sendMessage(bot, message.Chat.ID, response)
	        }

    case "/login":
        response := "برای ورود کانفیگ خود را بعد از /login ارسال نمایید!\nفرمت ارسال دستور ورود:\n/login V2ray_Config"
        sendMessage(bot, message.Chat.ID, response)
    case "/buyconfig":
        // Handle the "/buyconfig" button press
        response := "You pressed the /buyconfig button!"
        sendMessage(bot, message.Chat.ID, response)
    }
}

func sendMessage(bot *tgbotapi.BotAPI, chatID int64, text string) {
    msg := tgbotapi.NewMessage(chatID, text)
    _, err := bot.Send(msg)
    if err != nil {
        log.Println("Error sending message:", err)
    }
}

func sendNewsToLoggedInUsers(bot *tgbotapi.BotAPI, newsMessage string) {
    // Replace the database connection details with your actual database connection
    db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
    if err != nil {
        log.Println("Error opening database:", err)
        return
    }
    defer db.Close()

    // Query the database to get a list of logged-in users
    rows, err := db.Query("SELECT user_id FROM user_session")
    if err != nil {
        log.Println("Error querying database:", err)
        return
    }
    defer rows.Close()

    // Iterate through the rows and send news to each logged-in user
    for rows.Next() {
        var userID int64
        if err := rows.Scan(&userID); err != nil {
            log.Println("Error scanning row:", err)
            continue
        }

        // Construct a message and send it to the user
        newsMessage := tgbotapi.NewMessage(userID, newsMessage)
        _, err := bot.Send(newsMessage)
        if err != nil {
            log.Println("Error sending news to user:", err)
        }
    }

    if err := rows.Err(); err != nil {
        log.Println("Error iterating through rows:", err)
    }
}


func ShowMenuUpdate(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
    // Check if the user is logged in
    isLoggedIn := checkUserLogin(int(message.Chat.ID))

    // Determine which menu to display based on login status
    if isLoggedIn {
        handleLoggedInCommand(bot, message)
    } else {
        handleNotLoggedInCommand(bot, message)
    }
}
