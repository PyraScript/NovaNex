package main

import (
	"fmt"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"strconv"
	"crypto/rand"
	"github.com/dgrijalva/jwt-go"
	"math/big"
	"bufio"
        "github.com/google/uuid"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/disk"
        "io/ioutil"
        "encoding/json"
        "io"
        "path/filepath"
        "web_panel/telegrambot/utils"

)

// User represents a user with username and password.
type User struct {
	Username string
	Password string
}

// Add a UserSession struct to store session information
type UserSession struct {
	Username string
	Token    string
	Expire   time.Time
}

type ActiveMathProblem struct {
	MathProblem   string
	CorrectAnswer int64
	Expiration    time.Time
}

// SystemData represents the data structure for system statistics
type SystemData struct {
	CpuUsage  float64
	RamUsage  float64
	SwapUsage float64
	DiskUsage float64
}

type UpdateSettingsData struct {
    OldUsername     string `json:"oldUsername"`
    NewUsername     string `json:"newUsername"`
    OldPassword     string `json:"oldPassword"`
    NewPassword     string `json:"newPassword"`
    ConfirmPassword string `json:"confirmPassword"`
}

var activeMathProblems map[string]ActiveMathProblem

var (
	userSessions []UserSession
	sessionMutex sync.Mutex
)

var (
    u_traffic int64
    D_traffic int64
    T_traffic int64
    E_date    int64
    QRCodeData string
)

var (
	users      []User
	usersMutex sync.Mutex
)

var incorrectLoginAttempts int

var (
    logger *log.Logger
)

// Add the following global variable
var db *sql.DB

func init() {
    // Open the log file for writing. Append to the file if it exists.
    file, err := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }

    // Set up the logger to write to the file
    logger = log.New(file, "APP: ", log.Ldate|log.Ltime|log.Lshortfile)
    initBotService()

}

func main() {

	// Initialize the map
	activeMathProblems = make(map[string]ActiveMathProblem)

        // Open SQLite database connection
        var err error
        db, err = sql.Open("sqlite3", "NovaNex.db")
        if err != nil {
            log.Fatal(err)
        }
        defer db.Close()

	// Handle requests
	http.Handle("/login", http.HandlerFunc(loginHandler))
	http.Handle("/panel", http.HandlerFunc(panelHandler))
        http.Handle("/admin-panel", http.HandlerFunc(adminPanelHandler))
        http.HandleFunc("/send-config", sendConfigHandler)
        http.HandleFunc("/upload-file", uploadFileHandler)
        http.HandleFunc("/update-settings", settingsHandler)
	http.HandleFunc("/get-initial-toggle-state", getInitialToggleStateHandler)
	http.HandleFunc("/get-initial-text-state", getInitialTextStateHandler)
	http.HandleFunc("/send-toggle-state", updateToggleStateHandler)
	http.HandleFunc("/send-texts", updateTextValuesHandler)
	http.HandleFunc("/send-message", sendMessageHandler)
	http.HandleFunc("/send-bot-token", sendBotTokenHandler)

	// Serve static files (including login.html and panel.html)
	http.Handle("/", logRequest(http.FileServer(http.Dir("templates"))))

	// Add a logout handler
	http.Handle("/logout", http.HandlerFunc(logoutHandler))

	// Periodically clean up expired math problems
        go func() {
            for {
                cleanupExpiredMathProblems()
		incorrectLoginAttempts = 0
                time.Sleep(15 * time.Minute) // Adjust the frequency as needed
            }
        }()

	// Start the server
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Home page
	http.ServeFile(w, r, "templates/login.html")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

    if r.FormValue("email") != "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    if r.Method == http.MethodPost {
        // Process login form submission
        username := r.FormValue("username-1")
        password := r.FormValue("password-1")
        mathAnswer := r.FormValue("math-answer-1")
	// Convert mathAnswer to int64
	mathAnswerInt, err := strconv.ParseInt(mathAnswer, 10, 64)

	if err != nil {
	    // Handle the error, e.g., log it or return an error response
	    http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	    return
	}
	mathProblem := r.FormValue("math-problem")

        // Check the math problem answer
        if !validateMathAnswer(mathProblem, mathAnswerInt) {
            http.Error(w, "Incorrect math problem answer", http.StatusUnauthorized)
            return
        }




        // Check if it's an admin login
        if strings.HasPrefix(username, "admin@") {
            if validateAdmin(username, password) {
                // Admin login successful
                // You can perform admin-specific actions here

                // Generate a session token for admin
                sessionToken, err := generateSessionToken()
                if err != nil {
                    // Handle the error, for example, log it and return an internal server error
                    log.Println("Error generating session token:", err)
                    http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                    return
                }

                // Store the admin session information
                storeSession(username, sessionToken)

                // Set the session token as a cookie
                http.SetCookie(w, &http.Cookie{
                    Name:    "session_token",
                    Value:   sessionToken,
                    Expires: time.Now().Add(60 * time.Minute), // Set the expiration time
                })

                // Redirect to the admin panel
                http.Redirect(w, r, "/admin-panel", http.StatusSeeOther)
                return
            } else {
                // Admin login failed
                http.Error(w, "Invalid admin credentials", http.StatusUnauthorized)
                return
            }
        } else {

	if validateUser(username, password) {
		// Generate a session token
		sessionToken, err := generateSessionToken()
        if err != nil {
            // Handle the error, for example, log it and return an internal server error
            log.Println("Error generating session token:", err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

		// Store the session information
		storeSession(username, sessionToken)

		// Set the session token as a cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(10 * time.Minute), // Set the expiration time
		})

		http.Redirect(w, r, "/panel", http.StatusSeeOther)
		return
        } else {
            // Increment incorrect login attempts
            incorrectLoginAttempts++

            // Check if the threshold is exceeded
            if incorrectLoginAttempts >= 5 {
            os.Exit(1)
        }
        }}
    } else {
        fmt.Println("Not a POST request")
    }

    // Generate and set the math problem in the template data
    mathProblemStruct := generateMathProblem()
    tmpl, err := template.ParseFiles("templates/login.html")
    if err != nil {
        // Handle the error
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    data := struct {
        MathProblem string

    }{
        MathProblem: mathProblemStruct.MathProblem,
    }

    // Render the login page with the math problem
    err = tmpl.Execute(w, data)
    if err != nil {
        // Handle the error
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
}

func panelHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session token from the request (e.g., from cookies)
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		// No session token, redirect to login
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Validate the session token
	if !validateSession(sessionToken.Value) {
		// Invalid session token, redirect to login
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract the username from the session information
	username := getUsernameFromSession(sessionToken.Value)
	if username == "" {
		// Unable to retrieve the username, redirect to login
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

    // If authenticated, render the panel template
    tmpl, err := template.ParseFiles("templates/panel.html")
    if err != nil {
        // If there is an error parsing the panel template, log the error
        log.Println("Error parsing panel template:", err)
        // Return an internal server error to the client
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Execute the info_extractor.sh script to update info_temp.txt
    updateInfoScript := exec.Command("sh", "info_extractor.sh")
    updateInfoScript.Stdout = os.Stdout
    updateInfoScript.Stderr = os.Stderr
    updateErr := updateInfoScript.Run()
    if updateErr != nil {
        log.Println("Error running info_extractor.sh:", updateErr)
        // Handle the error as needed (e.g., return an internal server error)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

        loadInfo(username)
	// Read QR code data from the file and replace placeholders
	QRCodeData, err = readQRCodeData("qrcodefile.txt", username)
	if err != nil {
		log.Println("Error reading QR code data:", err)
		QRCodeData = "Default QR Code Text"
	}

    // Create a data structure to pass to the template (in this case, the traffic variables)
    data := struct {
        Username string
        U_Traffic int64
        D_Traffic int64
        T_Traffic int64
        E_Date    int64
	QRCodeData string

    }{
        Username: username,
        U_Traffic: u_traffic,
        D_Traffic: D_traffic,
        T_Traffic: T_traffic,
        E_Date:    E_date,
	QRCodeData: QRCodeData,

    }

    // Execute the template with the provided data and write the output to the response writer
    err = tmpl.Execute(w, data)
    if err != nil {
        // If there is an error executing the template, log the error
        log.Println("Error executing panel template:", err)
        // Return an internal server error to the client
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
}

// logRequest is a middleware to log information about each incoming request.
func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Get user IP and port
		userIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("Error extracting user IP: %v", err)
			userIP = "unknown"
		}

		// Log request information
		log.Printf("[%s] %s - %s:%s - %s %s %s",
			startTime.Format("2006-01-02 15:04:05"),
			userIP,
			r.Method,
			r.URL.Host,
			r.Method,
			r.URL,
			r.Proto,
		)

		// Log form values for POST requests
		if r.Method == http.MethodPost {
			r.ParseForm()
			log.Println("Form values:", r.PostForm)
		}

		// Serve the request
		handler.ServeHTTP(w, r)

		// Log processing time
		duration := time.Since(startTime)
		log.Printf("Request processed in %v", duration)
	})
}

// Function to validate the username and password directly from the file
func validateUser(username, password string) bool {
    // Read and parse temp_up.txt
    content, err := os.ReadFile("temp_up.txt")
    if err != nil {
        log.Println("Error reading temp_up.txt:", err)
        return false
    }

    lines := strings.Split(string(content), "\n")
    for _, line := range lines {
        fields := strings.Fields(line)
        if len(fields) == 2 {
            // Check if the username and password match
            if strings.Trim(fields[0], `"`) == username && strings.Trim(fields[1], `"`) == password {
                return true
            }
        }
    }

    // If no match is found, update temp_up.txt and search again
    updateTempUpFile()

    // Read and parse temp_up.txt again after the update
    updatedContent, err := os.ReadFile("temp_up.txt")
    if err != nil {
        log.Println("Error reading updated temp_up.txt:", err)
        return false
    }

    updatedLines := strings.Split(string(updatedContent), "\n")
    for _, line := range updatedLines {
        fields := strings.Fields(line)
        if len(fields) == 2 {
            // Check if the username and password match after the update
            if strings.Trim(fields[0], `"`) == username && strings.Trim(fields[1], `"`) == password {
                return true
            }
        }
    }

    return false
}

// Function to update temp_up.txt
func updateTempUpFile() {
    // You can add your logic to update temp_up.txt here
    // For example, run a script or perform any necessary updates
    cmd := exec.Command("sh", "extractor.sh")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    err := cmd.Run()
    if err != nil {
        log.Println("Error updating temp_up.txt:", err)
    }
}

func loadInfo(usernameToFind string) (u_trafficGB, D_trafficGB, T_trafficGB int64, E_dateGB int64, found bool) {
	// Read and parse info_temp.txt
	content, err := os.ReadFile("info_temp.txt")
	if err != nil {
		log.Println("Error reading info_temp.txt:", err)
		return
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Split(line, "|")
		if len(fields) >= 9 {
			username := fields[3]

			// Check if the current line corresponds to the desired username
			if username == usernameToFind {
				// Parse values from strings to integers
				u_traffic, _ = strconv.ParseInt(fields[4], 10, 64)
				D_traffic, _ = strconv.ParseInt(fields[5], 10, 64)
				E_date, _ = strconv.ParseInt(fields[6], 10, 64)
				T_traffic, _ = strconv.ParseInt(fields[7], 10, 64)

				// Return the values and set found to true
				found = true
				return
			}
		}
	}

	// Return default values and set found to false if the username is not found
	return 0, 0, 0, 0, false
}

// Function to read QR code data from a file and replace placeholders
func readQRCodeData(filename, username string) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	// Replace placeholders with actual values
	data := strings.ReplaceAll(string(content), "{username}", username)

	// Find the user password from temp_up.txt
	password, err := findUserPassword(username)
	if err != nil {
		logger.Println("Error finding user password:", err)
		return "DefaultPassword", err
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
		userAgent, err := getRandomUserAgent("user-agent.txt")
		if err != nil {
			logger.Println("Error getting random user agent:", err)
			// You may choose to handle the error in a way that fits your application
		} else {
			data = strings.ReplaceAll(data, "{user-agent}", userAgent)
		}
	}

	return data, nil
}

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


// Function to find user password from temp_up.txt
func findUserPassword(username string) (string, error) {
    usersMutex.Lock()
    defer usersMutex.Unlock()

    // Read and parse temp_up.txt
    content, err := os.ReadFile("temp_up.txt")
    if err != nil {
        log.Println("Error reading temp_up.txt:", err)
        return "", err
    }

    lines := strings.Split(string(content), "\n")
    for _, line := range lines {
        fields := strings.Fields(line)
        if len(fields) == 2 {
            if strings.Trim(fields[0], `"`) == username {
                return strings.Trim(fields[1], `"`), nil
            }
        }
    }

    return "DefaultPassword", nil // Return a default password if not found
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


// Add a function to store the session information
func storeSession(username, token string) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	// Store the session in-memory (for simplicity, you might want to use a database)
	userSessions = append(userSessions, UserSession{
		Username: username,
		Token:    token,
		Expire:   time.Now().Add(10 * time.Minute),
	})
}


// Add a function to validate the session token
func validateSession(token string) bool {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	for _, session := range userSessions {
		if session.Token == token && time.Now().Before(session.Expire) {
			return true
		}
	}

	return false
}

// Add a function to retrieve the username from the session information
func getUsernameFromSession(token string) string {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	for _, session := range userSessions {
		if session.Token == token && time.Now().Before(session.Expire) {
			return session.Username
		}
	}

	return ""
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    // Expire the session token by setting the expiration time to a past time
    http.SetCookie(w, &http.Cookie{
        Name:    "session_token",
        Value:   "", // Clear the token
        Expires: time.Now().Add(-time.Hour), // Expire the cookie
    })

    // Redirect to the login page after logging out
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Function to generate a random math problem
func generateMathProblem() ActiveMathProblem {
	// Generate two random numbers between 1 and 10
	num1, _ := rand.Int(rand.Reader, big.NewInt(10))
	num2, _ := rand.Int(rand.Reader, big.NewInt(10))

	// Choose a random operation (addition or subtraction)
	operation, _ := rand.Int(rand.Reader, big.NewInt(2)) // 0 for addition, 1 for subtraction

	// Build the math problem string
	var mathProblem string

	// Calculate the correct answer
	var correctAnswer int64

	switch operation.Int64() {
	case 0:
		mathProblem = fmt.Sprintf("%d + %d", num1.Int64()+1, num2.Int64()+1)
		correctAnswer = num1.Int64() + num2.Int64() + 2
	case 1:
		// Ensure the result is non-negative for subtraction
		if num1.Cmp(num2) >= 0 {
			mathProblem = fmt.Sprintf("%d - %d", num1.Int64()+1, num2.Int64()+1)
			correctAnswer = num1.Int64() - num2.Int64()
		} else {
			mathProblem = fmt.Sprintf("%d - %d", num2.Int64()+1, num1.Int64()+1)
			correctAnswer = num2.Int64() - num1.Int64()
		}
	}

	// Set the expiration time for 3 minutes
	expiration := time.Now().Add(3 * time.Minute)

	// Store the active math problem
	activeMathProblems[mathProblem] = ActiveMathProblem{
		MathProblem:   mathProblem,
		CorrectAnswer: correctAnswer,
		Expiration:    expiration,
	}

	return activeMathProblems[mathProblem]
}

func validateMathAnswer(mathProblem string, userAnswer int64) bool {
	activeProblem, ok := activeMathProblems[mathProblem]
	if !ok {
		// Math problem not found (expired or invalid)
		return false
	}

	// Check if the answer is correct and within the active time window
	if userAnswer == activeProblem.CorrectAnswer && time.Now().Before(activeProblem.Expiration) {
	    delete(activeMathProblems, mathProblem)
	    return true
	}
	return false
}

func cleanupExpiredMathProblems() {
    currentTimestamp := time.Now()

    for mathProblem, activeProblem := range activeMathProblems {
        if currentTimestamp.After(activeProblem.Expiration) {
            delete(activeMathProblems, mathProblem)
        }
    }
}



// Function to hash passwords
func hashPassword(password string) (string, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hashedPassword), err
}

// Function to validate admin credentials
func validateAdmin(username, password string) bool {
    // Query the database to retrieve the hashed password for the given username
    var hashedPassword string
    err := db.QueryRow("SELECT password FROM admins WHERE username = ?", username).Scan(&hashedPassword)
    if err != nil {
        log.Println("Error querying database:", err)
        return false
    }

    // Compare the entered password with the hashed password from the database
    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
    return err == nil
}

func adminPanelHandler(w http.ResponseWriter, r *http.Request) {
        // Retrieve the session token from the request (e.g., from cookies)
        sessionToken, err := r.Cookie("session_token")
        if err != nil {
                // No session token, redirect to login
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
        }

        // Validate the session token
        if !validateSession(sessionToken.Value) {
                // Invalid session token, redirect to login
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
        }

        // Extract the username from the session information
        username := getUsernameFromSession(sessionToken.Value)
        if username == "" {
                // Unable to retrieve the username, redirect to login
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
        }

	// Fetch system data
	systemData, err := fetchSystemData()
	if err != nil {
		// Handle error (log or return an error response)
		log.Println("Error fetching system data:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

    // If authenticated, render the panel template
    tmpl, err := template.ParseFiles("templates/admin-panel.html")
    if err != nil {
        // If there is an error parsing the panel template, log the error
        log.Println("Error parsing panel template:", err)
        // Return an internal server error to the client
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }


	// Create a map to store the variables you want to pass to the template
	data := map[string]interface{}{
		"Username":   username,
		"CpuUsage":   systemData.CpuUsage,
		"RamUsage":   systemData.RamUsage,
		"SwapUsage":  systemData.SwapUsage,
		"DiskUsage":  systemData.DiskUsage,
	}

    // Execute the template with the provided data and write the output to the response writer
    err = tmpl.Execute(w, data)
    if err != nil {
        // If there is an error executing the template, log the error
        log.Println("Error executing panel template:", err)
        // Return an internal server error to the client
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

}

func fetchSystemData() (*SystemData, error) {
	// Fetch CPU usage
	cpuPercentages, err := cpu.Percent(0, false)
	if err != nil {
		return nil, err
	}
	cpuUsage := math.Round(cpuPercentages[0]*100)/100

	// Fetch RAM usage
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	ramUsage := math.Round(memInfo.UsedPercent*100)/100

	// Fetch Swap usage
	swapInfo, err := mem.SwapMemory()
	if err != nil {
		return nil, err
	}
	swapUsage := math.Round(swapInfo.UsedPercent*100)/100

	// Fetch Disk usage
	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}
	diskUsage := math.Round(diskInfo.UsedPercent*100)/100

	return &SystemData{
		CpuUsage:  cpuUsage,
		RamUsage:  ramUsage,
		SwapUsage: swapUsage,
		DiskUsage: diskUsage,
	}, nil
}

func sendConfigHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the session token from the request (e.g., from cookies)
    sessionToken, err := r.Cookie("session_token")
    if err != nil {
        // No session token, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Validate the session token
    if !validateSession(sessionToken.Value) {
        // Invalid session token, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Extract the username from the session information
    username := getUsernameFromSession(sessionToken.Value)
    if username == "" {
        // Unable to retrieve the username, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Check if the request method is POST
    if r.Method != http.MethodPost {
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
        return
    }

    // Parse the request body
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Error reading request body", http.StatusInternalServerError)
        return
    }

    // Extract the configuration text from the request body
    var configText struct {
        ConfigText string `json:"configText"`
    }

    if err := json.Unmarshal(body, &configText); err != nil {
        http.Error(w, "Error decoding JSON", http.StatusBadRequest)
        return
    }

    // Save the configuration text to the qrcodefile.txt file
    err = ioutil.WriteFile("qrcodefile.txt", []byte(configText.ConfigText), 0644)
    if err != nil {
        http.Error(w, "Error saving configuration text", http.StatusInternalServerError)
        return
    }

    // Respond with a success message
    fmt.Fprint(w, "Configuration text saved successfully")
}

func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the session token from the request (e.g., from cookies)
    sessionToken, err := r.Cookie("session_token")
    if err != nil {
        // No session token, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Validate the session token
    if !validateSession(sessionToken.Value) {
        // Invalid session token, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Extract the username from the session information
    username := getUsernameFromSession(sessionToken.Value)
    if username == "" {
        // Unable to retrieve the username, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    // Parse the form data, including the uploaded file
    errfsize := r.ParseMultipartForm(10 << 20) // 10 MB limit for the file size
    if errfsize != nil {
        http.Error(w, "Unable to parse form", http.StatusInternalServerError)
        return
    }

    // Get the file from the request
    file, handler, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "Error retrieving the file", http.StatusBadRequest)
        return
    }
    defer file.Close()

    // Create a file with a unique name in the "templates" directory
    fileName := filepath.Join("templates", handler.Filename)
    dest, err := os.Create(fileName)
    if err != nil {
        http.Error(w, "Unable to create the file", http.StatusInternalServerError)
        return
    }
    defer dest.Close()

    // Copy the uploaded file to the destination file
    _, err = io.Copy(dest, file)
    if err != nil {
        http.Error(w, "Unable to copy the file", http.StatusInternalServerError)
        return
    }

    // Return a success message
    w.Write([]byte("File uploaded successfully"))
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the session token from the request (e.g., from cookies)
    sessionToken, err := r.Cookie("session_token")
    if err != nil {
        // No session token, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Validate the session token
    if !validateSession(sessionToken.Value) {
        // Invalid session token, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Extract the username from the session information
    username := getUsernameFromSession(sessionToken.Value)
    if username == "" {
        // Unable to retrieve the username, redirect to login
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // If the form is submitted, update the settings
    if r.Method == http.MethodPost {
        // Decode JSON data
        var data UpdateSettingsData
        decoder := json.NewDecoder(r.Body)
        err := decoder.Decode(&data)
        if err != nil {
            fmt.Println("Error decoding JSON:", err)
            http.Error(w, "Bad Request", http.StatusBadRequest)
            return
        }

        // Update the username and password in the database
        if data.NewUsername != "" {
            // Update the username (you may add more logic here)
            // Make sure the new username starts with "admin@"
            if !strings.HasPrefix(data.NewUsername, "admin@") {
                http.Error(w, "New username must start with 'admin@'", http.StatusBadRequest)
                return
            }
            // Validate old username and password (you may add more validation logic here)
            if data.OldUsername != username {
                http.Error(w, "Invalid old username", http.StatusBadRequest)
                return
            }

			// Update the username in the database
			err := updateUsernameInDatabase(username, data.NewUsername)
			if err != nil {
				fmt.Println("Error updating username in database:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
        // Update the session with the new username
        updateSessionUsername(sessionToken.Value, data.NewUsername)

        // Update the current username with the new one
        username = data.NewUsername
        }

        if data.NewPassword != "" {
            // Update the password (you may add more logic here)
            // Update the password in the database (replace this with your actual update logic)
            if data.NewPassword != data.ConfirmPassword {
                http.Error(w, "New password and confirm password do not match", http.StatusBadRequest)
                return
            }
            // Check old password in the database (replace this with your actual database check)
            if !checkPasswordInDatabase(username, data.OldPassword) {
                http.Error(w, "Invalid old password", http.StatusBadRequest)
                return
            }
	    // Hash the new password
	    hashedPassword, err := hashPassword(data.NewPassword)
	    if err != nil {
		fmt.Println("Error hashing password:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	    }
	    // Update the password in the database
	    err = updatePasswordInDatabase(username, hashedPassword)
	    if err != nil {
		fmt.Println("Error updating password in database:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	    }
        }

        // Redirect to the admin panel after updating settings
        http.Redirect(w, r, "/admin-panel", http.StatusSeeOther)
        return
    }

    // If not a POST request, render the settings form
    tmpl, err := template.ParseFiles("templates/admin-panel.html")
    if err != nil {
        fmt.Println("Error parsing settings template:", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Create a map to store the variables you want to pass to the template
    data := map[string]interface{}{
        "Username": username,
    }

    // Execute the template with the provided data and write the output to the response writer
    err = tmpl.Execute(w, data)
    if err != nil {
        fmt.Println("Error executing settings template:", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
}

// Update username in the database
func updateUsernameInDatabase(oldUsername, newUsername string) error {
	stmt, err := db.Prepare("UPDATE admins SET username = ? WHERE username = ?")
	if err != nil {
		return fmt.Errorf("error preparing update username statement: %v", err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(newUsername, oldUsername)
	if err != nil {
		return fmt.Errorf("error executing update username statement: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %v", err)
	}

	if rowsAffected != 1 {
		return fmt.Errorf("expected 1 row affected, got %d", rowsAffected)
	}

	return nil
}

// Check password in the database
func checkPasswordInDatabase(username, password string) bool {
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM admins WHERE username = ?", username).Scan(&hashedPassword)
	if err == sql.ErrNoRows {
		log.Printf("User not found in the database: %s", username)
		return false
	} else if err != nil {
		log.Printf("Error querying password from database: %v", err)
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		log.Printf("Password check failed for user %s", username)
		return false
	}

	log.Printf("Password check successful for user %s", username)

	return true
}


// Update password in the database
func updatePasswordInDatabase(username, newPassword string) error {

	stmt, err := db.Prepare("UPDATE admins SET password = ? WHERE username = ?")
	if err != nil {
		return fmt.Errorf("error preparing update password statement: %v", err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(newPassword, username)
	if err != nil {
		return fmt.Errorf("error executing update password statement: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %v", err)
	}

	if rowsAffected != 1 {
		return fmt.Errorf("expected 1 row affected, got %d", rowsAffected)
	}

	return nil
}

// Add the following function
func updateSessionUsername(token string, newUsername string) {
    sessionMutex.Lock()
    defer sessionMutex.Unlock()

    for i, session := range userSessions {
        if session.Token == token {
            userSessions[i].Username = newUsername
            return
        }
    }
}









func getInitialToggleStateHandler(w http.ResponseWriter, r *http.Request) {
	// Open the database connection
	db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
	if err != nil {
		// Handle error (return an appropriate HTTP response, log, etc.)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Query the database to get the initial toggle state
	query := "SELECT text FROM texts_table WHERE key = 'bot_status'"
	row := db.QueryRow(query)

	var initialToggleState bool
	err = row.Scan(&initialToggleState)
	if err != nil {
		// Handle error (return an appropriate HTTP response, log, etc.)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    jsonResponse := map[string]bool{"initialToggleState": initialToggleState}
    sendJSONResponse(w, jsonResponse)
}

func sendJSONResponse(w http.ResponseWriter, data interface{}) {
    w.Header().Set("Content-Type", "application/json")

    // Marshal data to JSON
    jsonData, err := json.Marshal(data)
    if err != nil {
        fmt.Println("Error marshaling JSON:", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)

    // Write JSON response
    _, err = w.Write(jsonData)
    if err != nil {
        fmt.Println("Error writing JSON response:", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
    }
}


func getInitialTextStateHandler(w http.ResponseWriter, r *http.Request) {
	// Open the database connection
	db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
	if err != nil {
		// Handle error (return an appropriate HTTP response, log, etc.)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Define the keys you want to retrieve
	keys := []string{"welcome_not_logged_in", "welcome_logged_in", "servers", "fees"}

	// Fetch the initial text state from the database
	initialTextState := make(map[string]string)
	for _, key := range keys {
		query := "SELECT text FROM texts_table WHERE key = ?"
		row := db.QueryRow(query, key)

		var value string
		err := row.Scan(&value)
		if err != nil {
			value = "Default " + key
		}

		initialTextState[key] = value
	}

    // Return the initial text state as JSON
    jsonResponse := map[string]map[string]string{"initialTextState": initialTextState}
    sendJSONResponse(w, jsonResponse)
}

func updateToggleStateHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JSON request
    var requestData map[string]bool
    err := json.NewDecoder(r.Body).Decode(&requestData)
    if err != nil {
        http.Error(w, "Bad Request", http.StatusBadRequest)
        return
    }

	// Open the database connection
	db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
	if err != nil {
		// Handle error (return an appropriate HTTP response, log, etc.)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

    // Update the toggle state in your data source (e.g., database)
    newToggleState := requestData["newToggleState"]

	query := "UPDATE texts_table SET text = ? WHERE key = 'bot_status'"
	_, err = db.Exec(query, newToggleState)
	if err != nil {
		// Handle error (return an appropriate HTTP response, log, etc.)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if (newToggleState) {
		// Start the telegrambot.service using systemctl
		cmd := exec.Command("systemctl", "start", "telegrambot.service")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		
		err := cmd.Run()
		if err != nil {
			// Handle error (log, panic, etc.)
			fmt.Println("Error starting telegrambot.service:", err)
			return
		}
	} else {
		// Start the telegrambot.service using systemctl
		cmd := exec.Command("systemctl", "stop", "telegrambot.service")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		
		err := cmd.Run()
		if err != nil {
			// Handle error (log, panic, etc.)
			fmt.Println("Error starting telegrambot.service:", err)
			return
		}
	}

    // Respond with success
    sendJSONResponse(w, map[string]string{"status": "success"})
}

type TextValuesRequest struct {
    TextValues map[string]string `json:"textValues"`
}

func updateTextValuesHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JSON request
    var requestData TextValuesRequest
    err := json.NewDecoder(r.Body).Decode(&requestData)

    if err != nil {
        fmt.Println("Error decoding JSON:", err)
        http.Error(w, "Bad Request", http.StatusBadRequest)
        return
    }

    // Ensure the expected keys are present in the request payload
    requiredKeys := []string{"welcome_not_logged_in", "welcome_logged_in", "servers", "fees"}
    for _, key := range requiredKeys {
        if _, ok := requestData.TextValues[key]; !ok {
            fmt.Println("Missing key in request payload:", key)
            http.Error(w, "Bad Request: Missing required key", http.StatusBadRequest)
            return
        }
    }

	// Open the database connection
	db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
	if err != nil {
		// Handle error (return an appropriate HTTP response, log, etc.)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Update text values in the database
	for key, value := range requestData.TextValues {
		query := "UPDATE texts_table SET text = ? WHERE key = ?"
		_, err = db.Exec(query, value, key)
		if err != nil {
			// Handle error (return an appropriate HTTP response, log, etc.)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	utils.LoadText()
    // Respond with success
    sendJSONResponse(w, map[string]string{"status": "success"})
}

type MessageRequest struct {
    Message string `json:"message"`
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JSON request
    var requestData MessageRequest
    err := json.NewDecoder(r.Body).Decode(&requestData)

    if err != nil {
        fmt.Println("Error decoding JSON:", err)
        http.Error(w, "Bad Request", http.StatusBadRequest)
        return
    }

    utils.SendNewsFromMain(requestData.Message)

    // Respond with success
    sendJSONResponse(w, map[string]string{"status": "success"})
}

func sendBotTokenHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JSON request
    var requestData map[string]string
    err := json.NewDecoder(r.Body).Decode(&requestData)

    if err != nil {
        fmt.Println("Error decoding JSON:", err)
        http.Error(w, "Bad Request", http.StatusBadRequest)
        return
    }

    // Ensure the expected key is present in the request payload
    if botToken, ok := requestData["botToken"]; ok {
	// Store the bot token in the specified file
	err := storeBotTokenInFile(botToken)
	if err != nil {
		// Handle error (return an appropriate HTTP response, log, etc.)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

        // Respond with success
        sendJSONResponse(w, map[string]string{"status": "success"})
    } else {
        fmt.Println("Missing key in request payload: botToken")
        http.Error(w, "Bad Request: Missing required key 'botToken'", http.StatusBadRequest)
    }
}

func storeBotTokenInFile(botToken string) error {
	// Open or create the file
	file, err := os.OpenFile("/usr/local/web_panel/telegrambot/config.env", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the bot token to the file
	_, err = file.WriteString(fmt.Sprintf("TELEGRAM_BOT_TOKEN=%s\n", botToken))
	if err != nil {
		return err
	}

	return nil
}

func initBotService() {
	// Open the database connection
	db, err := sql.Open("sqlite3", "/usr/local/web_panel/NovaNex.db")
	if err != nil {
		// Handle error (log, panic, etc.)
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	// Query the database to get the current bot status
	query := "SELECT text FROM texts_table WHERE key = 'bot_status'"
	row := db.QueryRow(query)

	var botStatus bool
	err = row.Scan(&botStatus)
	if err != nil {
		// Handle error (log, panic, etc.)
		fmt.Println("Error querying database:", err)
		return
	}

	// Start the bot service if bot status is true
	if botStatus {
		// Start the telegrambot.service using systemctl
		cmd := exec.Command("systemctl", "start", "telegrambot.service")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		if err != nil {
			// Handle error (log, panic, etc.)
			fmt.Println("Error starting telegrambot.service:", err)
			return
		}
	}
}
