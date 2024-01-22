package main

import (
	"fmt"
	"html/template"
	"log"
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

func main() {

	// Initialize the map
	activeMathProblems = make(map[string]ActiveMathProblem)

	// Handle requests
	http.Handle("/login", http.HandlerFunc(loginHandler))
	http.Handle("/panel", http.HandlerFunc(panelHandler))

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
        }
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
