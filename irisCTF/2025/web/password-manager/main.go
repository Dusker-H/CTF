package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type CustomMux struct {
	handlers map[string]http.HandlerFunc
}
type Auth struct {
	User     string `json:"usr"`
	Password string `json:"pwd"`
}

var DB *sql.DB
var PathReplacer = strings.NewReplacer(
	"../", "",
)
var users map[string]string

func NewCustomMux() *CustomMux {
	return &CustomMux{handlers: make(map[string]http.HandlerFunc)}
}

func (mux *CustomMux) HandleFunc(pattern string, handler http.HandlerFunc) {
	mux.handlers[pattern] = handler
}

func (mux *CustomMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rawPath := r.URL.RawPath
	if rawPath == "" {
		rawPath = r.URL.Path
	}

	if handler, exists := mux.handlers[rawPath]; exists {
		handler(w, r)
	} else {
		mux.handlers["/"](w, r)
	}
}

func main() {
	// Connect to MySQL
	db, err := sql.Open("mysql", "readonly_user:password@tcp(127.0.0.1:3306)/uwu")
	if err != nil {
		fmt.Printf("Error connecting to mysql: %v\n", err)
		return
	}
	DB = db

	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	// Initialize users var
	file, err := os.Open("./users.json")
	if err != nil {
		fmt.Printf("Error reading users.json: %v\n", err)
		return
	}

	if err := json.NewDecoder(file).Decode(&users); err != nil {
		fmt.Printf("Error reading users.json: %v\n", err)
		return
	}
}

func rawMux(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	var auth Auth

	if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request!"))
		return
	}

	if !validateLogin(auth.User, auth.Password) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid password!"))
		return
	}

	authJson, err := json.Marshal(auth) // JSON 형태로 변환
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error occurred! (this should not happen, please open a ticket!)"))
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "auth",
		Value: base64.RawStdEncoding.EncodeToString(authJson),
	})
	w.Write([]byte("{}"))
}

func validateLogin(user, password string) bool {
	if realpassword, ok := users[user]; !ok || password != realpassword {
		fmt.Printf("%t | \"%s\"==\"%s\" %t", ok, password, realpassword, password == realpassword)
		return false
	}

	return true
}

func isLoggedIn(w http.ResponseWriter, r *http.Request) (bool, error) {
	var auth Auth
	authCookie, err := r.Cookie("auth") // 클라이언트의 auth라는 이름의 쿠키를 가져옴
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return false, err
	}

	data, err := base64.RawStdEncoding.DecodeString(authCookie.Value) // authCookie.Value는 Base64로 인코딩된 JSON 데이터 -> 이를 디코딩하여 JSON 데이터를 복원
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return false, err
	}

	json.Unmarshal(data, &auth) // JSON 데이터를 auth 구조체에 파싱

	return validateLogin(auth.User, auth.Password), nil
}

func getpasswords(w http.ResponseWriter, r *http.Request) {
	loggedIn, err := isLoggedIn(w, r) // 사용자가 현재 로그인 상태인지 확인

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
		return
	}

	if !loggedIn {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	res, err := DB.Exec("SELECT * FROM passwords")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
		return
	}

	err = json.NewEncoder(w).Encode(res) //쿼리 결과를 JSON 형식으로 변환하여 HTTP 응답(w)에 기록
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
		return
	}
}

func homepage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./pages/index.html")
}

func notfound(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "Hey! No page found!")
}

func pages(w http.ResponseWriter, r *http.Request) {
	// You. Shall. Not. Path traverse!
	path := PathReplacer.Replace(r.URL.Path)

	if path == "/" {
		homepage(w, r)
		return
	}

	if path == "/login" {
		login(w, r)
		return
	}

	if path == "/getpasswords" {
		getpasswords(w, r)
		return
	}

	fullPath := "./pages" + path

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		notfound(w, r)
		return
	}

	http.ServeFile(w, r, fullPath)
}
