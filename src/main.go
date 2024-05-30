package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	db        *gorm.DB
	jwtKey    = []byte("my_secret_key")
	templates *template.Template
)

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Password string
}

type Note struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint
	Title     string
	Content   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func init() {
	var err error
	db, err = gorm.Open(sqlite.Open("notes.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed connect to database:", err)
	}
	if err := db.AutoMigrate(&User{}, &Note{}); err != nil {
		log.Fatal("Failed to auto migrate tables:", err)
	}

}

func main() {
	var err error
	if templates, err = template.ParseGlob("src/templates/*"); err != nil {
		log.Fatal("Failed to parse templates:123", err)
	}
	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler).Methods("GET")
	r.HandleFunc("/register", RegisterHandler).Methods("GET", "POST")
	r.HandleFunc("/login", LoginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", LogoutHandler).Methods("POST")
	r.HandleFunc("/notes", AuthMiddleware(NotesHandler)).Methods("GET")
	r.HandleFunc("/note/create", AuthMiddleware(CreateNoteHandler)).Methods("GET", "POST")
	r.HandleFunc("/note/edit/{id}", AuthMiddleware(EditNoteHandler)).Methods("GET", "POST")
	r.HandleFunc("/note/delete/{id}", AuthMiddleware(DeleteNoteHandler)).Methods("POST")

	fs := http.FileServer(http.Dir("src/static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	http.Handle("/", r)
	log.Println("Server started")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := templates.ExecuteTemplate(w, "register.html", nil); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	user := User{Username: username, Password: string(hashedPassword)}
	result := db.Create(&user)
	if result.Error != nil {
		http.Error(w, "Username already taken", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	var user User
	result := db.Where("username = ?", username).First(&user)
	if result.Error != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   "",
		Expires: time.Unix(0, 0),
		Path:    "/",
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func NotesHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	var notes []Note
	db.Where("user_id = ?", user.ID).Find(&notes)
	if err := templates.ExecuteTemplate(w, "index.html", notes); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func CreateNoteHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	if r.Method == http.MethodGet {
		if err := templates.ExecuteTemplate(w, "note.html", nil); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	title := r.FormValue("title")
	content := r.FormValue("content")

	note := Note{UserID: user.ID, Title: title, Content: content}
	db.Create(&note)
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func EditNoteHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	vars := mux.Vars(r)
	id := vars["id"]

	var note Note
	db.First(&note, id)
	if note.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodGet {
		if err := templates.ExecuteTemplate(w, "note.html", note); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		return
	}

	if err := r.ParseForm(); err != nil {
    http.Error(w, "Internal server error", http.StatusInternalServerError)
    return
}
	note.Title = r.FormValue("title")
	note.Content = r.FormValue("content")
	db.Save(&note)
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func DeleteNoteHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	vars := mux.Vars(r)
	id := vars["id"]

	var note Note
	db.First(&note, id)
	if note.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	db.Delete(&note)
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		tokenStr := c.Value
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		if !tkn.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		user := User{}
		db.Where("username = ?", claims.Username).First(&user)

		//nolint
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getUserFromContext(r *http.Request) (User, error) {
	user, ok := r.Context().Value("user").(User)
	if !ok {
		return User{}, fmt.Errorf("no user")
	}
	return user, nil
}