package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB() *gorm.DB {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&User{}, &Note{})
	return db
}

func TestRegisterHandler(t *testing.T) {
	db = setupTestDB()

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "testpassword")

	req, err := http.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(RegisterHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected status %v, got %v", http.StatusSeeOther, rr.Code)
	}

	var user User
	db.Where("username = ?", "testuser").First(&user)
	if user.Username != "testuser" {
		t.Errorf("expected username %v, got %v", "testuser", user.Username)
	}
}

func TestLoginHandler(t *testing.T) {
	db = setupTestDB()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	user := User{Username: "testuser", Password: string(hashedPassword)}
	db.Create(&user)

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "testpassword")

	req, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(LoginHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected status %v, got %v", http.StatusSeeOther, rr.Code)
	}

	cookie := rr.Result().Cookies()
	if len(cookie) == 0 || cookie[0].Name != "token" {
		t.Errorf("expected token cookie, got %v", cookie)
	}
}

func TestCreateNoteHandler(t *testing.T) {
	db = setupTestDB()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	user := User{Username: "testuser", Password: string(hashedPassword)}
	db.Create(&user)

	token, _ := generateJWT(user.Username)
	req, err := http.NewRequest(http.MethodPost, "/note/create", strings.NewReader(url.Values{
		"title":   {"Test Note"},
		"content": {"This is a test note"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := AuthMiddleware(CreateNoteHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected status %v, got %v", http.StatusSeeOther, rr.Code)
	}

	var note Note
	db.Where("title = ?", "Test Note").First(&note)
	if note.Title != "Test Note" {
		t.Errorf("expected note title %v, got %v", "Test Note", note.Title)
	}
}

func TestEditNoteHandler(t *testing.T) {
	db = setupTestDB()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	user := User{Username: "testuser", Password: string(hashedPassword)}
	db.Create(&user)

	note := Note{UserID: user.ID, Title: "Old Note", Content: "Old content"}
	db.Create(&note)

	token, _ := generateJWT(user.Username)
	req, err := http.NewRequest(http.MethodPost, "/note/edit/"+fmt.Sprintf("%d", note.ID), strings.NewReader(url.Values{
		"title":   {"Updated Note"},
		"content": {"Updated content"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := AuthMiddleware(EditNoteHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected status %v, got %v", http.StatusSeeOther, rr.Code)
	}

	var updatedNote Note
	db.First(&updatedNote, note.ID)
	if updatedNote.Title != "Updated Note" {
		t.Errorf("expected note title %v, got %v", "Updated Note", updatedNote.Title)
	}
}

func TestDeleteNoteHandler(t *testing.T) {
	db = setupTestDB()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	user := User{Username: "testuser", Password: string(hashedPassword)}
	db.Create(&user)

	note := Note{UserID: user.ID, Title: "Note to be deleted", Content: "Delete this note"}
	db.Create(&note)

	token, _ := generateJWT(user.Username)
	req, err := http.NewRequest(http.MethodPost, "/note/delete/"+fmt.Sprintf("%d", note.ID), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "token", Value: token})

	rr := httptest.NewRecorder()
	handler := AuthMiddleware(DeleteNoteHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected status %v, got %v", http.StatusSeeOther, rr.Code)
	}

	var deletedNote Note
	result := db.First(&deletedNote, note.ID)
	if result.Error == nil {
		t.Errorf("expected note to be deleted, but it still exists")
	}
}

func TestNotesHandler(t *testing.T) {
	db = setupTestDB()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	user := User{Username: "testuser", Password: string(hashedPassword)}
	db.Create(&user)

	db.Create(&Note{UserID: user.ID, Title: "Note 1", Content: "Content 1"})
	db.Create(&Note{UserID: user.ID, Title: "Note 2", Content: "Content 2"})

	token, _ := generateJWT(user.Username)
	req, err := http.NewRequest(http.MethodGet, "/notes", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "token", Value: token})

	rr := httptest.NewRecorder()
	handler := AuthMiddleware(NotesHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %v, got %v", http.StatusOK, rr.Code)
	}

	// Here, you might want to verify the response body to check if the notes are rendered correctly.
	// However, for simplicity, we assume that if the status is OK, the notes are rendered.
}

func generateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}
