package auth

import (
	"encoding/json"
	"net/http"
	"vault-secret-plugin/server/dao"
	"vault-secret-plugin/server/models"

	"github.com/google/uuid"
)

type ApiUser struct {
	Username string
	Token    string
}

func Signup(w http.ResponseWriter, r *http.Request) {
	var p models.User
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user, _ := dao.GetByUsername(p.Username)
	if user != nil {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}
	err = dao.InsertUser(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func Signin(w http.ResponseWriter, r *http.Request) {
	var p models.User
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user, err := dao.GetByUsername(p.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if user == nil {
		http.Error(w, "User does not exist", http.StatusBadRequest)
		return
	}
	if user.Password != p.Password {
		http.Error(w, "Wrong password", http.StatusBadRequest)
		return
	}
	// Generate token
	token := uuid.New().String()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ApiUser{user.Username, token})
}
