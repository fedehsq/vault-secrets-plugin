package dao

import (
	sqldb "vault-secret-plugin/server/db"
	"vault-secret-plugin/server/models"
)

func GetByUsername(username string) (*models.User, error) {
	// Query the database for the user
	var user models.User
	err := sqldb.DB.QueryRow("SELECT * FROM users WHERE username = $1", username).Scan(&user.Id, &user.Username, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func InsertUser(user *models.User) error {
	_, err := sqldb.DB.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", user.Username, user.Password)
	if err != nil {
		return err
	}
	return nil
}
