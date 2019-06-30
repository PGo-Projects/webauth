package webauth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/PGo-Projects/webauth/internal/passhash"
	"github.com/PGo-Projects/webauth/internal/response"
	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
)

type Credentials struct {
	Username             string
	Password             string
	ConfirmationPassword string
	Role                 string
}

var (
	database Database
	store    *sessions.CookieStore

	ErrInternalServer        = errors.New("We're sorry, but something just went wrong.  Please try again later.")
	ErrInvalidCredentials    = errors.New("The username and/or password is incorrect.")
	ErrUsernameAlreadyExists = errors.New("This username is taken already.")
)

const (
	LoginSuccess    = "Logged in successfully!"
	RegisterSuccess = "Registered successfully!  Please login to proceed."
)

func RegisterDatabase(db Database) {
	database = db
}

func SetupSessions(authenticationKey []byte, encryptionKey []byte) {
	store = sessions.NewCookieStore(authenticationKey, encryptionKey)
}

func RegisterPOSTEndPoints(mux *chi.Mux) {
	mux.MethodFunc(http.MethodPost, "/login", LoginHandler)
	mux.MethodFunc(http.MethodPost, "/register", RegisterHandler)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	var status string
	var statusType string

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&credentials)
	if err != nil {
		status = ErrInternalServer.Error()
		statusType = response.StatusError
	}

	status, statusType = authenticate(credentials)
	if statusType == response.StatusSuccess {
		status, statusType = addAuthCookie(r, w, credentials.Username)
	}

	var responseJSON string
	if statusType == response.StatusError {
		responseJSON = response.Status(status, statusType)
	} else {
		responseJSON = response.General(map[string]string{
			"status":     status,
			"statusType": statusType,
			"username":   credentials.Username,
			"role":       credentials.Role,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseJSON))
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	var status string
	var statusType string

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&credentials); err != nil {
		status = ErrInternalServer.Error()
		statusType = response.StatusError
	}

	status, statusType = register(credentials)
	responseJSON := response.Status(status, statusType)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseJSON))
}

func authenticate(credentials Credentials) (status string, statusType string) {
	dbCredentials, err := retrieveCredentialsFromDB(credentials)
	if err != nil {
		return ErrInvalidCredentials.Error(), response.StatusError
	}

	matches, err := passhash.Verify(credentials.Password, dbCredentials.Password)
	if err != nil {
		return ErrInternalServer.Error(), response.StatusError
	}

	if !matches {
		return ErrInvalidCredentials.Error(), response.StatusError
	}

	return LoginSuccess, response.StatusSuccess
}

func register(credentials Credentials) (status string, statusType string) {
	if _, err := database.FindOne(credentials); err == nil {
		return ErrUsernameAlreadyExists.Error(), response.StatusError
	}

	if err := database.InsertOne(credentials); err != nil {
		return ErrInternalServer.Error(), response.StatusError
	}
	return RegisterSuccess, response.StatusSuccess
}

func addAuthCookie(r *http.Request, w http.ResponseWriter, username string) (status, statusType string) {
	session, err := store.Get(r, "auth")
	if err != nil {
		return ErrInternalServer.Error(), response.StatusError
	}

	session.Values["username"] = username
	session.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   86400 * 7,
	}
	if err = session.Save(r, w); err != nil {
		return ErrInternalServer.Error(), response.StatusError
	}
	return LoginSuccess, response.StatusSuccess
}

func retrieveCredentialsFromDB(credentials Credentials) (Credentials, error) {
	entry, err := database.FindOne(credentials)
	if err != nil {
		return Credentials{}, err
	}
	return entry.(Credentials), nil
}