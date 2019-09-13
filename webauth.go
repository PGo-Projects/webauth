package webauth

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/PGo-Projects/output"
	"github.com/PGo-Projects/webauth/internal/passhash"
	response "github.com/PGo-Projects/webresponse"
	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
)

type Credentials struct {
	Username             string
	Password             string
	ConfirmationPassword string `bson:"-" json:"-"`
	Role                 string
}

var (
	database Database
	store    *sessions.CookieStore

	authCookie = "auth"
	debugMode  = false

	RegisterRoute   = "/register"
	LoginRoute      = "/login"
	LogoutRotue     = "/logout"
	IsLoggedInRoute = "/is_logged_in"

	SessionOptions = sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   0,
	}
)

const (
	ErrInternalServer        = "We're sorry, but something just went wrong.  Please try again later."
	ErrInvalidCredentials    = "The username and/or password is incorrect."
	ErrUsernameAlreadyExists = "This username is taken already."

	LoginSuccess    = "Logged in successfully!"
	LogoutSuccess   = "Logged out successfully!  See you next time!"
	RegisterSuccess = "Registered successfully!  Please login to proceed."
)

func RegisterDatabase(db Database) {
	database = db
}

func SetDebugMode(dm bool) {
	debugMode = dm
}

func SetupSessions(authenticationKey []byte, encryptionKey []byte) {
	store = sessions.NewCookieStore(authenticationKey, encryptionKey)
}

func RegisterEndPoints(mux *chi.Mux) {
	mux.MethodFunc(http.MethodPost, LoginRoute, LoginHandler)
	mux.MethodFunc(http.MethodPost, LogoutRotue, LogoutHandler)
	mux.MethodFunc(http.MethodPost, RegisterRoute, RegisterHandler)

	mux.MethodFunc(http.MethodGet, IsLoggedInRoute, IsLoggedInHandler)
	mux.MethodFunc(http.MethodPost, IsAuthorizedRoute, IsAuthorizedHandler)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	var status string
	var statusType string

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&credentials)
	if err != nil {
		output.DebugErrorln(debugMode, err)
		status = ErrInternalServer
		statusType = response.StatusError
	}

	status, statusType = authenticate(credentials)
	if statusType == response.StatusSuccess {
		if err := runHooks(loginSuccessHooks, w, r, credentials); err != nil {
			status = ErrInternalServer
			statusType = response.StatusError
		}
	}

	if statusType == response.StatusSuccess {
		status, statusType = addAuthCookie(r, w, credentials.Username)
	}

	var responseJSON []byte
	if statusType == response.StatusSuccess {
		responseJSON = response.General(map[string]string{
			"status":     status,
			"statusType": statusType,
			"username":   credentials.Username,
			"role":       credentials.Role,
		})
	} else {
		responseJSON = response.Status(status, statusType)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseJSON)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var responseJSON []byte

	session, err := store.Get(r, authCookie)
	if err != nil {
		output.DebugErrorln(debugMode, err)
		responseJSON = response.Error(response.ErrInternalServer)
	}

	session.Options.MaxAge = -1
	if err = session.Save(r, w); err != nil {
		output.DebugErrorln(debugMode, err)
		responseJSON = response.Error(response.ErrInternalServer)
	} else {
		if err := runSimpleHooks(logoutSuccessHooks, w, r); err != nil {
			responseJSON = response.Error(response.ErrInternalServer)
		} else {
			responseJSON = response.Success(LogoutSuccess)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseJSON)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	var status string
	var statusType string

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&credentials); err != nil {
		output.DebugErrorln(debugMode, err)
		status = ErrInternalServer
		statusType = response.StatusError
	}

	status, statusType = register(credentials)
	if statusType == response.StatusSuccess {
		if err := runHooks(registerSuccessHooks, w, r, credentials); err != nil {
			status = ErrInternalServer
			statusType = response.StatusError
		}
	}

	responseJSON := response.Status(status, statusType)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseJSON))
}

func IsLoggedInHandler(w http.ResponseWriter, r *http.Request) {
	username, loggedInState := IsLoggedIn(r)
	responseJSON := response.General(map[string]string{
		"isLoggedIn": strconv.FormatBool(loggedInState),
		"username":   username,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseJSON))
}

func IsLoggedIn(r *http.Request) (string, bool) {
	session, err := store.Get(r, authCookie)
	if err != nil {
		output.DebugErrorln(debugMode, err)
		return "", false
	}
	username, ok := session.Values["username"]
	if ok {
		return username.(string), ok
	}
	return "", false
}

func authenticate(credentials Credentials) (status, statusType string) {
	dbCredentials, err := retrieveCredentialsFromDB(credentials)
	if err != nil {
		output.DebugErrorln(debugMode, err)
		return ErrInvalidCredentials, response.StatusError
	}

	matches, err := passhash.Verify(credentials.Password, dbCredentials.Password)
	if err != nil {
		output.DebugErrorln(debugMode, err)
		return ErrInternalServer, response.StatusError
	}

	if !matches {
		output.DebugStringln(debugMode, "The credentials don't match", output.RED)
		return ErrInvalidCredentials, response.StatusError
	}

	return LoginSuccess, response.StatusSuccess
}

func register(credentials Credentials) (status, statusType string) {
	if _, err := database.FindOne(credentials); err == nil {
		output.DebugStringln(debugMode, "The username already exists", output.RED)
		return ErrUsernameAlreadyExists, response.StatusError
	}

	hashedPassword, err := passhash.Hash(credentials.Password)
	if err != nil {
		output.DebugErrorln(debugMode, err)
		return ErrInternalServer, response.StatusError
	}

	credentials.Password = hashedPassword
	if err := database.InsertOne(credentials); err != nil {
		output.DebugErrorln(debugMode, err)
		return ErrInternalServer, response.StatusError
	}
	return RegisterSuccess, response.StatusSuccess
}

func addAuthCookie(r *http.Request, w http.ResponseWriter, username string) (status, statusType string) {
	session, err := store.Get(r, authCookie)
	if err != nil {
		output.DebugErrorln(debugMode, err)
		return ErrInternalServer, response.StatusError
	}

	session.Values["username"] = username
	session.Options = &SessionOptions
	if err = session.Save(r, w); err != nil {
		output.DebugErrorln(debugMode, err)
		return ErrInternalServer, response.StatusError
	}
	return LoginSuccess, response.StatusSuccess
}

func retrieveCredentialsFromDB(credentials Credentials) (Credentials, error) {
	entry, err := database.FindOne(credentials)
	if err != nil {
		output.DebugErrorln(debugMode, err)
		return Credentials{}, err
	}
	return entry.(Credentials), nil
}
