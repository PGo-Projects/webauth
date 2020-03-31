package webauth

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/PGo-Projects/output"
	response "github.com/PGo-Projects/webresponse"
	"github.com/go-chi/chi"
)

var (
	permissionTable map[string][]string

	IsAuthorizedRoute = "/is_authorized"
)

type authorizationURL struct {
	Path string `json:"path"`
}

func RegisterAuthorizedEndpoints(mux *chi.Mux) {
	mux.MethodFunc(http.MethodPost, IsAuthorizedRoute, IsAuthorizedHandler)
}

func RegisterPermissionTable(table map[string][]string) {
	permissionTable = table
}

func IsAuthorizedHandler(w http.ResponseWriter, r *http.Request) {
	var authURL *authorizationURL
	var responseJSON []byte

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&authURL)
	if err != nil {
		output.DebugErrorln(err)
		responseJSON = response.Error(response.ErrBadRequest)
	} else {
		authorized := false
		username, loggedInState := IsLoggedIn(r)
		if loggedInState {
			role := GetUserRole(username)

			for _, url := range permissionTable[role] {
				if url == authURL.Path {
					authorized = true
				}
			}
		}
		responseJSON = response.General(map[string]string{
			"authorized": strconv.FormatBool(authorized),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseJSON)
}

func IsAuthorized(username, role string) bool {
	return GetUserRole(username) == role
}

func GetUserRole(username string) string {
	c := Credentials{
		Username: username,
	}
	dbCredentials, err := retrieveCredentialsFromDB(c)
	if err != nil {
		return ""
	}
	return dbCredentials.Role
}
