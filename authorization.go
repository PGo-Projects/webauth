package webauth

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/PGo-Projects/output"
	response "github.com/PGo-Projects/webresponse"
)

var permissionTable map[string][]string

type authorizationURL struct {
	Path string `json:"path"`
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
		output.DebugErrorln(debugMode, err)
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
