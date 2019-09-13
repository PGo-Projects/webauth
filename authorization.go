package webauth

import (
	"net/http"
	"strconv"

	response "github.com/PGo-Projects/webresponse"
)

var permissionTable map[string][]string

func RegisterPermissionTable(table map[string][]string) {
	permissionTable = table
}

func IsAuthorizedHandler(w http.ResponseWriter, r *http.Request) {
	username, loggedInState := IsLoggedIn(r)

	authorized := false
	if loggedInState {
		role := GetUserRole(username)
		visitedURL := r.Host + r.URL.Path

		for _, url := range permissionTable[role] {
			if url == visitedURL {
				authorized = true
			}
		}
	}

	responseJSON := response.General(map[string]string{
		"authorized": strconv.FormatBool(authorized),
	})

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
