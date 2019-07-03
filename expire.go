package webauth

import (
	"net/http"

	"github.com/go-chi/chi"
)

func RegisterRefreshExpiryEndpoint(mux *chi.Mux) {
	mux.MethodFunc(http.MethodPost, "/refresh_expiry", RefreshHandler)
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	if session, err := store.Get(r, "auth"); err == nil {
		if _, ok := session.Values["username"]; ok {
			_ = session.Save(r, w)
		}
	}
}

func ExpirationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		RefreshHandler(w, r)
		next.ServeHTTP(w, r)
	})
}
