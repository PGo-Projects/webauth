package webauth

import (
	"github.com/go-chi/chi"
	"github.com/gorilla/csrf"
)

func SetupCSRF(mux *chi.Mux, secret []byte, productionMode bool) {
	csrfMiddleware := csrf.Protect(
		secret,
		csrf.Secure(productionMode),
	)
	mux.Use(csrfMiddleware)
}
