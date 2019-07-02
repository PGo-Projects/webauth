package webauth

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/rs/cors"
)

func SetupCORS(mux *chi.Mux, debugMode bool, allowedOrigins []string) {
	c := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodHead},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
		Debug:            debugMode,
	})
	mux.Use(c.Handler)
}

func SetupCORSWithOptions(mux *chi.Mux, options cors.Options) {
	c := cors.New(options)
	mux.Use(c.Handler)
}
