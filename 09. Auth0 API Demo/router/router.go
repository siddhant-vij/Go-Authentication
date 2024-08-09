package router

import (
	"net/http"

	"github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	
	"Auth0_API_Demo/middleware"
)

func New() *http.ServeMux {
	router := http.NewServeMux()

	router.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "public endpoint"}`))
	}))

	router.Handle("/api/private", middleware.EnsureValidToken()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS Headers
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "private endpoint"}`))
	})))

	router.Handle("/api/private-scoped", middleware.EnsureValidToken()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS Headers.
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization")

		w.Header().Set("Content-Type", "application/json")

		token := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)

		claims := token.CustomClaims.(*middleware.CustomClaims)
			if !claims.HasScope("read:messages") {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"message":"Insufficient scope."}`))
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message": "private-scoped endpoint"}`))
	})))

	return router
}
