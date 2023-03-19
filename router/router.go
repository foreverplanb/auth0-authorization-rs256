package router

import (
	"fmt"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"

	"01-Authorization-RS256/middleware"
)

type RespData struct {
	CheckScope  string   `json:"check_scope"`
	Scopes      string   `json:"scopes"`
	Permissions []string `json:"permissions"`
}

// New sets up our routes and returns a *http.ServeMux.
func New() *http.ServeMux {
	router := http.NewServeMux()

	// This route is always accessible.
	router.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Hello from a public endpoint! You don't need to be authenticated to see this."}`))
	}))

	// This route is only accessible if the user has a valid access_token.
	router.Handle("/api/private", middleware.EnsureValidToken()(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS Headers.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this."}`))
		}),
	))

	// This route is only accessible if the user has a
	// valid access_token with the read:messages scope.
	router.Handle("/api/private-scoped", middleware.EnsureValidToken()(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS Headers.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")

			w.Header().Set("Content-Type", "application/json")

			token := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)

			claims := token.CustomClaims.(*middleware.CustomClaims)
			fmt.Println(claims.Permissions)
			checkScope := r.URL.Query().Get("check_scope")
			fmt.Println(fmt.Sprintf("checkScope: %s, scopes: [%s]", checkScope, claims.Scope))
			if !claims.HasScope(checkScope) {
				w.WriteHeader(http.StatusForbidden)
				resp := fmt.Sprintf(`{"checkScope":"%s","scopes":"[%s]","message":"no auth scope."}`, checkScope, claims.Scope)
				w.Write([]byte(resp))
				return
			}

			w.WriteHeader(http.StatusOK)
			resp := fmt.Sprintf(`{"scope":"[%s]","message":"Hello from a private endpoint! You need to be authenticated to see this."}`, claims.Scope)
			w.Write([]byte(resp))
		}),
	))
	router.Handle("/api/private-permissions", middleware.EnsureValidToken()(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS Headers.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")
			w.Header().Set("Content-Type", "application/json")

			token := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
			claims := token.CustomClaims.(*middleware.CustomClaims)
			fmt.Println(claims.Permissions)
			checkPermission := r.URL.Query().Get("check_permission")
			fmt.Println(fmt.Sprintf("checkPermission: %s, permissions: %v", checkPermission, claims.Permissions))
			if !claims.HasPermission(checkPermission) {
				w.WriteHeader(http.StatusForbidden)
				resp := fmt.Sprintf(`{"checkPermission":"%s","permissions":"%v","message":"no auth permission."}`, checkPermission, claims.Permissions)
				w.Write([]byte(resp))
				return
			}

			w.WriteHeader(http.StatusOK)
			resp := fmt.Sprintf(`{"checkPermission":"%s","permissions":"%v","message":"Hello from a private endpoint! You have be authenticated to see this."}`, checkPermission, claims.Permissions)
			w.Write([]byte(resp))
		}),
	))

	return router
}
