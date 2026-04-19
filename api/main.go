package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var verifier *oidc.IDTokenVerifier

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		rawToken := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := verifier.Verify(r.Context(), rawToken)
		if err != nil {
			log.Printf("token verification failed: %v", err)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		var claims map[string]interface{}
		if err := token.Claims(&claims); err != nil {
			http.Error(w, "claims parse error", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next(w, r.WithContext(ctx))
	}
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(map[string]interface{})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Zero Trust says hello",
		"subject":   claims["sub"],
		"client_id": claims["azp"],
		"issued_by": claims["iss"],
	})
}

func main() {
	issuer := os.Getenv("OIDC_ISSUER")
	audience := os.Getenv("OIDC_AUDIENCE")

	caPath := os.Getenv("CA_CERT")
	caInfo, err := os.Stat(caPath)
	if err != nil {
		log.Fatalf("stat CA %s: %v", caPath, err)
	}
	if caInfo.IsDir() {
		log.Fatalf("CA path %s is a directory, not a file. "+
			"Did you run certs/generate-certs.sh before docker compose up?", caPath)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("no valid certificates found in %s", caPath)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}
	ctx := oidc.ClientContext(context.Background(), httpClient)

	// Retry OIDC discovery — Keycloak takes 30-60s to finish importing
	// the realm and bind its TLS listener on first boot.
	var provider *oidc.Provider
	for attempt := 1; attempt <= 60; attempt++ {
		provider, err = oidc.NewProvider(ctx, issuer)
		if err == nil {
			log.Printf("OIDC discovery succeeded on attempt %d", attempt)
			break
		}
		log.Printf("[%d] waiting for keycloak OIDC discovery: %v", attempt, err)
		time.Sleep(3 * time.Second)
	}
	if provider == nil {
		log.Fatalf("keycloak never became reachable at %s", issuer)
	}

	verifier = provider.Verifier(&oidc.Config{
		ClientID:          audience,
		SkipClientIDCheck: false,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/resource", authMiddleware(protectedHandler))

	log.Println("API listening on :8444 (TLS)")
	log.Fatal(http.ListenAndServeTLS(":8444",
		os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"), mux))
}
