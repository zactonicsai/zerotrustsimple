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

// authMiddleware enforces BOTH credentials on every request:
//  1. A valid TLS client certificate (enforced at the TLS layer — if this
//     fails, the request never reaches this handler at all).
//  2. A valid JWT bearer token.
//
// It then cross-checks that the cert's CN matches the token's `azp`
// (authorized party) claim. This closes the gap where an attacker might
// steal one credential but not the other.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// --- Layer 1: client cert (TLS layer already verified it exists
		//     and chains to our CA; we just need to inspect identity) ---
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			// Should be impossible with RequireAndVerifyClientCert, but belt-and-suspenders.
			http.Error(w, "mTLS: no client cert presented", http.StatusUnauthorized)
			return
		}
		clientCertCN := r.TLS.PeerCertificates[0].Subject.CommonName

		// --- Layer 2: bearer token ---
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

		// --- Cross-check: cert identity must match token identity ---
		tokenAzp, _ := claims["azp"].(string)
		if tokenAzp == "" {
			http.Error(w, "token missing azp claim", http.StatusUnauthorized)
			return
		}
		if clientCertCN != tokenAzp {
			log.Printf("cert/token mismatch: cert CN=%q, token azp=%q",
				clientCertCN, tokenAzp)
			http.Error(w, "cert/token identity mismatch", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		ctx = context.WithValue(ctx, "client_cn", clientCertCN)
		next(w, r.WithContext(ctx))
	}
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(map[string]interface{})
	clientCN := r.Context().Value("client_cn").(string)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":         "Zero Trust says hello (mTLS + JWT verified)",
		"token_subject":   claims["sub"],
		"token_azp":       claims["azp"],
		"token_issuer":    claims["iss"],
		"tls_client_cn":   clientCN,
	})
}

func main() {
	issuer := os.Getenv("OIDC_ISSUER")
	audience := os.Getenv("OIDC_AUDIENCE")

	// --- Read CA cert ---
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

	// --- HTTP client for OIDC discovery + JWKS (trusts our CA) ---
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}
	ctx := oidc.ClientContext(context.Background(), httpClient)

	// --- OIDC discovery (with retries for Keycloak boot time) ---
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

	// --- HTTP mux ---
	mux := http.NewServeMux()
	mux.HandleFunc("/api/resource", authMiddleware(protectedHandler))

	// -----------------------------------------------------------------
	// mTLS configuration
	//
	// ClientCAs:  caPool  -- the set of CAs whose client certs we accept.
	//                        Reusing caPool because in this demo the same
	//                        local CA issues both server and client certs.
	//                        In production you'd often use a SEPARATE CA
	//                        for client certs to limit blast radius.
	//
	// ClientAuth: RequireAndVerifyClientCert -- strictest setting. No
	//                        cert, no TLS handshake. Rejected before the
	//                        HTTP layer even runs.
	// -----------------------------------------------------------------
	tlsCfg := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      ":8444",
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Println("API listening on :8444 (TLS + mTLS enforced)")
	log.Fatal(server.ListenAndServeTLS(
		os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")))
}
