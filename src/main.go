package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 1. read the list of routes
// 2. build the handleFunc that forwards the public routes' requests as they are
// 3. build the handleFunc that promts for username and pwd
// 4. /auth is the endpoint where the user will POST: URL, username, password.
// 5. if auth is ok, attach JWT relative to that route, if not error message.

var jwtSecret = []byte("iamcoolindeed-hhhhhhhh")

type Route struct {
	URL      string `json:"URL"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Config struct {
	PublicRoutes    []Route `json:"public_routes"`
	ProtectedRoutes []Route `json:"protected_routes"`
}

type AuthRequest struct {
	Route    string `json:"route"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Route string `json:"route"`
	jwt.RegisteredClaims
}

var (
	publicRoutes    []Route
	protectedRoutes []Route
)

func main() {
	// 1. Read the list of routes
	configData, err := os.ReadFile("routes.json")
	if err != nil {
		log.Fatalf("Failed to read routes.json: %v", err)
	}

	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse routes.json: %v", err)
	}

	publicRoutes = config.PublicRoutes
	protectedRoutes = config.ProtectedRoutes

	// Sort protected routes by path length descending so most specific paths match first
	sort.Slice(protectedRoutes, func(i, j int) bool {
		return len(getPath(protectedRoutes[i].URL)) > len(getPath(protectedRoutes[j].URL))
	})

	// 4 & 5. /auth endpoint GET (login page) and POST (validate credentials & issue JWT)
	http.HandleFunc("/auth", handleAuth)

	// 2 & 3. Main proxy handler (public routes & protected routes)
	http.HandleFunc("/", handleProxy)

	fmt.Println("Proxy running on :8081...")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatal(err)
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Path

	// Check if path matches any protected route
	var matchedProtected *Route
	for _, pr := range protectedRoutes {
		pPath := getPath(pr.URL)
		if strings.HasPrefix(reqPath, pPath) {
			matchedProtected = &pr
			break
		}
	}

	if matchedProtected != nil {
		// Verify JWT cookie for this protected route
		cookie, err := r.Cookie("auth_token")
		if err != nil || !validateToken(cookie.Value, matchedProtected.URL) {
			// Prompt user for credentials if unauthenticated
			http.Redirect(w, r, "/auth?route="+url.QueryEscape(matchedProtected.URL), http.StatusFound)
			return
		}
		forwardRequest(w, r, matchedProtected.URL)
		return
	}

	// Check if path matches any public route
	var matchedPublic *Route
	for _, pub := range publicRoutes {
		pubPath := getPath(pub.URL)
		if strings.HasPrefix(reqPath, pubPath) {
			matchedPublic = &pub
			break
		}
	}

	if matchedPublic != nil {
		forwardRequest(w, r, matchedPublic.URL)
		return
	}

	http.Error(w, "Route not found", http.StatusNotFound)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Render plain HTML login page (black background, stacked white input rectangles)
		routeParam := r.URL.Query().Get("route")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, loginHTML, routeParam)

	case http.MethodPost:
		var req AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
			return
		}

		// Validate credentials against matching protected route
		var targetRoute *Route
		for _, pr := range protectedRoutes {
			if pr.URL == req.Route {
				targetRoute = &pr
				break
			}
		}

		if targetRoute == nil || req.Username != targetRoute.Username || req.Password != targetRoute.Password {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Invalid username or password"}`))
			return
		}

		// Generate JWT valid for 24 hours
		claims := Claims{
			Route: targetRoute.URL,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
			return
		}

		// Attach JWT via cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    tokenString,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true}`))

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func validateToken(tokenStr string, targetRoute string) bool {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return false
	}

	return claims.Route == targetRoute
}

func forwardRequest(w http.ResponseWriter, r *http.Request, targetURL string) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Bad target URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(parsed)
	r.Host = parsed.Host
	proxy.ServeHTTP(w, r)
}

func getPath(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "/"
	}
	if parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

const loginHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Login</title>
    <style>
        body {
            background-color: #000;
            color: #fff;
            font-family: sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            display: flex;
            flex-direction: column;
            gap: 15px;
            width: 300px;
        }
        input {
            background: #fff;
            border: none;
            padding: 12px;
            font-size: 16px;
            color: #000;
            box-sizing: border-box;
        }
        button {
            background: #fff;
            border: none;
            padding: 12px;
            font-size: 16px;
            font-weight: bold;
            color: #000;
            cursor: pointer;
        }
        #error {
            color: #ff4d4d;
            font-size: 14px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <input type="text" id="username" placeholder="Username" />
        <input type="password" id="password" placeholder="Password" />
        <button onclick="login()">Login</button>
        <div id="error"></div>
    </div>

    <script>
        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            errorDiv.innerText = '';

            const res = await fetch('/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    route: '%s',
                    username: username,
                    password: password
                })
            });

            if (res.ok) {
                // Get the protected target URL passed into the query parameter
				const urlParams = new URLSearchParams(window.location.search);
				const targetRoute = urlParams.get('route');

				if (targetRoute) {
					// Parse targetRoute to navigate to its path (e.g., "localhost:8080/dashub" -> "/dashub")
					try {
						const parsed = new URL(targetRoute.startsWith('http') ? targetRoute : 'http://' + targetRoute);
						window.location.href = parsed.pathname + parsed.search + parsed.hash;
					} catch (e) {
						window.location.href = '/';
					}
				} else {
					window.location.href = '/';
				}
            } else {
                const data = await res.json();
                errorDiv.innerText = data.error || 'Login failed';
            }
        }
    </script>
</body>
</html>`
