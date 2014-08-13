package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestopher/fancylogger"
	"github.com/lestopher/redauthservice/redauth"
)

// AuthHandler verifies that the username and password in the params are correct
func AuthHandler(session *Session, l *fancylogger.FancyLogger) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		params := r.Form
		var password string

		// If the parameters contains a password, pull it out and replace it with
		// a filtered one
		if _, ok := params["password"]; ok {
			password = params["password"][0]
			params["password"] = []string{"[FILTERED]"}
		}

		l.Info.Printf("%s - Parameters %v\n", "/authenticate", params)

		var user User
		// Set up the collection we're going to be using
		c := session.Collection("users")
		err := c.Find(map[string]string{"username": params["username"][0]}).One(&user)

		// We're going to pass json back to the client
		enc := json.NewEncoder(rw)
		rw.Header().Set("Content-Type", "application/json")

		if err != nil {
			l.Error.Fatalln(err)
		}

		passErr := redauth.CompareHashAndPassword(
			user.EncryptedPassword, password+secureConfig["pepper"])

		// TODO: Remove this when running for real
		l.Trace.Printf("User is: %v\n", user)

		// TODO: Cleanup the l.Error handling here, there's a lot of things that
		// could be DRY'd up
		if passErr != nil {
			rw.WriteHeader(http.StatusForbidden)
			if err = enc.Encode(&SuccessMessage{
				Success: false,
				Message: fmt.Sprintf("%s", passErr),
			}); err != nil {

				rw.WriteHeader(http.StatusInternalServerError)
				l.Error.Println("Unable to encode json message", err)
				return
			}
		} else {
			rw.WriteHeader(http.StatusOK)
			if err = enc.Encode(&SuccessMessage{Success: true}); err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				l.Error.Println("Unable to encode json message", err)
				return
			}
		}
	})
}
