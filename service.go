package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/lestopher/redauthservice/redauth"
	"github.com/mgutz/ansi"
	"gopkg.in/yaml.v1"
	"io"
	"io/ioutil"
	"labix.org/v2/mgo"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
)

var (
	local   = flag.String("local", "", "serve as webserver, example: 0.0.0.0:8000")
	tcp     = flag.String("tcp", "", "serve as FCGI via TCP, example: 0.0.0.0:8000")
	unix    = flag.String("unix", "", "serve as FCGI via UNIX socket, example /tmp/myprogram.sock")
	token   = flag.String("token", "", "oauth token")
	conf    = flag.String("conf", "", "secure configuration file (yml)")
	success = ansi.ColorCode("green")
	info    = ansi.ColorCode("white")
	fail    = ansi.ColorCode("red")
	warn    = ansi.ColorCode("yellow")
	reset   = ansi.ColorCode("reset")
	// TRACE is a logger for outputting tracing information
	TRACE *log.Logger
	// INFO is a logger for outputting regular information
	INFO *log.Logger
	// WARNING is a logger for ouputting information that may be dangerous
	WARNING *log.Logger
	// ERROR is a logger for putting information that is an error
	ERROR *log.Logger
	// secureConfig contains global constans read from a secure_config.yml file
	secureConfig map[string]string
)

// Session is a wrapper for a mongodb session
type Session struct {
	*mgo.Session
}

// NewSession creates a new mongodb sesssion
func NewSession() (*Session, error) {
	session, err := mgo.Dial("mongodb://localhost:27017")
	return &Session{session}, err
}

// User represents a red user right now, but there's no package
type User struct {
	Username          string
	Email             string
	EncryptedPassword string `bson:"encrypted_password" json:"encrypted_password"`
}

// SuccessMessage represents a json structure that tells us if we succeeded
type SuccessMessage struct {
	Success bool
	Message string `json:",omitempty"`
}

func setupLogger(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	// Set up log stuff
	TRACE = log.New(traceHandle, "TRACE: ",
		log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	INFO = log.New(infoHandle, info+"INFO: "+reset,
		log.Ldate|log.Ltime|log.Lmicroseconds)
	WARNING = log.New(warningHandle, warn+"WARNING: "+reset,
		log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	ERROR = log.New(errorHandle, fail+"ERROR: "+reset,
		log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)

}

func main() {
	flag.Parse()

	if *conf != "" {
		b, err := ioutil.ReadFile(*conf)
		if err != nil {
			ERROR.Fatalln(err)
		}

		err = yaml.Unmarshal(b, &secureConfig)

		if err != nil {
			ERROR.Fatalln(err)
		}
	} else {
		ERROR.Fatalln("Secure Config file not specified")
	}
	// Setup logging output
	setupLogger(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)

	// Connect to mongodb
	session, err := NewSession()
	defer session.Close()
	if err != nil {
		ERROR.Fatalln(err)
	}

	// Setup routing
	r := mux.NewRouter()
	r.Handle("/authenticate", AuthHandler(session)).Methods("POST")

	// The following is ripped from http://www.dav-muz.net/blog/2013/09/how-to-use-go-and-fastcgi/
	if *local != "" {
		INFO.Println("Local server started on", *local)
		err = http.ListenAndServe(*local, r)
	} else if *tcp != "" {
		listener, err := net.Listen("tcp", *tcp)
		if err != nil {
			ERROR.Fatalln(err)
		}
		defer listener.Close()

		INFO.Println("FCGI TCP Server started on", *tcp)
		err = fcgi.Serve(listener, r)
	} else if *unix != "" { // Run as FCGI via UNIX socket
		listener, err := net.Listen("unix", *unix)
		if err != nil {
			ERROR.Fatalln(err)
		}
		defer listener.Close()

		INFO.Println("FCGI Socket server started with file", *unix)
		err = fcgi.Serve(listener, r)
	} else { // Run as FCGI via standard I/O
		err = fcgi.Serve(nil, r)
	}

	// Check the err status on starting the web server
	if err != nil {
		ERROR.Fatalln(err)
	}
}

// AuthHandler verifies that the username and password in the params are correct
func AuthHandler(session *Session) http.Handler {
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

		INFO.Printf("%s - Parameters %v\n", "/authenticate", params)

		var user User
		// Set up the collection we're going to be using
		c := session.DB(secureConfig["database"]).C("users")
		err := c.Find(map[string]string{"username": params["username"][0]}).One(&user)

		// We're going to pass json back to the client
		enc := json.NewEncoder(rw)
		rw.Header().Set("Content-Type", "application/json")

		if err != nil {
			ERROR.Fatalln(err)
		}

		passErr := redauth.CompareHashAndPassword(
			user.EncryptedPassword, password+secureConfig["pepper"])

		// TODO: Remove this when running for real
		TRACE.Printf("User is: %v\n", user)

		// TODO: Cleanup the error handling here, there's a lot of things that
		// could be DRY'd up
		if passErr != nil {
			rw.WriteHeader(http.StatusForbidden)
			if err = enc.Encode(&SuccessMessage{
				Success: false,
				Message: fmt.Sprintf("%s", passErr),
			}); err != nil {

				rw.WriteHeader(http.StatusInternalServerError)
				ERROR.Println("Unable to encode json message", err)
				return
			}
		} else {
			rw.WriteHeader(http.StatusOK)
			if err = enc.Encode(&SuccessMessage{Success: true}); err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				ERROR.Println("Unable to encode json message", err)
				return
			}
		}
	})
}
