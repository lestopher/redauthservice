package main

import (
	"flag"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"

	"github.com/gorilla/mux"
	"github.com/lestopher/fancylogger"
	"gopkg.in/yaml.v1"
	"labix.org/v2/mgo"
)

var (
	local = flag.String("local", "", "serve as webserver, example: 0.0.0.0:8000")
	tcp   = flag.String("tcp", "", "serve as FCGI via TCP, example: 0.0.0.0:8000")
	unix  = flag.String("unix", "", "serve as FCGI via UNIX socket, example /tmp/myprogram.sock")
	token = flag.String("token", "", "oauth token")
	conf  = flag.String("conf", "", "secure configuration file (yml)")
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

// Collection is a wrapper for mgo collections
func (s *Session) Collection(name string) *mgo.Collection {
	return s.DB(secureConfig["database"]).C(name)
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

func main() {
	flag.Parse()

	l := fancylogger.NewFancyLogger(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)

	if *conf != "" {
		b, err := ioutil.ReadFile(*conf)
		if err != nil {
			l.Error.Fatalln(err)
		}

		err = yaml.Unmarshal(b, &secureConfig)

		if err != nil {
			l.Error.Fatalln(err)
		}
	} else {
		l.Error.Fatalln("Secure Config file not specified")
	}
	// Setup logging output
	// setupLogger(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)

	// Connect to mongodb
	session, err := NewSession()
	defer session.Close()
	if err != nil {
		l.Error.Fatalln(err)
	}

	// Setup routing
	r := mux.NewRouter()
	r.Handle("/authenticate", AuthHandler(session, l)).Methods("POST")

	// The following is ripped from http://www.dav-muz.net/blog/2013/09/how-to-use-go-and-fastcgi/
	if *local != "" {
		l.Info.Println("Local server started on", *local)
		err = http.ListenAndServe(*local, r)
	} else if *tcp != "" {
		listener, err := net.Listen("tcp", *tcp)
		if err != nil {
			l.Error.Fatalln(err)
		}
		defer listener.Close()

		l.Info.Println("FCGI TCP Server started on", *tcp)
		err = fcgi.Serve(listener, r)
	} else if *unix != "" { // Run as FCGI via UNIX socket
		listener, err := net.Listen("unix", *unix)
		if err != nil {
			l.Error.Fatalln(err)
		}
		defer listener.Close()

		l.Info.Println("FCGI Socket server started with file", *unix)
		err = fcgi.Serve(listener, r)
	} else { // Run as FCGI via standard I/O
		err = fcgi.Serve(nil, r)
	}

	// Check the err status on starting the web server
	if err != nil {
		l.Error.Fatalln(err)
	}
}
