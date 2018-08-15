package main

import (
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	"github.com/yosssi/ace"
	"gopkg.in/gorp.v1"

	gmux "github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/urfave/negroni"

	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
)

// User DTO
type User struct {
	Username string `db:"username"`
	Secret   []byte `db:"secret"`
}

// Book DTO
type Book struct {
	PK             int64  `db:"pk"`
	Title          string `db:"title"`
	Author         string `db:"author"`
	Classification string `db:"classification"`
	ID             string `db:"id"`
	User           string `db:"user"`
}

// Page is a DTO for the templating engine
type Page struct {
	Books  []Book
	Filter string
	User   string
}

// LoginPage is a DTO for the templating engine for the login page
type LoginPage struct {
	Error string
}

// SearchResult is a DRO for the search results
type SearchResult struct {
	Title  string `xml:"title,attr"`
	Author string `xml:"author,attr"`
	Year   string `xml:"hyr,attr"`
	ID     string `xml:"owi,attr"`
}

// ClassifySearchResponse captures the slice of results from the WS call
type ClassifySearchResponse struct {
	Results []SearchResult `xml:"works>work"`
}

// ClassifyBookResponse is a DTO of a single book instance
type ClassifyBookResponse struct {
	BookData struct {
		Title  string `xml:"title,attr"`
		Author string `xml:"author,attr"`
		ID     string `xml:"owi,attr"`
	} `xml:"work"`
	Classification struct {
		MostPopular string `xml:"sfa,attr"`
	} `xml:"recommendations>ddc>mostPopular"`
}

// database handle
var db *sql.DB
var dbmap *gorp.DbMap

func main() {

	// setup a gorp DB map
	initDB()

	// create a custom HTTP muxer
	mux := gmux.NewRouter()

	// handle the logout logic
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sessions.GetSession(r).Set("User", nil)
		sessions.GetSession(r).Set("Filter", nil)

		http.Redirect(w, r, "/login", http.StatusFound)
	})

	// render the login page and handle authentication
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var p LoginPage
		if r.FormValue("register") != "" {
			secret, _ := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), bcrypt.DefaultCost)
			user := User{r.FormValue("username"), secret}
			if err := dbmap.Insert(&user); err != nil {
				p.Error = err.Error()
			} else {
				sessions.GetSession(r).Set("User", user.Username)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		} else if r.FormValue("login") != "" {
			user, err := dbmap.Get(User{}, r.FormValue("username"))
			if err != nil {
				p.Error = err.Error()
			} else if user == nil {
				p.Error = "No such user found with Username: " + r.FormValue("username")
			} else {
				u := user.(*User)
				if err = bcrypt.CompareHashAndPassword(u.Secret, []byte(r.FormValue("password"))); err != nil {
					p.Error = err.Error()
				} else {
					sessions.GetSession(r).Set("User", u.Username)
					http.Redirect(w, r, "/", http.StatusFound)
					return
				}
			}
		}

		template, err := ace.Load("templates/login", "", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err = template.Execute(w, p); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// render the default page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		// load the ace template
		template, err := ace.Load("templates/index", "", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		// create book DTO and populate the sorted list
		p := Page{Books: []Book{}, Filter: getStringFromSession(r, "Filter"), User: getStringFromSession(r, "User")}
		if !getBookCollection(&p.Books, getStringFromSession(r, "SortBy"), getStringFromSession(r, "Filter"), getStringFromSession(r, "User"), w) {
			return
		}

		// populate the template with the dynamic data
		err = template.Execute(w, p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}).Methods("GET")

	// search for a book from the collection based on a search value
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		var results []SearchResult
		var err error

		if results, err = search(r.FormValue("search")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		encoder := json.NewEncoder(w)
		if err := encoder.Encode(results); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	}).Methods("POST")

	// add a new book and return it's value along with the PK via an HTTP PUT
	mux.HandleFunc("/books", func(w http.ResponseWriter, r *http.Request) {
		// get the book object
		book, err := find(r.FormValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		// insert book via gorp
		b := Book{
			PK:             -1,
			Title:          book.BookData.Title,
			Author:         book.BookData.Author,
			Classification: book.Classification.MostPopular,
			ID:             r.FormValue("id"),
			User:           getStringFromSession(r, "User"),
		}
		err = dbmap.Insert(&b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		// return JSON representing the inserted object
		err = json.NewEncoder(w).Encode(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}).Methods("PUT")

	// Gets a list of books in a filtered fashion
	mux.HandleFunc("/books", func(w http.ResponseWriter, r *http.Request) {
		var b []Book

		if !getBookCollection(&b, getStringFromSession(r, "SortBy"), r.FormValue("filter"), getStringFromSession(r, "User"), w) {
			return
		}

		// save filter value to session
		sessions.GetSession(r).Set("Filter", r.FormValue("filter"))

		err := json.NewEncoder(w).Encode(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}).Methods("GET").Queries("filter", "{filter:all|fiction|nonfiction}")

	// Gets a list of books in a sorted fashion
	mux.HandleFunc("/books", func(w http.ResponseWriter, r *http.Request) {
		var b []Book

		if !getBookCollection(&b, r.FormValue("sortBy"), getStringFromSession(r, "Filter"), getStringFromSession(r, "User"), w) {
			return
		}

		// save sort value to session
		sessions.GetSession(r).Set("SortBy", r.FormValue("sortBy"))

		err := json.NewEncoder(w).Encode(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}).Methods("GET").Queries("sortBy", "{sortBy:title|author|classification}")

	// Deletes a book based on a PK path param
	mux.HandleFunc("/books/{pk}", func(w http.ResponseWriter, r *http.Request) {
		// check to see if the book belongs to the current user.  if not, exit with an error
		pk, _ := strconv.ParseInt(gmux.Vars(r)["pk"], 10, 64)
		var b Book
		err := dbmap.SelectOne(&b, "select * from books where pk=? and user=?", pk, getStringFromSession(r, "User"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		// delete the book
		_, err = dbmap.Delete(&b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.WriteHeader(http.StatusOK)
	}).Methods("DELETE")

	// set up negroni middleware to intercept every request to handle sessions and database connectivity validation
	n := negroni.Classic()
	n.Use(sessions.Sessions("bookstore", cookiestore.New([]byte("my-big-ass-secret-123"))))
	n.Use(negroni.HandlerFunc(verifyDatabase))
	n.Use(negroni.HandlerFunc(verifyUser))

	// instantiate the gorilla muxer
	n.UseHandler(mux)

	// run the server
	n.Run(":8080")
}

// negroni middleware to check db for every route
func verifyDatabase(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	err := db.Ping()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// call the next handler
	next(w, r)
}

// negroni middleware to check for valid username in session
func verifyUser(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// if on login page, avoid redirect loop
	if r.URL.Path == "/login" {
		next(w, r)
		return
	}
	// get user object from DB to make sure it is valid
	username := getStringFromSession(r, "User")
	user, _ := dbmap.Get(User{}, username)
	if user != nil {
		next(w, r)
		return
	}

	// otherwise redirect to login page
	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

// find takes a book id and returns a unmarshalled object corresponding to a single book
func find(id string) (ClassifyBookResponse, error) {
	body, err := classifyAPI("http://classify.oclc.org/classify2/Classify?&summary=true&owi=" + url.QueryEscape(id))
	if err != nil {
		return ClassifyBookResponse{}, err
	}

	var c ClassifyBookResponse
	err = xml.Unmarshal(body, &c)
	return c, err
}

// search calls the book classifier api search method and returns a slice of unmarshalled search response objects
func search(query string) ([]SearchResult, error) {
	body, err := classifyAPI("http://classify.oclc.org/classify2/Classify?&summary=true&title=" + url.QueryEscape(query))
	if err != nil {
		return []SearchResult{}, err
	}

	var c ClassifySearchResponse
	err = xml.Unmarshal(body, &c)
	return c.Results, err
}

// classifyAPI takes a URL corresponding to an API endpoint and returns a bytearray of the response data
func classifyAPI(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

// initializes a gorp db mapping
func initDB() {
	db, _ = sql.Open("sqlite3", "dev.db")
	dbmap = &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}

	dbmap.AddTableWithName(Book{}, "books").SetKeys(true, "pk")
	dbmap.AddTableWithName(User{}, "users").SetKeys(false, "username")
	dbmap.CreateTablesIfNotExists()
}

// get a list of sorted books from the database
func getBookCollection(books *[]Book, sortCol string, filterByClass string, username string, w http.ResponseWriter) bool {

	// just check empty string, route handler deals with checking for valid values
	if sortCol == "" {
		sortCol = "pk"
	}

	// write the where clause for classification
	where := " where user=?"
	if filterByClass == "fiction" {
		where += " and classification between '800' and '900'"
	} else if filterByClass == "nonfiction" {
		where += " and classification not between '800' and '900'"
	}

	// get the book slice and populate the reference param
	_, err := dbmap.Select(books, "select * from books "+where+" order by "+sortCol, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}

	return true
}

// pull an arbitrary key from the session
func getStringFromSession(r *http.Request, key string) string {
	var retVal string
	sessionVal := sessions.GetSession(r).Get(key)
	if sessionVal != nil {
		retVal = sessionVal.(string)
	}
	return retVal
}
