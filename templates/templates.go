package templates

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path"
	"time"
)

//go:embed favicon.png
var Favicon []byte

//go:embed tailwind.min.css
var TailwindStyles []byte

//go:embed *.html
var webTemplates embed.FS

const localTimeFormat = "2006-01-02T15:04"

var templateFuncs = template.FuncMap{
	"humandate": func(t time.Time) string {
		return t.Format("02.01.2006 15:04")
	},
	"formdate": func(t time.Time) string {
		location, _ := time.LoadLocation("Europe/Berlin")
		return t.In(location).Format(localTimeFormat)
	},
	"inc": func(i int) int {
		return i + 1
	},
}

var templates = map[string]*template.Template{}

func init() {
	for _, t := range []string{"categories.html", "submit.html", "top.html", "confirm.html", "legal.html", "talk.html", "login.html", "login-code.html", "edit.html", "filter.html", "profile.html"} {
		templates[path.Base(t)] = template.Must(template.New("base.html").Funcs(templateFuncs).ParseFS(webTemplates, "base.html", t))
	}
}

type ErrorNotFound struct {
	Name string
}

func (err ErrorNotFound) Error() string {
	return fmt.Sprintf("template '%s' not found", err.Name)
}

func Execute(name string, writer io.Writer, data any) error {
	tmpl, ok := templates[name]
	if !ok {
		return ErrorNotFound{name}
	}
	return tmpl.Execute(writer, data)
}

type Context struct {
	Build      string
	Error      string
	Login      string
	SessionKey string
	CSRFToken  template.HTML
}

func (a *Context) Authenticated() bool {
	return a.Login != ""
}

type ContextFunc func(http.ResponseWriter, *http.Request) Context
