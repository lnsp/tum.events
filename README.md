# TUM Events [![Go Reference](https://pkg.go.dev/badge/github.com/lnsp/tum.events.svg)](https://pkg.go.dev/github.com/lnsp/tum.events)

This is the source repository for the TUM Events service available at [tum.events](https://tum.events). 

## Public sources
- https://www.net.in.tum.de/talks/
- https://db.in.tum.de/research/db_ag/?lang=de
- https://www.cs.cit.tum.de/sccs/aktuelles/sccs-kolloquium/

## Architecture

TUM Events uses Valar KV to store all talk data. Talks are stored in the format of `{prefix}_talks_{talkid}`.
The talk structure uses a minimal JSON format where a single character identifies a field. It is defined using
the following Go structure.

### Talks

```go
type Talk struct {
	ID       int64     `json:"i,omitempty"`
	Rank     int64     `json:"-"`
	User     string    `json:"u"`
	Title    string    `json:"t"`
	Category string    `json:"c"`
	Date     time.Time `json:"d"`
	Link     string    `json:"l,omitempty"`
	Body     string    `json:"b,omitempty"`
}
```

Thus, the following JSON block is a valid Talk doc.

```json
{
    "i": 1,
    "u": "go42tum",
    "t": "title",
    "c": "databases",
    "d": "2022-05-18T10:00:00+02:00",
    "l": "https://google.com"
}
```

Talks are synchronized if and only if the talk cache is empty OR the talk doc list changes.

### Login

```go
type Login struct {
	Expiration time.Time `json:"e"`
	User       string    `json:"u"`
	Key        string    `json:"k"`
	Code       string    `json:"c"`
	Attempt    int       `json:"a"`
}
```

### Sessions

A session represents an authenticated user.

```go
type Session struct {
	Expiration time.Time `json:"e"`
	User       string    `json:"u"`
	Key        string    `json:"k"`
}
```

### Verification

```go

type Verification struct {
	Expiration time.Time `json:"e"`
	Talk       *Talk     `json:"t"`
}
```

## Workflow

When developing locally, you most likely want to edit templates & run a local service instance.

```
# To continously render the tailwind.min.css styles, run the following command.
npx tailwindcss -i tailwind.css -m -w -o tailwind.min.css 
# In a second terminal, run & restart the web service as you see fit.
DEBUG=true go run main.go
```
