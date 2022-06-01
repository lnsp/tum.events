# IN.TUM talks

This is the source repository for the IN.TUM talks service.

## Public sources
- https://www.net.in.tum.de/talks/
- https://db.in.tum.de/research/db_ag/?lang=de

## Architecture

IN.TUM talks uses KV to store all talk data. Talks are stored in the format of `{prefix}_talks_{talkid}`.
The talk structure uses a minimal JSON format where a single character identifies a field. It is defined using
the following Go structure.

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