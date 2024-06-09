package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lnsp/tum.events/blob"
	"github.com/lnsp/tum.events/kv"
	"github.com/lnsp/tum.events/structs"
	"github.com/microcosm-cc/bluemonday"
	"github.com/mmcdole/gofeed"
	"gopkg.in/yaml.v2"
)

var (
	cronUser = flag.String("user", "ga87fey", "Cron user to submit talks")
	dryRun   = flag.Bool("dryrun", true, "Print talks to-be-inserted instead of submitting them")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

type TalkSource interface {
	Fetch() ([]*structs.Talk, error)
}

func run() error {
	// fetch all existing talks
	kvBackend := kv.NewRemoteStore(
		kv.Credentials{
			Token:   os.Getenv("VALAR_TOKEN"),
			Project: os.Getenv("VALAR_PROJECT"),
		})
	storage := structs.NewStorage(kvBackend, blob.WithInMemoryBackend(""), os.Getenv("VALAR_PREFIX"))
	talks, err := storage.Talks()
	if err != nil {
		return err
	}
	existingTalks := map[string]struct{}{}
	for _, t := range talks {
		existingTalks[t.Link] = struct{}{}
	}

	srcs := []TalkSource{TUMuchData{}, NetInTum{}}
	scraped := []*structs.Talk{}
	for _, src := range srcs {
		fetched, err := src.Fetch()
		if err != nil {
			log.Printf("Fetch talks from %T: %s", src, err)
			continue
		}
		scraped = append(scraped, fetched...)
	}

	count := 0
	for _, talk := range scraped {
		// to be considered the same, both title and url must be the same
		if _, ok := existingTalks[talk.Link]; ok {
			continue
		}
		talk.User = *cronUser
		if !*dryRun {
			// now we can feed it
			if err := storage.InsertTalk(talk); err != nil {
				return err
			}
		}
		fmt.Println("Inserted talk", talk.Title)
		count++
	}

	if !*dryRun {
		log.Printf("Inserted %d talks", count)
	}

	return nil
}

type NetInTum struct{}

func (NetInTum) Fetch() ([]*structs.Talk, error) {
	// fetch talk data
	fp := gofeed.NewParser()
	feed, err := fp.ParseURL("https://www.net.in.tum.de/rss/talks.xml")
	if err != nil {
		return nil, err
	}
	talks := []*structs.Talk{}
	for _, item := range feed.Items {
		titles := strings.Split(item.Custom["content"], "\n")
		descriptions := strings.Split(item.Description, "\n")
		for i := range titles {
			kind := ""
			if strings.HasPrefix(titles[i], "Final talk for Bachelor's Thesis") {
				kind = "bachelor-thesis"
			} else if strings.HasPrefix(titles[i], "Final talk for Master's Thesis") {
				kind = "master-thesis"
			} else {
				continue
			}
			published, err := time.Parse("02.01.2006 15:04 -0700", fmt.Sprintf("%s 16:00 +0100", item.Published))
			if err != nil {
				return nil, err
			}
			if time.Now().After(published) {
				continue
			}
			talks = append(talks, &structs.Talk{
				Category: kind,
				Title:    descriptions[i],
				Date:     published,
				Link:     item.Link,
			})
		}
	}
	return talks, nil
}

type TUMuchData struct{}

func (TUMuchData) Fetch() ([]*structs.Talk, error) {
	eventsYamlSrc := "https://raw.githubusercontent.com/tumuchdata/tumuchdata.github.io/main/data/events.yaml"
	eventsYamlResp, err := http.Get(eventsYamlSrc)
	if err != nil {
		return nil, err
	}
	defer eventsYamlResp.Body.Close()

	decoder := yaml.NewDecoder(eventsYamlResp.Body)
	events := []struct {
		Title        string `yaml:"title"`
		Description  string `yaml:"description"`
		StartTimeStr string `yaml:"start"`
		Location     string `yaml:"location"`
	}{}
	if err := decoder.Decode(&events); err != nil {
		return nil, err
	}

	berlinTz, _ := time.LoadLocation("Europe/Berlin")
	talks := []*structs.Talk{}
	for _, e := range events {
		timestamp, _ := time.ParseInLocation("2006-01-02T15:04:05", e.StartTimeStr, berlinTz)
		if time.Now().After(timestamp) {
			continue
		}

		sanitizer := bluemonday.StrictPolicy()
		description := sanitizer.Sanitize(e.Description)

		headline, _, _ := strings.Cut(description, "\n")
		headline, _ = strings.CutPrefix(headline, "Weekly Paper Reading Group. ")

		talks = append(talks, &structs.Talk{
			Category: "databases",
			Title:    sanitizer.Sanitize(e.Title) + " - " + headline,
			Link:     "https://www.tumuchdata.club/events/#" + e.StartTimeStr,
			Date:     timestamp,
		})
	}

	return talks, nil
}
