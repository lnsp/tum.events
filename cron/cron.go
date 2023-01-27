package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lnsp/tumtalks/kv"
	"github.com/lnsp/tumtalks/structs"
	"github.com/mmcdole/gofeed"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// fetch all existing talks
	store := structs.NewStore(&kv.Credentials{
		Token:   os.Getenv("VALAR_TOKEN"),
		Project: os.Getenv("VALAR_PROJECT"),
	}, os.Getenv("VALAR_PREFIX"))
	talks, err := store.Talks()
	if err != nil {
		return err
	}
	existingTalks := map[string]string{}
	for _, t := range talks {
		existingTalks[t.Title] = t.Link
	}

	// fetch talk data
	fp := gofeed.NewParser()
	feed, err := fp.ParseURL("https://www.net.in.tum.de/rss/talks.xml")
	if err != nil {
		return err
	}
	count := 0
	for _, item := range feed.Items {
		titles := strings.Split(item.Custom["content"], "\n")
		descriptions := strings.Split(item.Description, "\n")
		for i := range titles {
			kind := ""
			if strings.HasPrefix(titles[i], "Final talk for Bachelor's Thesis") {
				kind = "Bachelor's Thesis"
			} else if strings.HasPrefix(titles[i], "Final talk for Master's Thesis") {
				kind = "Master's Thesis"
			} else {
				continue
			}
			published, err := time.Parse("02.01.2006 15:04 -0700", fmt.Sprintf("%s 16:00 +0100", item.Published))
			if err != nil {
				return err
			}
			if time.Now().After(published) {
				continue
			}
			title := fmt.Sprintf("%s (%s)", descriptions[i], kind)
			talk := &structs.Talk{
				Category: "computer-networks",
				User:     "ga87fey",
				Title:    title,
				Date:     published,
				Link:     item.Link,
			}
			// to be considered the same, both title and url must be the same
			if existingTalks[talk.Title] == talk.Link {
				continue
			}
			log.Printf("Added talk with ID %d", talk.ID)
			// now we can feed it
			if err := store.InsertTalk(talk); err != nil {
				return err
			}
			count++
		}
	}

	log.Printf("Inserted %d talks", count)

	return nil
}
