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
	kvBackend := kv.NewRemoteStore(
		kv.Credentials{
			Token:   os.Getenv("VALAR_TOKEN"),
			Project: os.Getenv("VALAR_PROJECT"),
		})
	store := structs.NewStore(kvBackend, os.Getenv("VALAR_PREFIX"))
	talks, err := store.Talks()
	if err != nil {
		return err
	}
	existingTalks := map[string]struct{}{}
	for _, t := range talks {
		existingTalks[t.Link] = struct{}{}
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
				kind = "bachelor-thesis"
			} else if strings.HasPrefix(titles[i], "Final talk for Master's Thesis") {
				kind = "master-thesis"
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
			talk := &structs.Talk{
				Category: kind,
				User:     "ga87fey",
				Title:    descriptions[i],
				Date:     published,
				Link:     item.Link,
			}
			// to be considered the same, both title and url must be the same
			if _, ok := existingTalks[talk.Link]; ok {
				continue
			}
			// now we can feed it
			if err := store.InsertTalk(talk); err != nil {
				return err
			}
			fmt.Println("Inserted talk", talk.Title)
			count++
		}
	}

	log.Printf("Inserted %d talks", count)

	return nil
}
