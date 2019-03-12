package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/PuerkitoBio/goquery"
	"github.com/ilyaglow/go-cortex"
)

const miraiSearch = "https://mirai.badpackets.net/?source_ip_address=%s&country=&autonomous_system=&asn=&first_seen__gt=&first_seen__lt="

// Entry represents a found entry
type Entry struct {
	Address       string `json:"ip"`
	ASN           string `json:"asn"`
	ASDescription string `json:"as_description"`
	Country       string `json:"country"`
	FirstSeen     string `json:"first_seen"`
}

// Report is a highest level struct for results
type Report struct {
	Entries []*Entry `json:"entries"`
}

func main() {
	input, client, err := cortex.NewInput()
	if err != nil {
		log.Fatal(err)
	}

	http.DefaultClient = client
	ent, err := findByIP(input.Data)
	if err != nil {
		input.PrintError(err)
	}

	var txs []cortex.Taxonomy
	namespace := "BadPackets"
	predicate := "Mirai"
	if ent == nil {
		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     cortex.TxSafe,
			Value:     false,
		})
	} else {
		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     cortex.TxMalicious,
			Value:     true,
		})

		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: "Country",
			Level:     cortex.TxInfo,
			Value:     ent.Country,
		})

		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: "ASN",
			Level:     cortex.TxInfo,
			Value:     ent.ASN,
		})

		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: "ASDescription",
			Level:     cortex.TxInfo,
			Value:     ent.ASDescription,
		})

		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: "FirstSeen",
			Level:     cortex.TxInfo,
			Value:     ent.FirstSeen,
		})
	}

	input.PrintReport(&Report{Entries: []*Entry{ent}}, txs)
}

func findByIP(ip string) (*Entry, error) {
	resp, err := http.Get(fmt.Sprintf(miraiSearch, ip))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	s := doc.Find("tbody tr").First()
	if s.Length() == 0 {
		return nil, nil
	}

	entry := &Entry{
		Address:       s.Find("td:first-child a").Text(),
		ASDescription: s.Find("td:nth-child(2)").Text(),
		Country:       s.Find("td:nth-child(3)").Text(),
		ASN:           s.Find("td:nth-child(4) a").Text(),
		FirstSeen:     s.Find("td:nth-child(5)").Text(),
	}

	return entry, nil
}
