package main

import (
	"log"
	"strings"

	categorify "github.com/ilyaglow/go-categorify"
	cortex "github.com/ilyaglow/go-cortex"
)

func main() {
	// Grab stdin to JobInput structure
	input, client, err := cortex.NewInput()
	if err != nil {
		log.Fatal(err)
	}

	cat := categorify.NewWithClient(client)

	report, err := cat.Lookup(input.Data)
	if err != nil {
		input.PrintError(err)
	}

	var txs []cortex.Taxonomy
	namespace := "Categorify"
	txs = append(txs, cortex.Taxonomy{
		Namespace: namespace,
		Predicate: "Rating",
		Level:     cortex.TxInfo,
		Value:     report.Rating.Description,
	})
	txs = append(txs, cortex.Taxonomy{
		Namespace: namespace,
		Predicate: "Categories",
		Level:     cortex.TxInfo,
		Value:     strings.Join(report.Categories, ","),
	})

	var keywords []string
	for k := range report.KeywordHeatmap {
		keywords = append(keywords, k)
	}
	txs = append(txs, cortex.Taxonomy{
		Namespace: namespace,
		Predicate: "Keywords",
		Level:     cortex.TxInfo,
		Value:     strings.Join(keywords, ","),
	})

	input.PrintReport(report, txs)
}
