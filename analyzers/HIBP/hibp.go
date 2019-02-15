package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/ilyaglow/go-cortex"
)

const (
	apiv2Breaches = "https://haveibeenpwned.com/api/v2/breachedaccount/"
	apiv2Pastes   = "https://haveibeenpwned.com/api/v2/pasteaccount/"
)

type report struct {
	Results []result `json:"results"`
}

type result struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	AddedDate    string   `json:"AddedDate"`
	ModifiedDate string   `json:"ModifiedDate"`
	PwnCount     int      `json:"PwnCount"`
	Description  string   `json:"Description"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool     `json:"IsVerified"`
	IsSensitive  bool     `json:"IsSensitive"`
	IsRetired    bool     `json:"IsRetired"`
	IsSpamList   bool     `json:"IsSpamList"`
}

func main() {
	i, client, err := cortex.NewInput()
	if err != nil {
		log.Fatal(err)
	}

	br, btxs, err := getBreaches(client, i.Data)
	if err != nil {
		i.PrintError(err)
	}

	pr, ptxs, err := getPastes(client, i.Data)
	if err != nil {
		i.PrintError(err)
	}

	r := report{}
	if br != nil {
		r.Results = append(r.Results, br...)
	}

	if pr != nil {
		r.Results = append(r.Results, pr...)
	}
	i.PrintReport(r, append(btxs, ptxs...))
}

func getBreaches(c *http.Client, acc string) ([]result, []cortex.Taxonomy, error) {
	resp, err := c.Get(apiv2Breaches + acc)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	var txs []cortex.Taxonomy
	predicate := "Breaches"
	namespace := "HaveIBeenPwned"
	switch resp.StatusCode {
	case 404:
		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     cortex.TxSafe,
			Value:     "0",
		})
		return nil, txs, nil
	case 200:
		var r []result
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&r); err != nil {
			return nil, nil, fmt.Errorf("json decode: %s", err.Error())
		}

		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     cortex.TxSuspicious,
			Value:     strconv.FormatInt(int64(len(r)), 10),
		})

		var vf int
		for i := range r {
			if r[i].IsVerified {
				vf++
			}
		}

		predicate = "Verified"
		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     cortex.TxSuspicious,
			Value:     strconv.FormatInt(int64(vf), 10),
		})

		return r, txs, nil
	default:
		return nil, nil, fmt.Errorf("unexpected status code from haveibeenpwned.com %s", resp.Status)
	}
}

func getPastes(c *http.Client, acc string) ([]result, []cortex.Taxonomy, error) {
	resp, err := c.Get(apiv2Pastes + acc)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	var txs []cortex.Taxonomy
	predicate := "Pastes"
	namespace := "HaveIBeenPwned"
	switch resp.StatusCode {
	case 404:
		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     cortex.TxSafe,
			Value:     "0",
		})
		return nil, txs, nil
	case 200:
		var r []result
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&r); err != nil {
			return nil, nil, fmt.Errorf("json decode: %s", err.Error())
		}

		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     cortex.TxSuspicious,
			Value:     strconv.FormatInt(int64(len(r)), 10),
		})

		return r, txs, nil
	default:
		return nil, nil, fmt.Errorf("unexpected status code from haveibeenpwned.com %s", resp.Status)
	}
}
