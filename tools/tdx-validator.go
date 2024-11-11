package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-tdx-guest/abi"
	ccpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/google/go-tdx-guest/verify"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <quote-file-path>\n", os.Args[0])
		os.Exit(1)
	}

	quotePath := os.Args[1]

	// Read the quote file
	rawQuote, err := ioutil.ReadFile(quotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Convert raw quote to proto
	anyQuote, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting quote: %v\n", err)
		os.Exit(1)
	}

	// Basic root of trust config
	rootConfig := &ccpb.RootOfTrust{
		CheckCrl:      false,
		GetCollateral: false,
	}

	// Get verification options
	options, err := verify.RootOfTrustToOptions(rootConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating verification options: %v\n", err)
		os.Exit(1)
	}

	// Verify the quote
	if err := verify.TdxQuote(anyQuote, options); err != nil {
		fmt.Println("false")
		os.Exit(1)
	}

	fmt.Println("true")
}
