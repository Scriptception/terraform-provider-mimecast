package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/Scriptception/terraform-provider-mimecast/internal/provider"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "start provider in debug mode")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/Scriptception/mimecast",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version+"-"+commit), opts); err != nil {
		log.Fatal(err)
	}
}
