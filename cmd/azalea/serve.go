package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/1f349/azalea"
	"github.com/1f349/azalea/logger"
	"github.com/1f349/azalea/server"
	"github.com/google/subcommands"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mrmelon54/exit-reload"
	"os"
	"path/filepath"
)

type serveCmd struct{ configPath string }

func (s *serveCmd) Name() string { return "serve" }

func (s *serveCmd) Synopsis() string { return "Serve user authentication service" }

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configPath, "conf", "", "/path/to/config.json : path to the config file")
}

func (s *serveCmd) Usage() string {
	return `serve [-conf <config file>]
  Serve user authentication service using information from the config file
`
}

func (s *serveCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	logger.Logger.Info("Starting...")

	if s.configPath == "" {
		logger.Logger.Error("Config flag is missing")
		return subcommands.ExitUsageError
	}

	openConf, err := os.Open(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Logger.Error("Missing config file")
		} else {
			logger.Logger.Error("Open config file: ", err)
		}
		return subcommands.ExitFailure
	}

	var config server.Conf
	err = json.NewDecoder(openConf).Decode(&config)
	if err != nil {
		logger.Logger.Error("Invalid config file: ", err)
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		logger.Logger.Fatal("Failed to get absolute config path")
	}
	wd := filepath.Dir(configPathAbs)
	normalLoad(config, wd)
	return subcommands.ExitSuccess
}

func normalLoad(startUp server.Conf, wd string) {
	db, err := azalea.InitDB(filepath.Join(wd, "azalea.db.sqlite"))
	if err != nil {
		logger.Logger.Fatal("Failed to open database:", err)
	}

	srv := server.NewDnsServer(startUp, db)
	logger.Logger.Info("Starting server", "addr", srv.Addr)
	srv.Run()

	exit_reload.ExitReload("Azalea", func() {}, func() {
		// stop http server
		_ = srv.Close()
	})
}
