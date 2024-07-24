package main

import (
	"context"
	"flag"
	"github.com/1f349/azalea"
	"github.com/1f349/azalea/conf"
	"github.com/1f349/azalea/logger"
	"github.com/1f349/azalea/resolver"
	"github.com/1f349/azalea/server"
	"github.com/1f349/azalea/server/api"
	"github.com/1f349/mjwt"
	"github.com/charmbracelet/log"
	"github.com/google/subcommands"
	"github.com/mrmelon54/exit-reload"
	"github.com/oschwald/geoip2-golang"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type serveCmd struct {
	configPath string
	debugLog   bool
}

func (s *serveCmd) Name() string { return "serve" }

func (s *serveCmd) Synopsis() string { return "Serve user authentication service" }

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configPath, "conf", "", "/path/to/config.json : path to the config file")
	f.BoolVar(&s.debugLog, "debug", false, "enable debug logging")
}

func (s *serveCmd) Usage() string {
	return `serve [-conf <config file>] [-debug]
  Serve user authentication service using information from the config file
`
}

func (s *serveCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if s.debugLog {
		logger.Logger.SetLevel(log.DebugLevel)
	}
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
			logger.Logger.Error("Open config file", "err", err)
		}
		return subcommands.ExitFailure
	}

	var config conf.Conf
	err = yaml.NewDecoder(openConf).Decode(&config)
	if err != nil {
		logger.Logger.Error("Invalid config file", "err", err)
		return subcommands.ExitFailure
	}

	configPathAbs, err := filepath.Abs(s.configPath)
	if err != nil {
		logger.Logger.Fatal("Failed to get absolute config path", "err", err)
	}
	wd := filepath.Dir(configPathAbs)
	normalLoad(config, wd)
	return subcommands.ExitSuccess
}

func normalLoad(startUp conf.Conf, wd string) {
	// load the MJWT RSA public key from a pem encoded file
	mJwtVerify, err := mjwt.NewMJwtVerifierFromFile(filepath.Join(wd, "signer.public.pem"))
	if err != nil {
		logger.Logger.Fatal("Failed to load MJWT verifier public key", "file", filepath.Join(wd, "signer.public.pem"), "err", err)
	}

	db, err := azalea.InitDB(startUp.DB)
	if err != nil {
		logger.Logger.Fatal("Failed to open database", "err", err)
	}

	var openGeo *geoip2.Reader
	if startUp.GeoIP != "" {
		logger.Logger.Info("Loading GeoIP database", "db", startUp.GeoIP)
		openGeo, err = geoip2.Open(filepath.Join(wd, startUp.GeoIP))
		if err != nil {
			logger.Logger.Fatal("Failed to open GeoIP DB", "err", err)
		}
	}

	geoRes := resolver.NewGeoResolver(openGeo, db)
	res := resolver.NewResolver(startUp.Soa, db, geoRes)

	dnsSrv := server.NewDnsServer(startUp, res)
	logger.Logger.Info("Starting server", "addr", dnsSrv.Addr)
	dnsSrv.Run()

	if startUp.Master {
		apiMux := api.NewApiServer(db, res, mJwtVerify, startUp.MetricsAuth)
		apiSrv := &http.Server{
			Addr:              startUp.ApiListen,
			Handler:           apiMux,
			ReadTimeout:       time.Minute,
			ReadHeaderTimeout: time.Minute,
			WriteTimeout:      time.Minute,
			IdleTimeout:       time.Minute,
			MaxHeaderBytes:    2500,
		}
		logger.Logger.Info("Starting API server", "addr", apiSrv.Addr)
		go func() {
			err := apiSrv.ListenAndServe()
			if err != nil {
				logger.Logger.Error("Failed to start API server", "err", err)
			}
		}()
	}

	exit_reload.ExitReload("Azalea", func() {}, func() {
		// stop dns server
		dnsSrv.Close()
	})
}
