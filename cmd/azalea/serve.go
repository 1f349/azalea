package main

import (
	"context"
	"errors"
	"flag"
	"github.com/1f349/azalea"
	"github.com/1f349/azalea/conf"
	"github.com/1f349/azalea/logger"
	"github.com/1f349/azalea/resolver"
	"github.com/1f349/azalea/server"
	"github.com/1f349/azalea/server/api"
	"github.com/1f349/mjwt"
	"github.com/charmbracelet/log"
	"github.com/cloudflare/tableflip"
	"github.com/google/subcommands"
	"github.com/oschwald/geoip2-golang"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type serveCmd struct {
	configPath string
	debugLog   bool
	pidFile    string
}

func (s *serveCmd) Name() string { return "serve" }

func (s *serveCmd) Synopsis() string { return "Serve user authentication service" }

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configPath, "conf", "", "/path/to/config.json : path to the config file")
	f.BoolVar(&s.debugLog, "debug", false, "enable debug logging")
	f.StringVar(&s.pidFile, "pid-file", "", "path to pid file")
}

func (s *serveCmd) Usage() string {
	return `serve [-conf <config file>] [-debug] [-pid-file <pid file>]
  Serve user authentication service using information from the config file
`
}

func (s *serveCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if s.debugLog {
		logger.Logger.SetLevel(log.DebugLevel)
	}
	logger.Logger.Info("Starting...")

	upg, err := tableflip.New(tableflip.Options{
		PIDFile: s.pidFile,
	})
	if err != nil {
		panic(err)
	}
	defer upg.Stop()

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

	// load the MJWT RSA public key from a pem encoded file
	mJwtVerify, err := mjwt.NewKeyStoreFromDir(afero.NewBasePathFs(afero.NewOsFs(), filepath.Join(wd, "keys")))
	if err != nil {
		logger.Logger.Fatal("Failed to load MJWT verifier public key", "file", filepath.Join(wd, "signer.public.pem"), "err", err)
	}

	db, err := azalea.InitDB(config.DB)
	if err != nil {
		logger.Logger.Fatal("Failed to open database", "err", err)
	}

	var openGeo *geoip2.Reader
	if config.GeoIP != "" {
		logger.Logger.Info("Loading GeoIP database", "db", config.GeoIP)
		openGeo, err = geoip2.Open(filepath.Join(wd, config.GeoIP))
		if err != nil {
			logger.Logger.Fatal("Failed to open GeoIP DB", "err", err)
		}
	}

	geoRes := resolver.NewGeoResolver(openGeo, db)
	res := resolver.NewResolver(config.Soa, db, geoRes)

	dnsTcp, err := upg.Listen("tcp", config.Listen.Dns)
	if err != nil {
		logger.Logger.Fatal("Listen failed", "err", err)
	}
	dnsUdp, err := upg.ListenPacket("udp", config.Listen.Dns)
	if err != nil {
		logger.Logger.Fatal("Listen failed", "err", err)
	}

	dnsSrv := server.NewDnsServer(dnsTcp, dnsUdp, res)
	logger.Logger.Info("Starting server", "addr", config.Listen.Dns)
	dnsSrv.Run()

	var apiSrv *http.Server
	if config.Master {
		lnApi, err := upg.Listen("tcp", config.Listen.Api)
		if err != nil {
			logger.Logger.Fatal("Listen failed", "err", err)
		}

		apiMux := api.NewApiServer(db, res, mJwtVerify, config.MetricsAuth)
		apiSrv = &http.Server{
			Handler:           apiMux,
			ReadTimeout:       time.Minute,
			ReadHeaderTimeout: time.Minute,
			WriteTimeout:      time.Minute,
			IdleTimeout:       time.Minute,
			MaxHeaderBytes:    2500,
		}
		logger.Logger.Info("Starting API server", "addr", config.Listen.Api)
		go func() {
			err := apiSrv.Serve(lnApi)
			switch {
			case err == nil:
				return
			case errors.Is(err, http.ErrServerClosed):
				return
			default:
				logger.Logger.Error("Failed to start API server", "err", err)
			}
		}()
	}

	// Do an upgrade on SIGHUP
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			err := upg.Upgrade()
			if err != nil {
				logger.Logger.Error("Failed upgrade", "err", err)
			}
		}
	}()

	logger.Logger.Info("Ready")
	if err := upg.Ready(); err != nil {
		panic(err)
	}
	<-upg.Exit()

	time.AfterFunc(30*time.Second, func() {
		logger.Logger.Warn("Graceful shutdown timed out")
		os.Exit(1)
	})

	dnsSrv.Close()
	if apiSrv != nil {
		_ = apiSrv.Shutdown(context.Background())
	}

	return subcommands.ExitSuccess
}
