package server

import (
	"context"
	"fmt"
	"github.com/natefinch/lumberjack"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/neo-ngd/neo-go/cli/options"
	"github.com/neo-ngd/neo-go/pkg/config"
	"github.com/neo-ngd/neo-go/pkg/consensus"
	"github.com/neo-ngd/neo-go/pkg/core"
	"github.com/neo-ngd/neo-go/pkg/core/block"
	"github.com/neo-ngd/neo-go/pkg/core/chaindump"
	corestate "github.com/neo-ngd/neo-go/pkg/core/stateroot"
	"github.com/neo-ngd/neo-go/pkg/core/storage"
	"github.com/neo-ngd/neo-go/pkg/io"
	"github.com/neo-ngd/neo-go/pkg/network"
	"github.com/neo-ngd/neo-go/pkg/network/metrics"
	"github.com/neo-ngd/neo-go/pkg/rpc/server"
	"github.com/neo-ngd/neo-go/pkg/services/stateroot"
	"github.com/urfave/cli"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// _winfileSinkRegistered denotes whether zap has registered
	// user-supplied factory for all sinks with `winfile`-prefixed scheme.
	_winfileSinkRegistered bool
	_winfileSinkCloser     func() error
)

// NewCommands returns 'node' command.
func NewCommands() []cli.Command {
	var cfgFlags = []cli.Flag{
		cli.StringFlag{Name: "config-path"},
		cli.BoolFlag{Name: "debug, d"},
	}
	cfgFlags = append(cfgFlags, options.Network...)
	var cfgWithCountFlags = make([]cli.Flag, len(cfgFlags))
	copy(cfgWithCountFlags, cfgFlags)
	cfgWithCountFlags = append(cfgWithCountFlags,
		cli.UintFlag{
			Name:  "count, c",
			Usage: "number of blocks to be processed (default or 0: all chain)",
		},
	)
	var cfgCountOutFlags = make([]cli.Flag, len(cfgWithCountFlags))
	copy(cfgCountOutFlags, cfgWithCountFlags)
	cfgCountOutFlags = append(cfgCountOutFlags,
		cli.UintFlag{
			Name:  "start, s",
			Usage: "block number to start from (default: 0)",
		},
		cli.StringFlag{
			Name:  "out, o",
			Usage: "Output file (stdout if not given)",
		},
	)
	var cfgCountInFlags = make([]cli.Flag, len(cfgWithCountFlags))
	copy(cfgCountInFlags, cfgWithCountFlags)
	cfgCountInFlags = append(cfgCountInFlags,
		cli.StringFlag{
			Name:  "in, i",
			Usage: "Input file (stdin if not given)",
		},
		cli.StringFlag{
			Name:  "dump",
			Usage: "directory for storing JSON dumps",
		},
		cli.BoolFlag{
			Name:  "incremental, n",
			Usage: "use if dump is incremental",
		},
	)
	return []cli.Command{
		{
			Name:   "node",
			Usage:  "start a neo-go-evm node",
			Action: startServer,
			Flags: append(cfgFlags, cli.BoolFlag{
				Name:  "consensus",
				Usage: "try start as consensus or not",
			}),
		},
		{
			Name:  "db",
			Usage: "database manipulations",
			Subcommands: []cli.Command{
				{
					Name:   "dump",
					Usage:  "dump blocks (starting with block #1) to the file",
					Action: dumpDB,
					Flags:  cfgCountOutFlags,
				},
				{
					Name:   "restore",
					Usage:  "restore blocks from the file",
					Action: restoreDB,
					Flags:  cfgCountInFlags,
				},
			},
		},
	}
}

func newGraceContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		cancel()
		signal.Reset(os.Interrupt)
	}()
	return ctx
}

// getConfigFromContext looks at path and mode flags in the given config and
// returns appropriate config.
func getConfigFromContext(ctx *cli.Context) (config.Config, error) {
	configPath := "./config"
	if argCp := ctx.String("config-path"); argCp != "" {
		configPath = argCp
		return config.LoadFile(configPath)
	}
	return config.Load(configPath, options.GetNetwork(ctx))
}

// handleLoggingParams reads logging parameters.
// If user selected debug level -- function enables it.
// If logPath is configured -- function creates dir and file for logging.
// If logPath is configured on Windows -- function returns closer to be
// able to close sink for opened log output file.
func handleLoggingParams(ctx *cli.Context, cfg config.ApplicationConfiguration) (*zap.Logger, func() error, error) {
	level := zapcore.InfoLevel
	if ctx.Bool("debug") {
		level = zapcore.DebugLevel
	}

	ec := zap.NewProductionEncoderConfig()
	ec.EncodeDuration = zapcore.StringDurationEncoder
	ec.EncodeLevel = zapcore.CapitalLevelEncoder
	ec.EncodeTime = zapcore.ISO8601TimeEncoder

	cc := zap.NewProductionConfig()
	cc.EncoderConfig = ec
	cc.DisableCaller = true
	cc.DisableStacktrace = true
	cc.Encoding = "console"
	cc.Level = zap.NewAtomicLevelAt(level)
	cc.Sampling = nil

	if logPath := cfg.LogPath; logPath != "" {
		if err := io.MakeDirForFile(logPath, "logger"); err != nil {
			return nil, nil, err
		}

		if runtime.GOOS == "windows" {
			if !_winfileSinkRegistered {
				// See https://github.com/uber-go/zap/issues/621.
				err := zap.RegisterSink("winfile", func(u *url.URL) (zap.Sink, error) {
					if u.User != nil {
						return nil, fmt.Errorf("user and password not allowed with file URLs: got %v", u)
					}
					if u.Fragment != "" {
						return nil, fmt.Errorf("fragments not allowed with file URLs: got %v", u)
					}
					if u.RawQuery != "" {
						return nil, fmt.Errorf("query parameters not allowed with file URLs: got %v", u)
					}
					// Error messages are better if we check hostname and port separately.
					if u.Port() != "" {
						return nil, fmt.Errorf("ports not allowed with file URLs: got %v", u)
					}
					if hn := u.Hostname(); hn != "" && hn != "localhost" {
						return nil, fmt.Errorf("file URLs must leave host empty or use localhost: got %v", u)
					}
					switch u.Path {
					case "stdout":
						return os.Stdout, nil
					case "stderr":
						return os.Stderr, nil
					}
					f, err := os.OpenFile(u.Path[1:], // Remove leading slash left after url.Parse.
						os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
					_winfileSinkCloser = func() error {
						_winfileSinkCloser = nil
						return f.Close()
					}
					return f, err
				})
				if err != nil {
					return nil, nil, fmt.Errorf("failed to register windows-specific sinc: %w", err)
				}
				_winfileSinkRegistered = true
			}
			logPath = "winfile:///" + logPath
		}

		cc.OutputPaths = []string{logPath}

		hook := &lumberjack.Logger{
			Filename:   fmt.Sprintf("%s/%04d%02d%02d", logPath, time.Now().Year(), time.Now().Month(), time.Now().Day()),
			MaxSize:    1,
			MaxAge:     7,
			Compress:   false,
		}
		ws := zapcore.AddSync(hook)
		encoder := zapcore.NewConsoleEncoder(ec)
		core := zapcore.NewCore(encoder, ws, level)
		return zap.New(core), _winfileSinkCloser, nil
	}

	log, err := cc.Build()
	return log, _winfileSinkCloser, err
}

func initBCWithMetrics(cfg config.Config, log *zap.Logger) (*core.Blockchain, *metrics.Service, *metrics.Service, error) {
	chain, err := initBlockChain(cfg, log)
	if err != nil {
		return nil, nil, nil, cli.NewExitError(err, 1)
	}
	configureAddresses(&cfg.ApplicationConfiguration)
	prometheus := metrics.NewPrometheusService(cfg.ApplicationConfiguration.Prometheus, log)
	pprof := metrics.NewPprofService(cfg.ApplicationConfiguration.Pprof, log)

	go chain.Run()
	go prometheus.Start()
	go pprof.Start()

	return chain, prometheus, pprof, nil
}

func dumpDB(ctx *cli.Context) error {
	cfg, err := getConfigFromContext(ctx)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	log, logCloser, err := handleLoggingParams(ctx, cfg.ApplicationConfiguration)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if logCloser != nil {
		defer func() { _ = logCloser() }()
	}
	count := uint32(ctx.Uint("count"))
	start := uint32(ctx.Uint("start"))

	var outStream = os.Stdout
	if out := ctx.String("out"); out != "" {
		outStream, err = os.Create(out)
		if err != nil {
			return cli.NewExitError(err, 1)
		}
	}
	defer outStream.Close()
	writer := io.NewBinWriterFromIO(outStream)

	chain, prometheus, pprof, err := initBCWithMetrics(cfg, log)
	if err != nil {
		return err
	}
	defer func() {
		pprof.ShutDown()
		prometheus.ShutDown()
		chain.Close()
	}()

	chainCount := chain.BlockHeight() + 1
	if start+count > chainCount {
		return cli.NewExitError(fmt.Errorf("chain is not that high (%d) to dump %d blocks starting from %d", chainCount-1, count, start), 1)
	}
	if count == 0 {
		count = chainCount - start
	}
	writer.WriteU32LE(count)
	err = chaindump.Dump(chain, writer, start, count)
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}
	return nil
}

func restoreDB(ctx *cli.Context) error {
	cfg, err := getConfigFromContext(ctx)
	if err != nil {
		return err
	}
	log, logCloser, err := handleLoggingParams(ctx, cfg.ApplicationConfiguration)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if logCloser != nil {
		defer func() { _ = logCloser() }()
	}
	count := uint32(ctx.Uint("count"))

	var inStream = os.Stdin
	if in := ctx.String("in"); in != "" {
		inStream, err = os.Open(in)
		if err != nil {
			return cli.NewExitError(err, 1)
		}
	}
	defer inStream.Close()
	reader := io.NewBinReaderFromIO(inStream)

	dumpDir := ctx.String("dump")
	if dumpDir != "" {
		cfg.ProtocolConfiguration.SaveStorageBatch = true
	}

	chain, prometheus, pprof, err := initBCWithMetrics(cfg, log)
	if err != nil {
		return err
	}
	defer func() {
		pprof.ShutDown()
		prometheus.ShutDown()
		chain.Close()
	}()

	var start uint32
	if ctx.Bool("incremental") {
		start = reader.ReadU32LE()
		if reader.Err != nil {
			return cli.NewExitError(reader.Err, 1)
		}
		if chain.BlockHeight()+1 < start {
			return cli.NewExitError(fmt.Errorf("expected height: %d, dump starts at %d",
				chain.BlockHeight()+1, start), 1)
		}
	}
	skip := chain.BlockHeight() + 1 - start

	var allBlocks = reader.ReadU32LE()
	if reader.Err != nil {
		return cli.NewExitError(err, 1)
	}
	if skip+count > allBlocks {
		return cli.NewExitError(fmt.Errorf("input file has only %d blocks, can't read %d starting from %d", allBlocks, count, skip), 1)
	}
	if count == 0 {
		count = allBlocks - skip
	}
	log.Info("initialize restore",
		zap.Uint32("start", start),
		zap.Uint32("height", chain.BlockHeight()),
		zap.Uint32("skip", skip),
		zap.Uint32("count", count))

	gctx := newGraceContext()
	var lastIndex uint32
	dump := newDump()
	defer func() {
		_ = dump.tryPersist(dumpDir, lastIndex)
	}()

	var f = func(_ *block.Block) error {
		select {
		case <-gctx.Done():
			return gctx.Err()
		default:
			return nil
		}
	}
	if dumpDir != "" {
		f = func(b *block.Block) error {
			select {
			case <-gctx.Done():
				return gctx.Err()
			default:
			}
			batch := chain.LastBatch()
			// The genesis block may already be persisted, so LastBatch() will return nil.
			if batch == nil && b.Index == 0 {
				return nil
			}
			dump.add(b.Index, batch)
			lastIndex = b.Index
			if b.Index%1000 == 0 {
				if err := dump.tryPersist(dumpDir, b.Index); err != nil {
					return fmt.Errorf("can't dump storage to file: %w", err)
				}
			}
			return nil
		}
	}

	err = chaindump.Restore(chain, reader, skip, count, f)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	return nil
}

func mkConsensus(config network.ServerConfig, chain *core.Blockchain, serv *network.Server, log *zap.Logger) (consensus.Service, error) {
	if config.Wallet == nil {
		return nil, nil
	}
	srv, err := consensus.NewService(consensus.Config{
		Logger:                log,
		Broadcast:             serv.BroadcastExtensible,
		Chain:                 chain,
		ProtocolConfiguration: chain.GetConfig(),
		RequestTx:             serv.RequestTx,
		Wallet:                config.Wallet,
		TimePerBlock:          config.TimePerBlock,
	})
	if err != nil {
		return nil, fmt.Errorf("can't initialize Consensus module: %w", err)
	}

	serv.AddExtensibleHPService(srv, consensus.Category, srv.OnPayload, srv.OnTransaction)
	return srv, nil
}

func startServer(ctx *cli.Context) error {
	cfg, err := getConfigFromContext(ctx)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	asConsensus := ctx.Bool("consensus")

	log, logCloser, err := handleLoggingParams(ctx, cfg.ApplicationConfiguration)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	if logCloser != nil {
		defer func() { _ = logCloser() }()
	}

	grace, cancel := context.WithCancel(newGraceContext())

	serverConfig := network.NewServerConfig(cfg)

	chain, prometheus, pprof, err := initBCWithMetrics(cfg, log)
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	serv, err := network.NewServer(serverConfig, chain, log)
	if err != nil {
		return cli.NewExitError(fmt.Errorf("failed to create network server: %w", err), 1)
	}
	srMod := chain.GetStateModule().(*corestate.Module) // Take full responsibility here.
	sr, err := stateroot.New(serverConfig.StateRootCfg, srMod, log, chain, serv.BroadcastExtensible)
	if err != nil {
		return cli.NewExitError(fmt.Errorf("can't initialize StateRoot service: %w", err), 1)
	}
	serv.AddExtensibleService(sr, stateroot.Category, sr.OnPayload)

	if asConsensus {
		_, err = mkConsensus(serverConfig, chain, serv, log)
		if err != nil {
			return cli.NewExitError(err, 1)
		}
	}

	rpcServer := server.New(chain, cfg.ApplicationConfiguration.RPC, serv, serverConfig.Wallet, log)
	errChan := make(chan error)

	go serv.Start(errChan)
	go func() {
		rpcServer.Start(errChan)
		sighupCh := make(chan os.Signal, 1)
		signal.Notify(sighupCh, syscall.SIGHUP)

		defer cancel()
		defer func() {
			pprof.ShutDown()
			prometheus.ShutDown()
			chain.Close()
		}()
		var shutdownErr error
	Main:
		for {
			select {
			case err := <-errChan:
				shutdownErr = fmt.Errorf("server error: %w", err)
				cancel()
			case sig := <-sighupCh:
				switch sig {
				case syscall.SIGHUP:
					log.Info("SIGHUP received, restarting rpc-server")
					serverErr := rpcServer.Shutdown()
					if serverErr != nil {
						errChan <- fmt.Errorf("error while restarting rpc-server: %w", serverErr)
						break
					}
					rpcServer = server.New(chain, cfg.ApplicationConfiguration.RPC, serv, serverConfig.Wallet, log)
					rpcServer.Start(errChan)
				}
			case <-grace.Done():
				signal.Stop(sighupCh)
				serv.Shutdown()
				if serverErr := rpcServer.Shutdown(); serverErr != nil {
					shutdownErr = fmt.Errorf("error on shutdown: %w", serverErr)
				}
				break Main
			}
		}

		if shutdownErr != nil {
			cli.NewExitError(shutdownErr, 1)
		}
	}()

	fmt.Fprintln(ctx.App.Writer, Logo())
	fmt.Fprintln(ctx.App.Writer, serv.UserAgent)
	fmt.Fprintln(ctx.App.Writer)

	return nil
}

// configureAddresses sets up addresses for RPC, Prometheus and Pprof depending from the provided config.
// In case RPC or Prometheus or Pprof Address provided each of them will use it.
// In case global Address (of the node) provided and RPC/Prometheus/Pprof don't have configured addresses they will
// use global one. So Node and RPC and Prometheus and Pprof will run on one address.
func configureAddresses(cfg *config.ApplicationConfiguration) {
	if cfg.Address != "" {
		if cfg.RPC.Address == "" {
			cfg.RPC.Address = cfg.Address
		}
		if cfg.Prometheus.Address == "" {
			cfg.Prometheus.Address = cfg.Address
		}
		if cfg.Pprof.Address == "" {
			cfg.Pprof.Address = cfg.Address
		}
	}
}

// initBlockChain initializes BlockChain with preselected DB.
func initBlockChain(cfg config.Config, log *zap.Logger) (*core.Blockchain, error) {
	store, err := storage.NewStore(cfg.ApplicationConfiguration.DBConfiguration)
	if err != nil {
		return nil, cli.NewExitError(fmt.Errorf("could not initialize storage: %w", err), 1)
	}

	chain, err := core.NewBlockchain(store, cfg.ProtocolConfiguration, log)
	if err != nil {
		return nil, cli.NewExitError(fmt.Errorf("could not initialize blockchain: %w", err), 1)
	}
	return chain, nil
}

func Logo() string {
	return `
    _   ____________        __________       _________    ____  ___
   / | / / ____/ __ \      / ____/ __ \      / ____/| |  / /  |/  |
  /  |/ / __/ / / / /_____/ / __/ / / /_____/ __/   | | / / /| /| |
 / /|  / /___/ /_/ /_____/ /_/ / /_/ /_____/ /___   | |/ / / |/ | |
/_/ |_/_____/\____/      \____/\____/     /_____/   |___/_/     |_|
`
}
