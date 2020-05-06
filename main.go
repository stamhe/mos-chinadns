//     Copyright (C) 2020, IrineSistiana
//
//     This file is part of mos-chinadns.
//
//     mos-chinadns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mos-chinadns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/sirupsen/logrus"
)

var (
	version = "dev/unknown"

	configPath  = flag.String("c", "config.json", "[path] load config from file")
	genConfigTo = flag.String("gen", "", "[path] generate a config template here")

	dir                 = flag.String("dir", "", "[path] change working directory to here")
	dirFollowExecutable = flag.Bool("dir2exe", false, "change working directory to the executable that started the current process")

	debug = flag.Bool("debug", false, "more log")
	quite = flag.Bool("quite", false, "no log")

	cpu         = flag.Int("cpu", runtime.NumCPU(), "the maximum number of CPUs that can be executing simultaneously")
	showVersion = flag.Bool("v", false, "show verison")
)

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(*cpu)

	logger := logrus.New()
	switch {
	case *quite:
		logger.SetLevel(logrus.ErrorLevel)
	case *debug:
		logger.SetLevel(logrus.DebugLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}
	entry := logrus.NewEntry(logger)

	// show version
	if *showVersion {
		fmt.Printf("%s\n", version)
		return
	}

	// show summary
	entry.Infof("main: mos-chinadns ver: %s", version)
	entry.Infof("main: arch: %s os: %s", runtime.GOARCH, runtime.GOOS)

	//gen config
	if len(*genConfigTo) != 0 {
		err := genJSONConfig(*genConfigTo)
		if err != nil {
			entry.Errorf("main: can not generate config template, %v", err)
		} else {
			entry.Info("main: config template generated")
		}
		return
	}

	// try to change working dir to os.Executable() or *dir
	var wd string
	if *dirFollowExecutable {
		ex, err := os.Executable()
		if err != nil {
			entry.Fatalf("main: get executable path: %v", err)
		}
		wd = filepath.Dir(ex)
	} else {
		if len(*dir) != 0 {
			wd = *dir
		}
	}
	if len(wd) != 0 {
		err := os.Chdir(wd)
		if err != nil {
			entry.Fatalf("main: change the current working directory: %v", err)
		}
		entry.Infof("main: current working directory: %s", wd)
	}

	//checking
	if len(*configPath) == 0 {
		entry.Fatal("main: need a config file")
	}

	c, err := loadJSONConfig(*configPath)
	if err != nil {
		entry.Fatalf("main: can not load config file, %v", err)
	}

	d, err := initDispatcher(c, entry)
	if err != nil {
		entry.Fatalf("main: init dispatcher: %v", err)
	}

	startServerExitWhenFailed := func(network string) {
		entry.Infof("main: %s server started", network)
		if err := d.ListenAndServe(network); err != nil {
			entry.Fatalf("main: %s server exited with err: %v", network, err)
		} else {
			entry.Infof("main: %s server exited", network)
			os.Exit(0)
		}
	}

	switch c.BindProtocol {
	case "all", "":
		go startServerExitWhenFailed("tcp")
		go startServerExitWhenFailed("udp")
	case "udp":
		go startServerExitWhenFailed("udp")
	case "tcp":
		go startServerExitWhenFailed("tcp")
	default:
		entry.Fatalf("main: unknown bind protocol: %s", c.BindProtocol)
	}

	//wait signals
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	s := <-osSignals
	entry.Infof("main: exiting: signal: %v", s)
	os.Exit(0)
}
