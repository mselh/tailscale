// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !freebsd && !windows && !darwin
// +build !freebsd,!windows,!darwin

package monitor

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"sync"
	"time"

	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
)

func newPollingMon(logf logger.Logf, m *Mon) (osMon, error) {
	return &pollingMon{
		logf: logf,
		m:    m,
		stop: make(chan struct{}),
	}, nil
}

// pollingMon is a bad but portable implementation of the link monitor
// that works by polling the interface state every 10 seconds, in lieu
// of anything to subscribe to.
type pollingMon struct {
	logf logger.Logf
	m    *Mon

	closeOnce sync.Once
	stop      chan struct{}
}

func (pm *pollingMon) Close() error {
	pm.closeOnce.Do(func() {
		close(pm.stop)
	})
	return nil
}

func (pm *pollingMon) isCloudRun() bool {
	// https: //cloud.google.com/run/docs/reference/container-contract#env-vars
	if os.Getenv("K_REVISION") == "" || os.Getenv("K_CONFIGURATION") == "" ||
		os.Getenv("K_SERVICE") == "" || os.Getenv("PORT") == "" {
		return false
	}
	vers, err := os.ReadFile("/proc/version")
	if err != nil {
		pm.logf("Failed to read /proc/version: %v", err)
		return false
	}
	return string(bytes.TrimSpace(vers)) == "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016"
}

func (pm *pollingMon) Receive() (message, error) {
	d := 10 * time.Second
	if runtime.GOOS == "android" {
		// We'll have Android notify the link monitor to wake up earlier,
		// so this can go very slowly there, to save battery.
		// https://github.com/tailscale/tailscale/issues/1427
		d = 10 * time.Minute
	}
	if pm.isCloudRun() {
		// Cloud Run routes never change at runtime. the containers are killed within
		// 15 minutes by default, set the interval long enough to be effectively infinite.
		pm.logf("monitor polling: Cloud Run detected, reduce polling interval to 24h")
		d = 24 * time.Hour
	}
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	base := pm.m.InterfaceState()
	for {
		if cur, err := pm.m.interfaceStateUncached(); err == nil && !cur.EqualFiltered(base, interfaces.UseInterestingInterfaces, interfaces.UseInterestingIPs) {
			return unspecifiedMessage{}, nil
		}
		select {
		case <-ticker.C:
		case <-pm.stop:
			return nil, errors.New("stopped")
		}
	}
}
