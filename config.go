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
	"encoding/json"
	"io/ioutil"
	"os"
)

// Config is config
type Config struct {
	BindAddr            string `json:"bind_addr"`
	BindProtocol        string `json:"bind_protocol"`
	LocalServerAddr     string `json:"local_server_addr"`
	LocalServerProtocol string `json:"local_server_protocol"`
	LocalServerURL      string `json:"local_server_url"`
	LocalServerPEMCA    string `json:"local_server_pem_ca"`

	LocalDenyUnusualType      bool `json:"local_deny_unusual_type"`
	LocalDenyResultsWithoutIP bool `json:"local_deny_results_without_ip"`
	LocalCheckCNAME           bool `json:"local_check_cname"`

	LocalIPPolicies     string `json:"local_ip_policies"`
	LocalDomainPolicies string `json:"local_domain_policies"`

	RemoteServerAddr       string `json:"remote_server_addr"`
	RemoteServerProtocol   string `json:"remote_server_protocol"`
	RemoteServerURL        string `json:"remote_server_url"`
	RemoteServerPEMCA      string `json:"remote_server_pem_ca"`
	RemoteServerDelayStart int    `json:"remote_server_delay_start"`

	LocalECSSubnet  string `json:"local_ecs_subnet"`
	RemoteECSSubnet string `json:"remote_ecs_subnet"`
}

func loadJSONConfig(configFile string) (*Config, error) {
	c := new(Config)
	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}

	return c, nil
}

func genJSONConfig(configFile string) error {
	c := new(Config)

	f, err := os.Create(configFile)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return err
	}

	_, err = f.Write(b)

	return err
}
