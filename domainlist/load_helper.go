package domainlist

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func LoadFormFile(file string) (*List, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return LoadFormReader(f)
}

func LoadFormReader(r io.Reader) (*List, error) {
	l := New()

	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())

		//ignore lines begin with # and empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		fqdn := dns.Fqdn(line)
		if _, ok := dns.IsDomainName(fqdn); !ok {
			return nil, fmt.Errorf("invaild domain [%s]", line)
		}
		l.Add(line)

	}

	return l, nil
}
