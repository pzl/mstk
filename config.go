package mstk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pzl/mstk/logger"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

// This is a wrapper around koanf and pflag
// It includes some universally common flags (-v, -c (config))
// and standardizes the config loading order to
// file < environment < flag
// and it includes some config directory file searching.
// basically adds back some convenience that viper had
// but with the flexibility of koanf
type Config struct {
	Log       *logrus.Logger
	K         *koanf.Koanf
	confDir   string
	confNames []string
}

func ConfigFiles(n ...string) func(*Config) {
	return func(c *Config) {
		c.confNames = n
	}
}

func NewConfig(dir string, opts ...func(*Config)) *Config {
	c := &Config{
		Log:       logger.NewBuffered(),
		K:         koanf.New("."),
		confDir:   dir,
		confNames: []string{dir},
	}
	for _, o := range opts {
		if o != nil {
			o(c)
		}
	}
	return c
}

func (c *Config) SearchDir(dir string) {
	exts := map[string]struct{}{
		".js":   struct{}{},
		".json": struct{}{},
		".toml": struct{}{},
		".tml":  struct{}{},
		".yaml": struct{}{},
		".yml":  struct{}{},
		".conf": struct{}{},
		".cnf":  struct{}{},
		".ini":  struct{}{},
	}

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error { //nolint
		if err != nil {
			if !os.IsNotExist(err) {
				c.Log.WithError(err).Error("unable to search config dir")
			}
			return err
		}

		l := c.Log.WithFields(logrus.Fields{
			"path":  path,
			"name":  info.Name(),
			"isdir": info.IsDir(),
		})
		l.Trace("searching config dir..")

		if dir == info.Name() {
			l.Trace("skipping. Is top-level directory")
			return nil // top-level dir
		}

		if info.IsDir() {
			l.Trace("skipping, is directory")
			return filepath.SkipDir
		}
		filename := info.Name()
		li := strings.LastIndex(filename, ".")
		if li < 1 {
			l.Trace("skipping. Is hidden or no extension")
			return nil // starts with dot (hidden) or has no extension
		}
		name := filename[:li]

		match := false
		for _, f := range c.confNames {
			if strings.ToLower(name) == strings.ToLower(f) {
				match = true
				break
			}
		}
		if !match {
			l.Trace("skipping, filename does not match")
			return nil
		}

		ext := filename[li:]
		if _, ok := exts[ext]; ok {
			l.Trace("loading file!")
			parser, err := fileParser(filename)
			if err != nil {
				l.WithError(err).Error("unable to determine parser for file")
				return err
			}
			c.Log.WithField("file", path).Debug("Loading config file")
			err = c.K.Load(file.Provider(path), parser)
			if err != nil {
				l.WithError(err).Error("unable to parse file")
			}
			return err
		}
		l.Trace("did not have the correct extension")
		return nil
	})
}

func fileParser(filename string) (koanf.Parser, error) {
	ext := filepath.Ext(filename)
	switch ext {
	case ".js", ".json":
		return json.Parser(), nil
	case ".toml", ".tml", ".conf", ".cnf", ".ini":
		return toml.Parser(), nil
	case ".yaml", ".yml":
		return yaml.Parser(), nil
	}

	// attempt to determine from file contents
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, 50)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}

	buf = bytes.TrimSpace(buf)
	// best guesses by syntax
	switch buf[0] {
	case '{':
		return json.Parser(), nil
	case '[':
		return toml.Parser(), nil
	}

	// looks like a yaml list somewhere in the file
	if yamlList := regexp.MustCompile(`(?im)^\s*- \w+`); yamlList.Match(buf) {
		return yaml.Parser(), nil
	}

	// look at  key: value  vs key =
	eql := regexp.MustCompile(`(?im)^\w+\s*([=:])\s*`)
	if match := eql.FindSubmatch(buf); match != nil {
		switch match[1][0] {
		case ':':
			return yaml.Parser(), nil
		case '=':
			return toml.Parser(), nil
		}
	}

	return nil, fmt.Errorf("no provider found for file %s", filename)
}

func xdgCfgHome(dir string) string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, dir)
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", dir)
	}
	return filepath.Join("/etc/xdg", dir)
}

// sets logger level, based on -v count
func logLvl(log *logrus.Logger, v int) {
	lvls := []logrus.Level{
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
		logrus.TraceLevel,
	}
	if v > 3 {
		v = 3
	} else if v < 0 {
		v = 0
	}
	log.SetLevel(lvls[v])
}

// searches default config dirs, and CONFIG_DIR, -d and -c into koanf
func (c *Config) LoadConfigFiles(app string) error {
	c.SearchDir(filepath.Join("/etc", app))
	c.SearchDir(xdgCfgHome(app))
	c.SearchDir(".")
	if cdir := os.Getenv("CONFIG_DIR"); cdir != "" {
		c.SearchDir(cdir) //search $CONFIG_DIR if passed in env
	}

	if !pflag.Parsed() {
		return errors.New("call Parse() before loading config files")
	}
	if cd, err := pflag.CommandLine.GetString("conf-dir"); err == nil && cd != "" {
		c.SearchDir(cd) // load --conf-dir  if passed as a flag
	}
	if cf, err := pflag.CommandLine.GetString("config"); err == nil && cf != "" {
		// load explicit config file if passed as -c
		parser, err := fileParser(cf)
		if err != nil {
			return err
		}
		return c.K.Load(file.Provider(cf), parser)
	}
	return nil
}

// loads env vars into koanf
func (c *Config) LoadEnv() error {
	return c.K.Load(env.Provider("", ".", func(key string) string {
		return strings.Replace(strings.ToLower(key), "_", "-", 0)
	}), nil)
}

// alias for loading pflag into koanf
func (c *Config) LoadFlags() error {
	return c.K.Load(posflag.Provider(pflag.CommandLine, ".", c.K), nil)
}

// adds common defined flags (-d, -c, -j, -v)
func (c *Config) CommonFlags() *pflag.FlagSet {
	common := pflag.NewFlagSet("common", pflag.ExitOnError)
	common.StringP("conf-dir", "d", "", "Search this directory for config files")
	common.StringP("config", "c", "", "Config file to read values from")
	common.BoolP("json", "j", false, "output logs in JSON formt")
	common.CountP("verbose", "v", "increased logging. can use multiple times for more")
	return common
}

// Sets logger output format (+ flushes if needed)
func (c *Config) logFmt() error {
	j, err := pflag.CommandLine.GetBool("json")
	if err != nil {
		return err
	}
	logger.SetFormat(c.Log, j)

	return nil
}

/*
Parses all configurations from the various sources:

- Config Files (via config dirs, files, incl those specified via ENV vars or flags)
- Environment variables
- Flags

And sets up the configured logger level (-v) and output (-j). This will flush the log buffer if buffered.

*/
func (c *Config) Parse() error {
	pflag.Parse()

	v, err := pflag.CommandLine.GetCount("verbose")
	if err != nil {
		return err
	}
	logLvl(c.Log, v)

	if err := c.LoadConfigFiles(c.confDir); err != nil {
		return err
	}
	if err := c.LoadEnv(); err != nil { // load environments next
		return err
	}
	if err := c.LoadFlags(); err != nil { // load CLI flags last
		return err
	}
	if err := c.logFmt(); err != nil {
		return err
	}
	return nil
}

// Convenience function for adding pflags
func (c *Config) SetFlags(f func(*pflag.FlagSet)) { f(pflag.CommandLine) }
