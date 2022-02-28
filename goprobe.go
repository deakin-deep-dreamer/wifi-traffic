package main

import (
  "fmt"
  "os"
  "io"
  "path"
  "time"
  "encoding/json"
  "runtime"
  "net/http"
  "bytes"
  "io/ioutil"

  "wifi-traffic/goprobe/probe"

  // "github.com/sidepelican/goprobe/probe"
  "github.com/BurntSushi/toml"
  "github.com/lestrrat/go-file-rotatelogs"
)

const (
  topic = "/goprobe"
  logPath = "/var/log/goprobe.log"
)

type Config struct {
  Device string
}

func mainLoop() {
  defer func() {
    if err := recover(); err != nil {
      log.Println("recover: ", err)
    }
  }()

  // logging setup
  log.SetFlags(0)
  rl, err := makeRotateLogs()
  if err != nil {
    log.Println("error setup rotatelogs: %v", err)
  } else {
    log.Println("logging to ", logPath)
    defer rl.Close()
    log.SetOutput(io.MultiWriter(rl, os.Stdout))
  }

  config := loadConfig()

  // start packet capturing
  source, err := probe.NewProbeSource(config.Device)
  if err != nil {
    log.Fatal(err)
  }
  defer source.Close()

  for record := range source.Records {
    log.Println(record.String())
  }
}

func makeRotateLogs() (*rotatelogs.RotateLogs, error) {
  return rotatelogs.New(
    logPath+".%Y%m%d",
    rotatelogs.WithLinkName(logPath),
    rotatelogs.WithRotationTime(time.Hour),
    rotatelogs.WithMaxAge(0),
  )
}

func findConfigPath() (string, error) {
  const configFileName = "config.tml"
  errret := fmt.Errorf("%s not found at: ", configFileName)

  // current dir
	pwd, err := os.Getwd()
	if err == nil {
		p := pwd + "/" + configFileNAme
		if exists(p) {
			return p, nil
		}
		errret = fmt.Errorf("%v\n\t%v", errret, p)
	}

  return "", errret
}

func loadConfig() (config Config) {
  path, err := findConfigPath()
  if err != nil {
    log.Println(err)
    return
  }
  log.Println("load config:", path)

  // decode const settings
  if _, err := toml.DecodeFile(path, &config); err != nil {
    log.Println(err)
    return
  }

  return
}


func main() {
	// nextOdd := makeOddGenerator()
	// fmt.Println(nextOdd())
	// fmt.Println(nextOdd())
	// fmt.Println(nextOdd())

	fmt.Println("Start...")
	for {
		mainLoop()
	}
}
