package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/bobziuchkovski/writ"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	strftime "github.com/jehiah/go-strftime"
	"github.com/robfig/cron"
)

type NetDumper struct {
	HelpFlag   bool   `flag:"h, help" description:"Print the tcpdump and libpcap version strings, print a usage message, and exit."`
	IfaceList  bool   `flag:"D,list-interfaces" desctiption:"Print the list of the network interfaces available on the system and on which tcpdump can capture packets"`
	Iface      string `option:"i, interface" placeholder:"interface" default:"" description:"Listen on interface."`
	FileName   string `option:"w" placeholder:"file_name" default:"" description:"Write the raw packets to file. File name should include a time format as defined by strftime(3)". For example: dump_%Y%m%d_%H%M%S.pcap will produce dump_20171121_220010.pcap`
	PostRotate string `option:"z" placeholder:"postrotate-command" default:"" description:"This will make netdump run \"postrotate-command file\", where file is the savefile being closed after each rotation. For example, specifying -z gzip or -z bzip2 will compress each savefile using gzip or bzip2."`
	Cron       string `option:"cron" placeholder:"time" default:"" description:"Specify time in cron format for file saving. For example dump data to new file every 15 minutes of hour: 0 */15 * * * *"`
	SnapLen    int    `option:"s,snapshot-length" default:"262144" placeholder:"snaplen" description:"Snarf snaplen bytes of data from each packet rather than the default of 262144 bytes."`
}

type postRotator struct {
	cmdName string
	args    []string
}

func (pr *postRotator) Run(fileName *os.File, wg *sync.WaitGroup) {
	cmd := exec.Command(pr.cmdName, append(pr.args, fileName.Name())...)
	if err := cmd.Run(); err != nil {
		//result, _ := cmd.CombinedOutput()
		fmt.Fprintf(os.Stderr, "Postrotate command error : %s\n", err)
	}
	wg.Done()
}

func main() {
	netDumper := &NetDumper{}
	cmd := writ.New("netDumper", netDumper)
	cmd.Description = "netdump - dump traffic on a network and write to file at exactly time"
	cmd.Name = "netdump"
	cmd.Help.Usage = "netdump [OPTION] [ expression ]"

	_, positional, err := cmd.Decode(os.Args[1:])
	if err != nil || netDumper.HelpFlag {
		cmd.ExitHelp(err)
	}

	// List interfaces available for capture
	if netDumper.IfaceList {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to get information about interfaces: %s\n", err)
			os.Exit(-1)
		}
		for i, iface := range ifaces {
			fmt.Printf("%d. %s (%s)\n", i+1, iface.Name, iface.Description)
		}
		os.Exit(0)
	}

	// Check file name
	fname := netDumper.FileName
	if fname == "" {
		fmt.Fprintf(os.Stderr, "Need specify file name\n")
		os.Exit(-1)
	} else if fname == strftime.Format(fname, time.Now()) {
		fmt.Fprintf(os.Stderr, "File name must include time format (http://strftime.org/)")
		os.Exit(-1)
	}

	// Check cron format and start task
	if _, err := cron.Parse(netDumper.Cron); err != nil {
		fmt.Fprintf(os.Stderr, "Wron cron format: %s", err)
		os.Exit(-1)
	}
	c := cron.New()

	cronCh := make(chan bool, 1)
	c.AddFunc(netDumper.Cron, func() {
		cronCh <- true
	})
	c.Start()

	//Check postRotateCmd
	var rotator *postRotator = nil
	if netDumper.PostRotate != "" {
		strs := strings.Split(netDumper.PostRotate, " ")
		rotator = &postRotator{
			cmdName: strs[0],
			args:    strs[1:],
		}

		if err = exec.Command(rotator.cmdName).Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Postrotate command error: %s", err)
			os.Exit(-1)
		}
	}

	// open interface
	inactiveHandler, err := pcap.NewInactiveHandle(netDumper.Iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Open interface %s error: %s\n", netDumper.Iface, err)
		os.Exit(-1)
	}
	defer inactiveHandler.CleanUp()

	// snap length
	if err = inactiveHandler.SetSnapLen(-1); err != nil {
		fmt.Fprintf(os.Stderr, "Set snap length error: %s\n", err)
		os.Exit(-1)
	}

	if err = inactiveHandler.SetTimeout(-1); err != nil {
		fmt.Fprintf(os.Stderr, "Set timeout error: %s\n", err)
		os.Exit(-1)
	}

	// Activate capture
	var handle *pcap.Handle
	if handle, err = inactiveHandler.Activate(); err != nil {
		fmt.Printf("Start capture on interface %s error: %s\n", netDumper.Iface, err)
		os.Exit(-1)
	}
	if len(positional) > 0 {
		bpffilter := strings.Join(positional, " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			fmt.Fprintf(os.Stderr, "BPF filter error: %s", err)
			os.Exit(-1)
		}
	}
	defer handle.Close()

	linkType := handle.LinkType()

	// File writer
	var w *pcapgo.Writer
	var file *os.File
	if file, w, err = createFile(fname, time.Now(), linkType); err != nil {
		fmt.Fprint(os.Stdout, err)
		os.Exit(-1)
	}

	var writeMutex sync.Mutex
	go func() {
		for data, ci, err := handle.ZeroCopyReadPacketData(); ; data, ci, err = handle.ZeroCopyReadPacketData() {
			if err != nil {
				fmt.Fprintf(os.Stderr, "Write packet error: %s\n", err)
			}
			writeMutex.Lock()
			w.WritePacket(ci, data)
			writeMutex.Unlock()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	signal.Notify(sigCh, os.Kill)

	wg := &sync.WaitGroup{}
loop:
	for {
		select {
		case <-cronCh:
			writeMutex.Lock()
			oldFile := file
			if file, w, err = createFile(fname, time.Now(), linkType); err != nil {
				fmt.Fprint(os.Stdout, err)
				os.Exit(-1)
			}
			writeMutex.Unlock()

			oldFile.Close()
			if rotator != nil {
				wg.Add(1)
				go rotator.Run(oldFile, wg)
			}

		case <-sigCh:
			writeMutex.Lock()
			file.Close()
			if rotator != nil {
				wg.Add(1)
				go rotator.Run(file, wg)
			}

			break loop
		}

	}
	wg.Wait()
}

func createFile(fileName string, tm time.Time, l layers.LinkType) (file *os.File, w *pcapgo.Writer, err error) {
	fileName = strftime.Format(fileName, tm)
	file, err = os.Create(fileName)
	if err != nil {
		return file, w, fmt.Errorf("Unable to create file %s: %s", fileName, err)
	}

	w = pcapgo.NewWriter(file)

	if err := w.WriteFileHeader(0, l); err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("Unable write to file: %s", err)
	}

	return file, w, nil
}
