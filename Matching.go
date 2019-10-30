package main

import (
	"github.com/Mimoja/MFT-Common"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/hillu/go-yara"
	"io/ioutil"
	"os"
	"time"
)

var yaraRules *yara.Rules

func setupYara() {
	c, err := yara.NewCompiler()
	if err != nil {
		Bundle.Log.Fatal("Could not create yara compiler")
	}

	file, err := os.Open("rules.yara")
	if err != nil {
		Bundle.Log.Fatalf("Could not load rules: %v", err)
	}

	c.AddFile(file, "test")

	r, err := c.GetRules()
	if err != nil {
		Bundle.Log.Fatalf("Failed to compile rules: %s", err)
	}
	yaraRules = r
}

func analyse(entry MFTCommon.FlashImage) error {
	Bundle.Log.Infof("Searching for Magic Bytes: %s", entry.ID.GetID())

	reader, err := Bundle.Storage.GetFile(entry.ID.GetID())
	if err != nil {
		fmt.Printf("could not fetch file: %s : %v\n", entry.ID.GetID(), err)
		return err
	}
	defer reader.Close()

	bts, err := ioutil.ReadAll(reader)
	if err != nil {
		fmt.Printf("could not read file: %s : %v\n", entry.ID.GetID(), err)
		return err
	}

	matches, err := yaraRules.ScanMem(bts, 0, 0)
	if err != nil {
		fmt.Printf("could not scan with yara %v\n", err)
		return err
	}

	if len(matches) == 0 {
		fmt.Printf("Could not find any matches!\n")
	}

	for _, match := range matches {
		for _, str := range match.Strings {
			reader := bytes.NewReader(bts)
			reader.Seek(int64(str.Offset), 0)

			switch str.Name {
			case "$AMD":
				fmt.Printf("Ignoring AMD Microcode for now..  :(\n")
				var header AMDHeader
				binary.Read(reader, binary.LittleEndian, &header)
				fmt.Printf("Found AMD MC Update at 0x%x with Length: 0x%x\n", str.Offset, header.DataSize)
			case "$Intel":
				var header IntelHeader
				binary.Read(reader, binary.LittleEndian, &header)
				fmt.Printf("Found Intel MC Update at 0x%x with Length: 0x%x\n", str.Offset, header.TotalSize)
				mcUpdate := bts[str.Offset : str.Offset+uint64(header.TotalSize)]
				// Save in MCExtractor naming scheme
				year := header.Date & 0x0000FFFF
				day := header.Date & 0x00FF0000 >> 16
				month := header.Date & 0xFF000000 >> 24
				path := fmt.Sprintf("cpu%X_plat%02X_ver%08X_%x-%02x-%02x_PRD_%08X.bin",
					header.ProcessorSignature, header.ProcessorFlags, header.UpdateRevision, year, month, day, header.Checksum)

				currentYear, _, _ := time.Now().Date()
				if !(year == 1896 && month == 0 && day == 7) &&
					(year < 1993 || year > uint32(currentYear+2)) {
					Bundle.Log.WithField("path", path).Infof("Unplausible year: %d", year)
					continue
				}

				if header.Reserved1 != 0 ||
					header.Reserved2 != 0 ||
					header.Reserved3 != 0 {
					Bundle.Log.WithField("path", path).Infof("Reserved fields are not zero %x %x %x", header.Reserved1, header.Reserved2, header.Reserved3)
					continue
				}

				//fmt.Printf("Storing to: %s\n", path)
				err = Bundle.Storage.StoreBytes(mcUpdate, path)
				if err != nil {
					fmt.Printf("Could not store microcode! %v\n", err)
				}
				//TODO remember in DB
			}

		}
		//entry.File.IsFlash = true
	}

	//jsonEncoder.Encode(matches)
	return nil
}
