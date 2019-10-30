package main

import (
	"github.com/Mimoja/MFT-Common"
	"encoding/json"
	"fmt"
)

var Bundle MFTCommon.AppBundle

func main() {
	Bundle = MFTCommon.Init("MicrocodeAnalyser")

	setupYara()

	Bundle.MessageQueue.BiosImagesQueue.RegisterCallback("MicrocodeAnalyser", func(payload string) error {

		fmt.Println("Got new Message!")
		var file MFTCommon.FlashImage
		err := json.Unmarshal([]byte(payload), &file)
		if err != nil {
			fmt.Printf("Could not unmarshall json: %v\n", err)
		}

		err = analyse(file)

		return err
	})
	fmt.Println("Starting up!")
	select {}
}
