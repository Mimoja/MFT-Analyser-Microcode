package main

type IntelHeader struct {
	HeaderVersion      uint32
	UpdateRevision     uint32
	Date               uint32
	ProcessorSignature uint32
	Checksum           uint32
	LoaderRevision     uint32
	ProcessorFlags     uint32
	DataSize           uint32
	TotalSize          uint32
	Reserved1          uint32
	Reserved2          uint32
	Reserved3          uint32
}

type AMDHeader struct {
	Date               uint32
	UpdateRevision     uint32
	LoaderID           uint16
	DataSize           uint8
	InitializationFlag uint8
	DataChecksum       uint32
	NorthBridgeVEN_ID  uint16
	NorthBridgeDEV_ID  uint16
	SouthBridgeVEN_ID  uint16
	SouthBridgeDEV_ID  uint16
	ProcessorSignature uint16
	NorthBridgeREV_ID  uint8
	SouthBridgeREV_ID  uint8
	BiosApiREV_ID      uint8
	Reserved           [3]uint8
}
