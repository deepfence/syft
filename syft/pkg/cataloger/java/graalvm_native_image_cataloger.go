package java

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	"github.com/anchore/syft/syft/source"
)

type nativeImageCycloneDX struct {
	BomFormat   string                 `json:"bomFormat"`
	SpecVersion string                 `json:"specVersion"`
	Version     int                    `json:"version"`
	Components  []nativeImageComponent `json:"components"`
}

type nativeImageComponent struct {
	Type       string           `json:"type"`
	Group      string           `json:"group"`
	Name       string           `json:"name"`
	Version    string           `json:"version"`
	Properties []nativeImageCPE `json:"properties"`
}

type nativeImageCPE struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type nativeImage interface {
	fetchPkgs() ([]pkg.Package, error)
}

type nativeImageElf struct {
	file *elf.File
}

type nativeImageMachO struct {
	file *macho.File
}

type exportTypesPE struct {
	functionPointer uint32
	namePointer     uint32
	headerAttribute uint32
}

type exportPrefixPE struct {
	characteristics uint32
	timeDateStamp   uint32
	majorVersion    uint16
	minorVersion    uint16
	name            uint32
	base            uint32
}

type exportContentPE struct {
	// Directory Entry Contents for finding SBOM symbols
	numberOfFunctions  uint32
	numberOfNames      uint32
	addressOfFunctions uint32
	addressOfNames     uint32
	// Locations of SBOM symbols in the .data section
	addressOfSbom       uint32
	addressOfSbomLength uint32
	addressOfSvmVersion uint32
}

// A nativeImagePE must maintain the underlying reader to fetch information unavailable in the Golang API.
type nativeImagePE struct {
	file          *pe.File
	reader        io.ReaderAt
	exportSymbols pe.DataDirectory
	exports       []byte
	t             exportTypesPE
	header        exportPrefixPE
}

type NativeImageCataloger struct{}

const nativeImageCatalogerName = "graalvm-native-image-cataloger"
const nativeImageSbomSymbol = "sbom"
const nativeImageSbomLengthSymbol = "sbom_length"
const nativeImageSbomVersionSymbol = "__svm_version_info"
const nativeImageMissingSymbolsError = "one or more symbols are missing from the native image executable"
const nativeImageInvalidIndexError = "parsing the executable file generated an invalid index"
const nativeImageMissingExportedDataDirectoryError = "exported data directory is missing"

// newNativeImageCataloger returns a new Native Image cataloger object.
func NewNativeImageCataloger() *NativeImageCataloger {
	return &NativeImageCataloger{}
}

// Name returns a string that uniquely describes a native image cataloger
func (c *NativeImageCataloger) Name() string {
	return nativeImageCatalogerName
}

// getPackage returns the package given within a NativeImageComponent.
func getPackage(component nativeImageComponent) pkg.Package {
	var cpes []cpe.CPE
	for _, property := range component.Properties {
		cpe, err := cpe.New(property.Value)
		if err != nil {
			log.Debugf("native-image cataloger: could not parse CPE: %v.", err)
			continue
		}
		cpes = append(cpes, cpe)
	}
	return pkg.Package{
		Name:         component.Name,
		Version:      component.Version,
		Language:     pkg.Java,
		Type:         pkg.GraalVMNativeImagePkg,
		MetadataType: pkg.JavaMetadataType,
		FoundBy:      nativeImageCatalogerName,
		Metadata: pkg.JavaMetadata{
			PomProperties: &pkg.PomProperties{
				GroupID: component.Group,
			},
		},
		CPEs: cpes,
	}
}

// decompressSbom returns the packages given within a native image executable's SBOM.
func decompressSbom(databuf []byte, sbomStart uint64, lengthStart uint64) ([]pkg.Package, error) {
	var pkgs []pkg.Package

	lengthEnd := lengthStart + 8
	buflen := len(databuf)
	if lengthEnd > uint64(buflen) {
		return nil, errors.New("the sbom_length symbol overflows the binary")
	}

	length := databuf[lengthStart:lengthEnd]
	p := bytes.NewBuffer(length)
	var storedLength uint64
	err := binary.Read(p, binary.LittleEndian, &storedLength)
	if err != nil {
		log.Debugf("native-image-cataloger: could not read from binary file.")
		return nil, err
	}
	log.Tracef("native-image cataloger: found SBOM of length %d.", storedLength)
	sbomEnd := sbomStart + storedLength
	if sbomEnd > uint64(buflen) {
		return nil, errors.New("the sbom symbol overflows the binary")
	}
	sbomCompressed := databuf[sbomStart:sbomEnd]
	p = bytes.NewBuffer(sbomCompressed)
	gzreader, err := gzip.NewReader(p)
	if err != nil {
		log.Debugf("native-image cataloger: could not decompress the SBOM.")
		return nil, err
	}
	output, err := io.ReadAll(gzreader)
	if err != nil {
		log.Debugf("native-image cataloger: could not read the decompressed SBOM.")
		return nil, err
	}
	var sbomContent nativeImageCycloneDX
	err = json.Unmarshal(output, &sbomContent)
	if err != nil {
		log.Debugf("native-image cataloger: could not unmarshal JSON.")
		return nil, err
	}

	for _, component := range sbomContent.Components {
		p := getPackage(component)
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// fileError logs an error message when an executable cannot be read.
func fileError(filename string, err error) (nativeImage, error) {
	// We could not read the file as a binary for the desired platform, but it may still be a native-image executable.
	log.Debugf("native-image cataloger: unable to read executable (file=%q): %v.", filename, err)
	return nil, err
}

// newElf reads a Native Image from an ELF executable.
func newElf(filename string, r io.ReaderAt) (nativeImage, error) {
	// First attempt to read an ELF file.
	bi, err := elf.NewFile(r)

	// The reader does not refer to an ELF file.
	if err != nil {
		return fileError(filename, err)
	}
	return nativeImageElf{
		file: bi,
	}, nil
}

// newMachO reads a Native Image from a Mach O executable.
func newMachO(filename string, r io.ReaderAt) (nativeImage, error) {
	// First attempt to read an ELF file.
	bi, err := macho.NewFile(r)

	// The reader does not refer to an MachO file.
	if err != nil {
		return fileError(filename, err)
	}
	return nativeImageMachO{
		file: bi,
	}, nil
}

// newPE reads a Native Image from a Portable Executable file.
func newPE(filename string, r io.ReaderAt) (nativeImage, error) {
	// First attempt to read an ELF file.
	bi, err := pe.NewFile(r)

	// The reader does not refer to an MachO file.
	if err != nil {
		return fileError(filename, err)
	}
	var exportSymbolsDataDirectory pe.DataDirectory
	switch h := bi.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		exportSymbolsDataDirectory = h.DataDirectory[0]
	case *pe.OptionalHeader64:
		exportSymbolsDataDirectory = h.DataDirectory[0]
	default:
		return nil, fmt.Errorf("unable to get exportSymbolsDataDirectory from binary: %s", filename)
	}
	// If we have no exported symbols it is not a Native Image
	if exportSymbolsDataDirectory.Size == 0 {
		return fileError(filename, errors.New(nativeImageMissingExportedDataDirectoryError))
	}
	exportSymbolsOffset := uint64(exportSymbolsDataDirectory.VirtualAddress)
	exports := make([]byte, exportSymbolsDataDirectory.Size)
	_, err = r.ReadAt(exports, int64(exportSymbolsOffset))
	if err != nil {
		log.Debugf("native-image cataloger: could not read the exported symbols data directory: %v.", err)
		return fileError(filename, err)
	}
	return nativeImagePE{
		file:          bi,
		reader:        r,
		exportSymbols: exportSymbolsDataDirectory,
		exports:       exports,
		t: exportTypesPE{
			functionPointer: 0,
			namePointer:     0,
			headerAttribute: 0,
		},
		header: exportPrefixPE{
			characteristics: 0,
			timeDateStamp:   0,
			majorVersion:    0,
			minorVersion:    0,
			name:            0,
			base:            0,
		},
	}, nil
}

// fetchPkgs obtains the packages given in the binary.
func (ni nativeImageElf) fetchPkgs() ([]pkg.Package, error) {
	bi := ni.file
	var sbom elf.Symbol
	var sbomLength elf.Symbol
	var svmVersion elf.Symbol

	si, err := bi.Symbols()
	if err != nil {
		log.Debugf("native-image cataloger: no symbols found.")
		return nil, err
	}
	for _, s := range si {
		switch s.Name {
		case nativeImageSbomSymbol:
			sbom = s
		case nativeImageSbomLengthSymbol:
			sbomLength = s
		case nativeImageSbomVersionSymbol:
			svmVersion = s
		}
	}
	if sbom.Value == 0 || sbomLength.Value == 0 || svmVersion.Value == 0 {
		log.Debugf("native-image cataloger: %v", nativeImageMissingSymbolsError)
		return nil, errors.New(nativeImageMissingSymbolsError)
	}
	dataSection := bi.Section(".data")
	if dataSection == nil {
		log.Debugf("native-image cataloger: .data section missing from ELF file.")
		return nil, err
	}
	dataSectionBase := dataSection.SectionHeader.Addr
	data, err := dataSection.Data()
	if err != nil {
		log.Debugf("native-image cataloger: cannot read the .data section.")
		return nil, err
	}
	sbomLocation := sbom.Value - dataSectionBase
	lengthLocation := sbomLength.Value - dataSectionBase

	return decompressSbom(data, sbomLocation, lengthLocation)
}

// fetchPkgs obtains the packages from a Native Image given as a Mach O file.
func (ni nativeImageMachO) fetchPkgs() ([]pkg.Package, error) {
	var sbom macho.Symbol
	var sbomLength macho.Symbol
	var svmVersion macho.Symbol

	bi := ni.file
	for _, s := range bi.Symtab.Syms {
		switch s.Name {
		case "_" + nativeImageSbomSymbol:
			sbom = s
		case "_" + nativeImageSbomLengthSymbol:
			sbomLength = s
		case "_" + nativeImageSbomVersionSymbol:
			svmVersion = s
		}
	}
	if sbom.Value == 0 || sbomLength.Value == 0 || svmVersion.Value == 0 {
		log.Debugf("native-image cataloger: %v.", nativeImageMissingSymbolsError)
		return nil, errors.New(nativeImageMissingSymbolsError)
	}

	dataSegment := bi.Segment("__DATA")
	if dataSegment == nil {
		return nil, nil
	}
	databuf, err := dataSegment.Data()
	if err != nil {
		log.Debugf("native-image cataloger: cannot obtain buffer from data segment.")
		return nil, nil
	}
	sbomLocation := sbom.Value - dataSegment.Addr
	lengthLocation := sbomLength.Value - dataSegment.Addr

	return decompressSbom(databuf, sbomLocation, lengthLocation)
}

// fetchExportAttribute obtains an attribute from the exported symbols directory entry.
func (ni nativeImagePE) fetchExportAttribute(i int) (uint32, error) {
	var attribute uint32
	n := len(ni.exports)
	j := int(unsafe.Sizeof(ni.header)) + i*int(unsafe.Sizeof(ni.t.headerAttribute))
	if j+4 >= n {
		log.Debugf("native-image cataloger: invalid index to export directory entry attribute: %v.", j)
		return uint32(0), errors.New(nativeImageInvalidIndexError)
	}
	p := bytes.NewBuffer(ni.exports[j : j+4])
	err := binary.Read(p, binary.LittleEndian, &attribute)
	if err != nil {
		log.Debugf("native-image cataloger: error fetching export directory entry attribute: %v.", err)
		return uint32(0), err
	}
	return attribute, nil
}

// fetchExportFunctionPointer obtains a function pointer from the exported symbols directory entry.
func (ni nativeImagePE) fetchExportFunctionPointer(functionsBase uint32, i uint32) (uint32, error) {
	var pointer uint32

	n := uint32(len(ni.exports))
	sz := uint32(unsafe.Sizeof(ni.t.functionPointer))
	j := functionsBase + i*sz
	if j+sz >= n {
		log.Debugf("native-image cataloger: invalid index to exported function: %v.", j)
		return uint32(0), errors.New(nativeImageInvalidIndexError)
	}
	p := bytes.NewBuffer(ni.exports[j : j+sz])
	err := binary.Read(p, binary.LittleEndian, &pointer)
	if err != nil {
		log.Debugf("native-image cataloger: error fetching exported function: %v.", err)
		return uint32(0), err
	}
	return pointer, nil
}

// fetchExportContent obtains the content of the export directory entry relevant to the SBOM.
func (ni nativeImagePE) fetchExportContent() (*exportContentPE, error) {
	content := new(exportContentPE)
	var err error
	content.numberOfFunctions, err = ni.fetchExportAttribute(0)
	if err != nil {
		log.Debugf("native-image cataloger: could not find the number of exported functions attribute: %v", err)
		return nil, err
	}
	content.numberOfNames, err = ni.fetchExportAttribute(1)
	if err != nil {
		log.Debugf("native-image cataloger: could not find the number of exported names attribute: %v", err)
		return nil, err
	}
	content.addressOfFunctions, err = ni.fetchExportAttribute(2)
	if err != nil {
		log.Debugf("native-image cataloger: could not find the exported functions attribute: %v", err)
		return nil, err
	}
	content.addressOfNames, err = ni.fetchExportAttribute(3)
	if err != nil {
		log.Debugf("native-image cataloger: could not find the exported names attribute: %v", err)
		return nil, err
	}
	return content, nil
}

// fetchSbomSymbols enumerates the symbols exported by a binary to detect Native Image's SBOM symbols.
func (ni nativeImagePE) fetchSbomSymbols(content *exportContentPE) {
	// Appending NULL bytes to symbol names simplifies finding them in the export data directory
	sbomBytes := []byte(nativeImageSbomSymbol + "\x00")
	sbomLengthBytes := []byte(nativeImageSbomLengthSymbol + "\x00")
	svmVersionInfoBytes := []byte(nativeImageSbomVersionSymbol + "\x00")
	n := uint32(len(ni.exports))

	// Find SBOM, SBOM Length, and SVM Version Symbol
	for i := uint32(0); i < content.numberOfNames; i++ {
		j := i * uint32(unsafe.Sizeof(ni.t.namePointer))
		addressBase := content.addressOfNames - ni.exportSymbols.VirtualAddress
		k := addressBase + j
		sz := uint32(unsafe.Sizeof(ni.t.namePointer))
		if k+sz >= n {
			log.Debugf("native-image cataloger: invalid index to exported function: %v.", k)
			// If we are at the end of exports, stop looking
			return
		}
		var symbolAddress uint32
		p := bytes.NewBuffer(ni.exports[k : k+sz])
		err := binary.Read(p, binary.LittleEndian, &symbolAddress)
		if err != nil {
			log.Debugf("native-image cataloger: error fetching address of symbol %v.", err)
			return
		}
		symbolBase := symbolAddress - ni.exportSymbols.VirtualAddress
		if symbolBase >= n {
			log.Debugf("native-image cataloger: invalid index to exported symbol: %v.", symbolBase)
			return
		}
		switch {
		case bytes.HasPrefix(ni.exports[symbolBase:], sbomBytes):
			content.addressOfSbom = i
		case bytes.HasPrefix(ni.exports[symbolBase:], sbomLengthBytes):
			content.addressOfSbomLength = i
		case bytes.HasPrefix(ni.exports[symbolBase:], svmVersionInfoBytes):
			content.addressOfSvmVersion = i
		}
	}
}

// fetchPkgs obtains the packages from a Native Image given as a PE file.
func (ni nativeImagePE) fetchPkgs() ([]pkg.Package, error) {
	content, err := ni.fetchExportContent()
	if err != nil {
		log.Debugf("native-image cataloger: could not fetch the content of the export directory entry: %v.", err)
		return nil, err
	}
	ni.fetchSbomSymbols(content)
	if content.addressOfSbom == uint32(0) || content.addressOfSbomLength == uint32(0) || content.addressOfSvmVersion == uint32(0) {
		log.Debugf("native-image cataloger: %v.", nativeImageMissingSymbolsError)
		return nil, errors.New(nativeImageMissingSymbolsError)
	}
	functionsBase := content.addressOfFunctions - ni.exportSymbols.VirtualAddress
	sbomOffset := content.addressOfSbom
	sbomAddress, err := ni.fetchExportFunctionPointer(functionsBase, sbomOffset)
	if err != nil {
		log.Debugf("native-image cataloger: cannot fetch SBOM pointer from exported functions: %v.", err)
		return nil, err
	}
	sbomLengthOffset := content.addressOfSbomLength
	sbomLengthAddress, err := ni.fetchExportFunctionPointer(functionsBase, sbomLengthOffset)
	if err != nil {
		log.Debugf("native-image cataloger: cannot fetch SBOM length pointer from exported functions: %v.", err)
		return nil, err
	}
	bi := ni.file
	dataSection := bi.Section(".data")
	if dataSection == nil {
		return nil, nil
	}
	databuf, err := dataSection.Data()
	if err != nil {
		log.Debugf("native-image cataloger: cannot obtain buffer from .data section.")
		return nil, nil
	}
	sbomLocation := sbomAddress - dataSection.VirtualAddress
	lengthLocation := sbomLengthAddress - dataSection.VirtualAddress

	return decompressSbom(databuf, uint64(sbomLocation), uint64(lengthLocation))
}

// fetchPkgs provides the packages available in a UnionReader.
func fetchPkgs(reader unionreader.UnionReader, filename string) []pkg.Package {
	var pkgs []pkg.Package
	imageformats := []func(string, io.ReaderAt) (nativeImage, error){newElf, newMachO, newPE}

	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		log.Debugf("native-image cataloger: failed to open a binary: %v.", err)
		return nil
	}
	for _, r := range readers {
		for _, makeNativeImage := range imageformats {
			ni, err := makeNativeImage(filename, r)
			if err != nil {
				continue
			}
			newpkgs, err := ni.fetchPkgs()
			if err != nil {
				log.Debugf("native-image cataloger: error extracting SBOM from %s: %v.", filename, err)
				continue
			}
			pkgs = append(pkgs, newpkgs...)
		}
	}
	return pkgs
}

// Catalog attempts to find any native image executables reachable from a resolver.
func (c *NativeImageCataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	fileMatches, err := resolver.FilesByMIMEType(internal.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return pkgs, nil, fmt.Errorf("failed to find binaries by mime types: %w", err)
	}

	for _, location := range fileMatches {
		readerCloser, err := resolver.FileContentsByLocation(location)
		if err != nil {
			log.Debugf("native-image cataloger: error opening file: %v.", err)
			continue
		}
		log.Tracef("native-image cataloger: found an executable file %v.", location)
		reader, err := unionreader.GetUnionReader(readerCloser)
		if err != nil {
			return nil, nil, err
		}
		newpkgs := fetchPkgs(reader, location.RealPath)
		pkgs = append(pkgs, newpkgs...)
		internal.CloseAndLogError(readerCloser, location.RealPath)
	}

	return pkgs, nil, nil
}