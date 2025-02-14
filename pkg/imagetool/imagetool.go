package imagetool

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jaegdi/quay-client/pkg/cli"
)

// ImageToolData represents the structure of the JSON data received from image-tool.
type ImageToolData map[string]struct {
	AllIstags    map[string]ClusterData            `json:"AllIstags,omitempty"`
	UsedIstags   map[string]map[string][]ImageData `json:"UsedIstags,omitempty"`
	UnUsedIstags interface{}                       `json:"UnUsedIstags,omitempty"`
}

// ClusterData represents the data for a specific cluster.
type ClusterData struct {
	Is     struct{}   `json:"Is,omitempty"`
	Istag  struct{}   `json:"Istag,omitempty"`
	Image  struct{}   `json:"Image,omitempty"`
	Report ReportData `json:"Report,omitempty"`
}

// ReportData represents the report data for a cluster.
type ReportData struct {
	Anz_ImageStreamTags int `json:"Anz_ImageStreamTags,omitempty"`
	Anz_Images          int `json:"Anz_Images,omitempty"`
	Anz_ImageStreams    int `json:"Anz_ImageStreams,omitempty"`
}

// ImageData represents the data for a specific image.
type ImageData struct {
	Cluster         string `json:"Cluster,omitempty"`
	UsedInNamespace string `json:"UsedInNamespace,omitempty"`
	FromNamespace   string `json:"FromNamespace,omitempty"`
	AgeInDays       int    `json:"AgeInDays,omitempty"`
	Image           string `json:"Image,omitempty"`
	RegistryUrl     string `json:"RegistryUrl,omitempty"`
}

// LoadImageToolData loads the JSON data from the specified file and unmarshals it into an ImageToolData struct.
func LoadImageToolData(org string) (*ImageToolData, error) {
	flags := cli.GetFlags()
	var cmd *exec.Cmd
	var err error
	if flags.Verify {
		cmd = exec.Command("image-tool", "-family", org, "-used", "-json", "-statcfg", "-verify")
	} else {
		cmd = exec.Command("image-tool", "-family", org, "-used", "-json", "-statcfg")
	}
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %v", err)
	}

	var imageToolData ImageToolData
	if err := json.Unmarshal(stdout, &imageToolData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	if flags.Verify {
		PrintReport(&imageToolData)
	}
	return &imageToolData, nil
}

// PrintReport prints the report data for all clusters.
func PrintReport(data *ImageToolData) {
	fmt.Println("Report Data:")
	flags := cli.GetFlags()
	for cluster, clusterData := range (*data)[flags.Org].AllIstags {
		fmt.Printf("Cluster: %s\n", cluster)
		fmt.Printf("  ImageStreamTags: %d\n", clusterData.Report.Anz_ImageStreamTags)
		fmt.Printf("  Images: %d\n", clusterData.Report.Anz_Images)
		fmt.Printf("  ImageStreams: %d\n", clusterData.Report.Anz_ImageStreams)
	}
}

// PrintUsedImages prints the used image data.
func PrintUsedImages(data *ImageToolData) {
	fmt.Println("Used Images:")
	flags := cli.GetFlags()
	for imageName, versions := range (*data)[flags.Org].UsedIstags {
		fmt.Printf("Image: %s\n", imageName)
		for version, images := range versions {
			fmt.Printf("  Version: %s\n", version)
			for _, image := range images {
				fmt.Printf("    Cluster: %s\n", image.Cluster)
				fmt.Printf("    UsedInNamespace: %s\n", image.UsedInNamespace)
				fmt.Printf("    FromNamespace: %s\n", image.FromNamespace)
				fmt.Printf("    AgeInDays: %d\n", image.AgeInDays)
				fmt.Printf("    Image: %s\n", image.Image)
				fmt.Printf("    RegistryUrl: %s\n", image.RegistryUrl)
			}
		}
	}
}

// IsRegistryUrlFound checks if the given registry URL is found in the ImageToolData.
func IsRegistryUrlFound(data *ImageToolData, registryUrl string) (string, string, string, bool) {
	flags := cli.GetFlags()
	for _, tags := range (*data)[flags.Org].UsedIstags {
		for _, images := range tags {
			for _, image := range images {
				if strings.Contains(image.RegistryUrl, registryUrl) {
					return image.Cluster, image.UsedInNamespace, image.RegistryUrl, true
				}
			}
		}
	}
	return "", "", "", false
}
