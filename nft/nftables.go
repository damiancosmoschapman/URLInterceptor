package nft

import (
	"log"
	"os/exec"
)

// LoadRuleset reads and applies the nftables ruleset from the specified file.
// It executes: nft -f <filePath>
func LoadRuleset(filePath string) error {
	cmd := exec.Command("nft", "-f", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("nft command error: %s", string(output))
		return err
	}
	return nil
}

// FlushRuleset flushes all nftables rules by executing: nft flush ruleset.
func FlushRuleset() error {
	cmd := exec.Command("nft", "flush", "ruleset")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("nft flush error: %s", string(output))
		return err
	}
	return nil
}
