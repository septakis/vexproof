// Applies vexproof's output with the same library calls Trivy and Grype make.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	cdx "gocheck/bomlink"
	vex "gocheck/vexlib"
	packageurl "github.com/package-url/packageurl-go"
)

type sbom struct {
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Components   []struct {
		BOMRef string `json:"bom-ref"`
		PURL   string `json:"purl"`
	} `json:"components"`
}

func mustRead(p string, v any) {
	b, err := os.ReadFile(p)
	if err != nil { panic(err) }
	if err := json.Unmarshal(b, v); err != nil { panic(err) }
}

// Trivy: pkg/fanal/types PkgIdentifier.Match
func pkgMatch(bomRef, purl, s string) bool {
	if len(s) > 4 && s[:4] == "pkg:" {
		if p, err := packageurl.FromString(s); err == nil { s = p.String() }
	}
	return bomRef == s || purl == s
}

func main() {
	dir := os.Args[1]
	var lock sbom
	mustRead(dir+"/bom.lockfile.json", &lock)
	app, pkg := "pkg:npm/chart-dashboard@1.0.0", "pkg:npm/lodash@4.17.21"
	var lodashRef string
	for _, c := range lock.Components { if c.PURL == pkg { lodashRef = c.BOMRef } }

	fmt.Println("== Trivy, OpenVEX (vex.Matches(vulnID, parentPURL, [pkgPURL]) then last statement's status)")
	doc, err := openDoc(dir + "/vex.trivy.openvex.json")
	if err != nil { panic(err) }
	for _, id := range []string{"CVE-2026-4800", "CVE-2026-2950", "CVE-2025-13465"} {
		st := doc.Matches(id, app, []string{pkg})
		res := "no statement"
		if len(st) > 0 { res = string(st[len(st)-1].Status) }
		fmt.Printf("  %-16s → %s\n", id, res)
	}

	fmt.Println("== Trivy (CVE ids) applying a VEX written from Grype/npm-audit findings (GHSA ids, CVE aliases)")
	gdoc, err := openDoc(dir + "/vex.grype.openvex.json")
	if err != nil { panic(err) }
	for _, id := range []string{"CVE-2026-4800", "CVE-2026-2950"} {
		st := gdoc.Matches(id, app, []string{pkg})
		res := "no statement"
		if len(st) > 0 { res = string(st[len(st)-1].Status) }
		fmt.Printf("  %-16s → %s\n", id, res)
	}

	fmt.Println("== Grype, OpenVEX, SBOM/dir scan (pass 2: package PURL as product, no subcomponents)")
	for _, f := range []string{"vex.trivy.openvex.json", "vex.grype.openvex.json"} {
		d, err := openDoc(dir + "/" + f)
		if err != nil { panic(err) }
		for _, id := range []string{"GHSA-r5fr-rjxr-66jc", "GHSA-f23m-r3pf-42rh"} {
			st := d.Matches(id, pkg, nil)
			res := "no statement"
			if len(st) > 0 { res = string(st[0].Status) }
			fmt.Printf("  %-24s %-20s → %s\n", f, id, res)
		}
	}

	fmt.Println("== Trivy, CycloneDX VEX (statements keyed by vuln.ID; affects must be a BOM-Link into the scanned SBOM)")
	var v struct{ Vulnerabilities []struct {
		ID string `json:"id"`
		Analysis struct{ State string `json:"state"` } `json:"analysis"`
		Affects []struct{ Ref string `json:"ref"` } `json:"affects"`
	} `json:"vulnerabilities"` }
	mustRead(dir+"/vex.trivy.cdx.json", &v)
	seen := map[string]bool{}
	for _, vuln := range v.Vulnerabilities {
		if seen[vuln.ID] { continue } // Trivy keeps one statement per id (map)
		seen[vuln.ID] = true
		applied := false
		for _, a := range vuln.Affects {
			link, err := cdx.ParseBOMLink(a.Ref)
			if err != nil { fmt.Println("  bad link", a.Ref, err); continue }
			if link.SerialNumber() != lock.SerialNumber || link.Version() != lock.Version { fmt.Println("  serial/version mismatch"); continue }
			if pkgMatch(lodashRef, pkg, link.Reference()) { applied = true }
		}
		st := vuln.Analysis.State
		suppress := applied && (st == "not_affected" || st == "false_positive" || st == "resolved")
		fmt.Printf("  %-22s state=%-13s link resolves to lodash=%v → filtered=%v\n", vuln.ID, st, applied, suppress)
	}
}

func openDoc(p string) (*vex.VEX, error) {
	b, err := os.ReadFile(p)
	if err != nil { return nil, err }
	var d vex.VEX
	if err := json.Unmarshal(b, &d); err != nil { return nil, err }
	return &d, nil
}
