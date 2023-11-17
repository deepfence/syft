package commands

import (
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/bmatcuk/doublestar/v4"
)

var (
	OsIdPaths = []string{
		"**/etc/os-release", "**/usr/lib/os-release", "**/etc/lsb-release",
		"**/etc/centos-release", "**/etc/redhat-release", "**/etc/system-release-cpe",
		"**/bin/busybox", "**/usr/share/doc/**/copyright",
	}
	//BinarySearchPaths = []string{
	//	"**/usr/lib/jvm/**", "**/usr/share/java/**",
	//	"**/usr/local/sbin/*", "**/usr/local/bin/*", "**/usr/sbin/*", "**/usr/bin/*", "**/sbin/*", "**/bin/*",
	//	"**/usr/lib64/*", "**/usr/lib/*", "**/usr/share/*", "**/usr/local/lib64/*", "**/usr/local/lib/*",
	//}
	BinarySearchPaths = []string{
		"**/**",
	}
	CatalogerGlobPatterns = map[string][]string{
		"alpmdb-cataloger":        {"**/var/lib/pacman/local/**/desc"},
		"apkdb-cataloger":         {"**/lib/apk/db/installed"},
		"conan-cataloger":         {"**/conanfile.txt", "**/conan.lock"},
		"dartlang-lock-cataloger": {"**/pubspec.lock"},
		"dpkgdb-cataloger":        {"**/var/lib/dpkg/{status,status.d/**}"},
		"dotnet-deps-cataloger":   {"**/*.deps.json"},
		"go-mod-file-cataloger":   {"**/go.mod"},
		"haskell-cataloger":       {"**/stack.yaml", "**/stack.yaml.lock", "**/cabal.project.freeze"},
		"java-cataloger": {
			// java archive
			"**/*.jar", "**/*.war", "**/*.ear", "**/*.par",
			"**/*.sar", "**/*.jpi", "**/*.hpi", "**/*.lpkg",
			// zip java archive
			"**/*.zip",
			// tar java archive
			"**/*.tar", "**/*.tar.gz", "**/*.tgz", "**/*.tar.bz", "**/*.tar.bz2",
			"**/*.tbz", "**/*.tbz2", "**/*.tar.br", "**/*.tbr", "**/*.tar.lz4", "**/*.tlz4",
			"**/*.tar.sz", "**/*.tsz", "**/*.tar.xz", "**/*.txz", "**/*.tar.zst",
		},
		"java-pom-cataloger":               {"**/pom.xml"},
		"javascript-package-cataloger":     {"**/package.json"},
		"javascript-lock-cataloger":        {"**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml"},
		"nix-store-cataloger":              {"**/nix/store/*"},
		"php-composer-installed-cataloger": {"**/installed.json"},
		"php-composer-lock-cataloger":      {"**/composer.lock"},
		"portage-cataloger":                {"**/var/db/pkg/*/*/CONTENTS"},
		"rpm-db-cataloger":                 {"**/var/lib/rpm/{Packages,Packages.db,rpmdb.sqlite}", "**/var/lib/rpmmanifest/container-manifest-2"},
		"rpm-file-cataloger":               {"**/*.rpm"},
		"ruby-gemfile-cataloger":           {"**/Gemfile.lock"},
		"ruby-gemspec-cataloger":           {"**/specifications/**/*.gemspec"},
		"rust-cargo-lock-cataloger":        {"**/Cargo.lock"},
		"cocoapods-cataloger":              {"**/Podfile.lock"},

		"sbom-cataloger": {
			"**/*.syft.json", "**/*.bom.*", "**/*.bom",
			"**/bom", "**/*.sbom.*", "**/*.sbom", "**/sbom",
			"**/*.cdx.*", "**/*.cdx", "**/*.spdx.*", "**/*.spdx",
		},

		"python-index-cataloger": {"**/*requirements*.txt", "**/poetry.lock", "**/Pipfile.lock", "**/setup.py"},
		"python-package-cataloger": {"**/*egg-info/PKG-INFO", "**/*.egg-info", "**/*dist-info/METADATA",
			"**/*.egg", "**/*.whl", // python egg and whl files
		},

		// TODO: binary cataloger needs different handling
		"binary-cataloger":                 BinarySearchPaths,
		"go-module-binary-cataloger":       BinarySearchPaths,
		"cargo-auditable-binary-cataloger": BinarySearchPaths,
	}
)

func AnyGlobMatches(patterns *[]string, path string) bool {
	for _, p := range *patterns {
		match, err := doublestar.PathMatch(p, path)
		if err != nil {
			continue
		} else if match {
			return true
		}
	}
	return false
}

func getfilter(catalogers []string) image.PathFilter {
	patterns := []string{}
	patterns = append(patterns, OsIdPaths...)
	if len(catalogers) > 0 {
		for _, c := range catalogers {
			for k := range CatalogerGlobPatterns {
				if strings.Contains(k, c) {
					patterns = append(patterns, CatalogerGlobPatterns[k]...)
				}
			}
		}
	} else {
		for _, c := range CatalogerGlobPatterns {
			patterns = append(patterns, c...)
		}
	}
	log.Debugf("number of glob patterns %d", len(patterns))

	return func(path string) bool {
		return AnyGlobMatches(&patterns, path)
	}
}
