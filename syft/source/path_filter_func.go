package source

import (
	"strings"

	"github.com/anchore/stereoscope/pkg/pathfilter"
	"github.com/anchore/syft/internal/log"
	"github.com/bmatcuk/doublestar/v4"
)

var (
	OsIdPaths = []string{
		"**/etc/os-release",
		"**/usr/lib/os-release",
		"**/etc/lsb-release",
		"**/etc/centos-release",
		"**/etc/redhat-release",
		"**/etc/system-release-cpe",
		"**/bin/busybox",
		"**/usr/share/doc/**/copyright",
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
		"alpm-db-cataloger": {
			"**/var/lib/pacman/local/**/desc",
		},
		"apk-db-cataloger": {
			"**/lib/apk/db/installed",
		},
		"conan-cataloger": {
			"**/conanfile.txt",
			"**/conan.lock",
		},
		"conan-info-cataloger": {
			"**/conaninfo.txt",
		},
		"dart-pubspec-lock-cataloger": {
			"**/pubspec.lock",
		},
		"dpkg-db-cataloger": {
			"**/var/lib/dpkg/status",
			"**/var/lib/dpkg/status.d/*",
			"**/lib/opkg/info/*.control",
			"**/lib/opkg/status",
		},
		"dotnet-deps-cataloger": {
			"**/*.deps.json",
		},
		"dotnet-portable-executable-cataloger": {
			"**/*.dll",
			"**/*.exe",
		},
		"elixir-mix-lock-cataloger": {
			"**/mix.lock",
		},
		"erlang-rebar-lock-cataloger": {
			"**/rebar.lock",
		},
		"erlang-otp-application-cataloger": {
			"**/*.app",
		},
		"portage-cataloger": {
			"**/var/db/pkg/*/*/CONTENTS",
		},
		"github-actions-usage-cataloger": {
			"**/.github/workflows/*.yaml",
			"**/.github/workflows/*.yml",
			"**/.github/actions/*/action.yml",
			"**/.github/actions/*/action.yaml",
		},
		"github-action-workflow-usage-cataloger": {
			"**/.github/workflows/*.yaml",
			"**/.github/workflows/*.yml",
		},
		"go-module-file-cataloger": {
			"**/go.mod",
		},
		"haskell-cataloger": {
			"**/stack.yaml",
			"**/stack.yaml.lock",
			"**/cabal.project.freeze",
		},
		"java-archive-cataloger": {
			// java archive
			"**/*.jar", "**/*.war", "**/*.ear", "**/*.par", "**/*.sar",
			"**/*.nar", "**/*.jpi", "**/*.hpi", "**/*.lpkg",
			// zip archive
			"**/*.zip",
			// tar archive
			"**/*.tar", "**/*.tar.gz", "**/*.tgz", "**/*.tar.bz", "**/*.tar.bz2",
			"**/*.tbz", "**/*.tbz2", "**/*.tar.br", "**/*.tbr", "**/*.tar.lz4",
			"**/*.tlz4", "**/*.tar.sz", "**/*.tsz", "**/*.tar.xz", "**/*.txz",
			"**/*.tar.zst", "**/*.tzst", "**/*.tar.zstd", "**/*.tzstd",
		},
		"java-pom-cataloger": {
			"**/pom.xml",
		},
		"java-gradle-lockfile-cataloger": {
			"**/gradle.lockfile*",
		},
		"javascript-package-cataloger": {
			"**/package.json",
		},
		"javascript-lock-cataloger": {
			"**/package-lock.json",
			"**/yarn.lock",
			"**/pnpm-lock.yaml",
		},
		"linux-kernel-cataloger": {
			"**/kernel",
			"**/kernel-*",
			"**/vmlinux",
			"**/vmlinux-*",
			"**/vmlinuz",
			"**/vmlinuz-*",
			"**/lib/modules/**/*.ko",
		},
		"nix-store-cataloger": {
			"**/nix/store/*",
		},
		"php-composer-installed-cataloger": {
			"**/installed.json",
		},
		"php-composer-lock-cataloger": {
			"**/composer.lock",
		},
		"php-pecl-serialized-cataloger": {
			"**/php/.registry/.channel.*/*.reg",
		},
		"python-package-cataloger": {
			"**/*requirements*.txt",
			"**/poetry.lock",
			"**/Pipfile.lock",
			"**/setup.py",
		},
		"python-installed-package-cataloger": {
			"**/*.egg-info",
			"**/*dist-info/METADATA",
			"**/*egg-info/PKG-INFO",
			"**/*DIST-INFO/METADATA",
			"**/*EGG-INFO/PKG-INFO",
		},
		"r-package-cataloger": {
			"**/DESCRIPTION",
		},
		"rpm-db-cataloger": {
			"**/{var/lib,usr/share,usr/lib/sysimage}/rpm/{Packages,Packages.db,rpmdb.sqlite}",
			"**/var/lib/rpmmanifest/container-manifest-2",
		},
		"rpm-archive-cataloger": {
			"**/*.rpm",
		},
		"ruby-gemfile-cataloger": {
			"**/Gemfile.lock",
		},
		"ruby-installed-gemspec-cataloger": {
			"**/specifications/**/*.gemspec",
		},
		"ruby-gemspec-cataloger": {
			"**/*.gemspec",
		},
		"rust-cargo-lock-cataloger": {
			"**/Cargo.lock",
		},
		"sbom-cataloger": {
			"**/*.syft.json",
			"**/*.bom.*",
			"**/*.bom",
			"**/bom",
			"**/*.sbom.*",
			"**/*.sbom",
			"**/sbom",
			"**/*.cdx.*",
			"**/*.cdx",
			"**/*.spdx.*",
			"**/*.spdx",
		},
		"swift-package-manager-cataloger": {
			"**/Package.resolved",
			"**/.package.resolved",
		},
		"cocoapods-cataloger": {
			"**/Podfile.lock",
		},
		"wordpress-plugins-cataloger": {
			"**/wp-content/plugins/*/*.php",
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
		}
		if match {
			log.Debugf("path %s matched glob %s", path, p)
			return true
		}
	}
	return false
}

func GetPathFilterFunc(catalogers []string) pathfilter.PathFilterFunc {
	log.Debugf("catalogers selected for glob patterns %s", catalogers)

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
