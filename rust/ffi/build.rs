// Copyright 2026 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{env, path::PathBuf, process::Command};

fn main() {
	let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
	let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

	// Resolve circuits dir relative to this crate, works both in-repo and as a git dep
	let circuits_dir = manifest_dir.join("../../circuits").canonicalize().unwrap_or_else(|e| {
		panic!(
			"cannot find circuits/ directory at {}: {e}",
			manifest_dir.join("../../circuits").display()
		)
	});

	let lib_name = "gnark_apk";
	let archive_path = out_dir.join(format!("lib{lib_name}.a"));

	let status = Command::new("go")
		.arg("build")
		.arg("-buildmode=c-archive")
		.arg(format!("-o={}", archive_path.display()))
		.arg("./ffi/")
		.current_dir(&circuits_dir)
		.status()
		.expect("failed to run `go build` — is Go installed?");

	assert!(status.success(), "go build -buildmode=c-archive failed");
	assert!(archive_path.exists(), "static archive not found at {}", archive_path.display());

	println!("cargo:rustc-link-search=native={}", out_dir.display());
	println!("cargo:rustc-link-lib=static={lib_name}");

	// Go's c-archive depends on pthreads and the system resolver
	println!("cargo:rustc-link-lib=dylib=resolv");
	println!("cargo:rustc-link-lib=dylib=pthread");

	println!("cargo:rerun-if-changed={}", circuits_dir.join("ffi").display());
	println!("cargo:rerun-if-changed={}", circuits_dir.join("apk").display());
}
