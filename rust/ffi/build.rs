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

	// Opt into the CUDA-accelerated PLONK prover with GNARK_APK_CUDA=1. Requires libgnark_cuda
	// (GNARK_CUDA_DIR) + icicle (ICICLE_DIR) + CUDA (CUDA_DIR, default /usr/local/cuda) present
	// at build time. The default build is unchanged CPU-only.
	let cuda = env::var("GNARK_APK_CUDA").map(|v| !v.is_empty() && v != "0").unwrap_or(false);
	let cuda_dirs = || {
		let gnark_cuda = env::var("GNARK_CUDA_DIR").expect("GNARK_APK_CUDA set but GNARK_CUDA_DIR is not");
		let icicle = env::var("ICICLE_DIR").expect("GNARK_APK_CUDA set but ICICLE_DIR is not");
		let cuda_dir = env::var("CUDA_DIR").unwrap_or_else(|_| "/usr/local/cuda".to_string());
		(gnark_cuda, icicle, cuda_dir)
	};

	let mut build = Command::new("go");
	build.arg("build").arg("-buildmode=c-archive");
	if cuda {
		let (gnark_cuda, icicle, cuda_dir) = cuda_dirs();
		build.arg("-tags").arg("cuda");
		build.env("CGO_CFLAGS", format!("-I{gnark_cuda}/include"));
		build.env("CGO_LDFLAGS", format!("-L{gnark_cuda}/build -L{icicle}/lib -L{cuda_dir}/lib64"));
	}
	build.arg(format!("-o={}", archive_path.display())).arg("./ffi/").current_dir(&circuits_dir);

	let status = build.status().expect("failed to run `go build` — is Go installed?");
	assert!(status.success(), "go build -buildmode=c-archive failed");
	assert!(archive_path.exists(), "static archive not found at {}", archive_path.display());

	println!("cargo:rustc-link-search=native={}", out_dir.display());
	println!("cargo:rustc-link-lib=static={lib_name}");

	// Go's c-archive depends on pthreads and the system resolver
	println!("cargo:rustc-link-lib=dylib=resolv");
	println!("cargo:rustc-link-lib=dylib=pthread");

	// Under -tags cuda the archive pulls in libgnark_cuda → icicle → CUDA; link + rpath them
	// so the resulting binary resolves the GPU symbols (matches the gpu package's #cgo LDFLAGS).
	if cuda {
		let (gnark_cuda, icicle, cuda_dir) = cuda_dirs();
		for dir in [format!("{gnark_cuda}/build"), format!("{icicle}/lib"), format!("{cuda_dir}/lib64")] {
			println!("cargo:rustc-link-search=native={dir}");
			println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
		}
		for lib in [
			"gnark_cuda",
			"icicle_field_bls12_381",
			"icicle_curve_bls12_381",
			"icicle_device",
			"cudart",
			"stdc++",
		] {
			println!("cargo:rustc-link-lib=dylib={lib}");
		}
	}

	println!("cargo:rerun-if-changed={}", circuits_dir.join("ffi").display());
	println!("cargo:rerun-if-changed={}", circuits_dir.join("apk").display());
	println!("cargo:rerun-if-env-changed=GNARK_APK_CUDA");
}
