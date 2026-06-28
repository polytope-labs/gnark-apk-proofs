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

use std::{
	env, fs,
	io::Write,
	path::{Path, PathBuf},
	process::Command,
};

// Native GPU dependencies, fetched + built from source under the `cuda` feature so a GPU build
// needs no pre-installed libraries and no path env vars. Pinned for reproducibility.
const OPEN_ICICLE_REPO: &str = "https://github.com/ingonyama-zk/open-icicle.git";
const OPEN_ICICLE_REV: &str = "a1f8a74b4c604367b9e1eae41aca4d02687e96fc";
const GNARK_CUDA_REPO: &str = "https://github.com/polytope-labs/gnark-cuda.git";
const GNARK_CUDA_REV: &str = "b435761c5833813b94f3b4edf75571439d091566";

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

	// Enable the CUDA-accelerated icicle prover with the `cuda` cargo feature (GNARK_APK_CUDA=1
	// also works for ad-hoc builds). When on, build.rs fetches + builds open-icicle + gnark-cuda
	// from source and links them *statically* into the binary — no external libraries, no paths,
	// and no build- or run-time env vars. Default is the unchanged CPU-only prover.
	let cuda = env::var_os("CARGO_FEATURE_CUDA").is_some() ||
		env::var("GNARK_APK_CUDA").map(|v| !v.is_empty() && v != "0").unwrap_or(false);

	let gpu = cuda.then(|| build_gpu_deps(&out_dir));

	// Compile the Go circuit/prover into a C static archive (with -tags cuda when GPU is on).
	let mut build = Command::new("go");
	build.arg("build").arg("-buildmode=c-archive");
	if let Some(g) = &gpu {
		build.arg("-tags").arg("cuda");
		build.env("CGO_CFLAGS", format!("-I{}", g.include.display()));
	}
	build
		.arg(format!("-o={}", archive_path.display()))
		.arg("./ffi/")
		.current_dir(&circuits_dir);

	let status = build.status().expect("failed to run `go build` — is Go installed?");
	assert!(status.success(), "go build -buildmode=c-archive failed");
	assert!(archive_path.exists(), "static archive not found at {}", archive_path.display());

	println!("cargo:rustc-link-search=native={}", out_dir.display());
	println!("cargo:rustc-link-lib=static={lib_name}");

	// Go's c-archive depends on pthreads and the system resolver
	println!("cargo:rustc-link-lib=dylib=resolv");
	println!("cargo:rustc-link-lib=dylib=pthread");

	// Link the GPU stack fully static so the binary is self-contained: only system libs end up
	// as NEEDED, and it runs with no LD_LIBRARY_PATH / ICICLE_BACKEND_INSTALL_DIR.
	if let Some(g) = &gpu {
		let lib = g.icicle_install.join("lib");
		for dir in [
			g.gnark_cuda_lib.clone(),
			lib.clone(),
			lib.join("backend/cuda"),
			lib.join("backend/bls12_381/cuda"),
			g.cuda_lib.clone(),
		] {
			println!("cargo:rustc-link-search=native={}", dir.display());
		}

		// gnark-cuda shim (device symbols resolved into the .a).
		println!("cargo:rustc-link-lib=static=gnark_cuda");
		// icicle CUDA backend: --whole-archive so the static-init REGISTER_* registrars survive
		// the linker's GC and run at program startup — this replaces the dlopen the shared build
		// used, giving an in-binary device registry (no runtime backend dir).
		for b in [
			"icicle_backend_cuda_device",
			"icicle_backend_cuda_field_bls12_381",
			"icicle_backend_cuda_curve_bls12_381",
		] {
			println!("cargo:rustc-link-lib=static:+whole-archive={b}");
		}
		// icicle frontend (host-only).
		for f in ["icicle_curve_bls12_381", "icicle_field_bls12_381", "icicle_device"] {
			println!("cargo:rustc-link-lib=static={f}");
		}
		// The CUDA runtime + driver stay dynamic — the standard, supported way. Linking
		// `cudart_static` here triggers `invalid resource handle` at kernel launch: its
		// per-module runtime state doesn't survive being statically merged with icicle's
		// device code. Only the project libraries (gnark-cuda + icicle) are static; the
		// stock CUDA runtime is found on the loader path like for any CUDA program.
		for s in ["cudart", "cuda", "stdc++", "dl", "rt", "m"] {
			println!("cargo:rustc-link-lib=dylib={s}");
		}
	}

	println!("cargo:rerun-if-changed={}", circuits_dir.join("ffi").display());
	println!("cargo:rerun-if-changed={}", circuits_dir.join("apk").display());
	println!("cargo:rerun-if-env-changed=GNARK_APK_CUDA");
}

/// Link directories produced by building the GPU native dependencies (all static).
struct GpuDeps {
	/// gnark-cuda headers (for the cgo `-I`).
	include: PathBuf,
	/// Directory holding `libgnark_cuda.a`.
	gnark_cuda_lib: PathBuf,
	/// icicle install prefix (its `lib/` holds the frontend + `backend/` static libs).
	icicle_install: PathBuf,
	/// CUDA toolkit `lib64` directory (holds `libcudart_static.a`, `libculibos.a`).
	cuda_lib: PathBuf,
}

/// Fetch open-icicle + gnark-cuda, patch them to build *static*, and build them into `out`.
/// Each build is skipped when its output already exists, so only the first GPU build pays the
/// (multi-minute) CUDA compile. Requires `git`, `cmake`, and the CUDA toolkit on PATH.
fn build_gpu_deps(out: &Path) -> GpuDeps {
	let cuda_home = env::var("CUDA_DIR").unwrap_or_else(|_| "/usr/local/cuda".to_string());
	let cuda_lib = PathBuf::from(format!("{cuda_home}/lib64"));

	// open-icicle: the generic MSM/NTT/vec backend gnark-cuda delegates to.
	let icicle_src = git_fetch(out, "open-icicle", OPEN_ICICLE_REPO, OPEN_ICICLE_REV);
	let icicle_install = out.join("icicle-install");
	if !icicle_install.join("lib/libicicle_device.a").exists() {
		patch_icicle_static(&icicle_src);
		cmake(
			&icicle_src.join("icicle"),
			&out.join("icicle-build"),
			&[
				"-DCURVE=bls12_381".into(),
				"-DCUDA_BACKEND=local".into(),
				"-DCMAKE_BUILD_TYPE=Release".into(),
				"-DCMAKE_CUDA_ARCHITECTURES=native".into(),
				format!("-DCMAKE_INSTALL_PREFIX={}", icicle_install.display()),
			],
			Some("install"),
		);
	}

	// gnark-cuda: the `gpu_*` C-ABI shim (icicle delegation + bespoke PLONK kernels).
	let gc_src = git_fetch(out, "gnark-cuda", GNARK_CUDA_REPO, GNARK_CUDA_REV);
	let gc_build = out.join("gnark-cuda-build");
	if !gc_build.join("libgnark_cuda.a").exists() {
		patch_gnark_cuda_static(&gc_src);
		cmake(
			&gc_src,
			&gc_build,
			&[
				"-DCMAKE_BUILD_TYPE=Release".into(),
				"-DCMAKE_CUDA_ARCHITECTURES=native".into(),
				format!("-DICICLE_INSTALL_DIR={}", icicle_install.display()),
				// gnark-cuda's CMake reads headers from `${ICICLE_SRC_DIR}/icicle/include`, so
				// this is the open-icicle repo root (not its `icicle/` subdir).
				format!("-DICICLE_SRC_DIR={}", icicle_src.display()),
			],
			// Only the library — gnark-cuda's optional `test_shim` exe needs test-only headers.
			Some("gnark_cuda"),
		);
	}

	GpuDeps { include: gc_src.join("include"), gnark_cuda_lib: gc_build, icicle_install, cuda_lib }
}

/// Patch open-icicle to build static libraries (it hardcodes `SHARED`) and to resolve CUDA
/// device symbols into each backend `.a` so a host linker can consume them. Idempotent: resets
/// the checkout to pristine first.
fn patch_icicle_static(src: &Path) {
	git_reset(src);
	let ic = src.join("icicle");
	replace(
		&ic.join("CMakeLists.txt"),
		"add_library(icicle_device SHARED",
		"add_library(icicle_device STATIC",
	);
	replace(
		&ic.join("cmake/curve.cmake"),
		"add_library(icicle_curve SHARED)",
		"add_library(icicle_curve STATIC)",
	);
	replace(
		&ic.join("cmake/field.cmake"),
		"add_library(icicle_field SHARED)",
		"add_library(icicle_field STATIC)",
	);
	let backend = ic.join("backend/cuda/CMakeLists.txt");
	replace(
		&backend,
		"add_library(icicle_backend_cuda_device SHARED",
		"add_library(icicle_backend_cuda_device STATIC",
	);
	replace(
		&backend,
		"add_library(icicle_cuda_field SHARED",
		"add_library(icicle_cuda_field STATIC",
	);
	replace(
		&backend,
		"add_library(icicle_cuda_curve SHARED",
		"add_library(icicle_cuda_curve STATIC",
	);
	append(
		&backend,
		"\nforeach(t icicle_backend_cuda_device icicle_cuda_field icicle_cuda_curve)\n  \
		 if(TARGET ${t})\n    set_target_properties(${t} PROPERTIES \
		 CUDA_RESOLVE_DEVICE_SYMBOLS ON POSITION_INDEPENDENT_CODE ON)\n  endif()\nendforeach()\n",
	);
	// Quiet icicle's own startup logs: the dlopen "Failed to load backend" INFO is moot once the
	// backend is statically registered, and the per-device "Registering DEVICE" DEBUG line is
	// noise. Default the minimum log level to Warning (warnings/errors still print).
	let log_h = ic.join("include/icicle/utils/log.h");
	replace(&log_h, "s_min_log_level = eLogLevel::Info;", "s_min_log_level = eLogLevel::Warning;");
	replace(&log_h, "s_min_log_level = eLogLevel::Debug;", "s_min_log_level = eLogLevel::Warning;");
}

/// Patch gnark-cuda to build a static library with its CUDA device symbols resolved.
fn patch_gnark_cuda_static(src: &Path) {
	git_reset(src);
	let cml = src.join("CMakeLists.txt");
	replace(&cml, "add_library(gnark_cuda SHARED", "add_library(gnark_cuda STATIC");
	append(&cml, "\nset_target_properties(gnark_cuda PROPERTIES CUDA_RESOLVE_DEVICE_SYMBOLS ON)\n");
}

fn replace(path: &Path, from: &str, to: &str) {
	let s = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
	assert!(s.contains(from), "patch anchor not found in {}: {from:?}", path.display());
	fs::write(path, s.replace(from, to)).unwrap();
}

fn append(path: &Path, text: &str) {
	let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
	f.write_all(text.as_bytes()).unwrap();
}

fn git_reset(dir: &Path) {
	run(Command::new("git").args(["checkout", "-q", "--", "."]).current_dir(dir));
}

/// Shallow-fetch a single pinned commit of `repo` into `out/<name>` (idempotent: a no-op once
/// the pinned commit is already checked out, so rebuilds don't hit the network).
fn git_fetch(out: &Path, name: &str, repo: &str, rev: &str) -> PathBuf {
	let dir = out.join(name);
	let at_rev = dir.join(".git").exists() &&
		Command::new("git")
			.args(["rev-parse", "HEAD"])
			.current_dir(&dir)
			.output()
			.map(|o| String::from_utf8_lossy(&o.stdout).trim() == rev)
			.unwrap_or(false);
	if !at_rev {
		fs::create_dir_all(&dir).unwrap();
		if !dir.join(".git").exists() {
			run(Command::new("git").args(["init", "-q"]).current_dir(&dir));
			run(Command::new("git").args(["remote", "add", "origin", repo]).current_dir(&dir));
		}
		run(Command::new("git")
			.args(["fetch", "-q", "--depth", "1", "origin", rev])
			.current_dir(&dir));
		run(Command::new("git").args(["checkout", "-q", "FETCH_HEAD"]).current_dir(&dir));
	}
	dir
}

/// Configure + build a CMake project, optionally invoking a target (e.g. `install`).
fn cmake(src: &Path, build: &Path, args: &[String], target: Option<&str>) {
	run(Command::new("cmake").arg("-S").arg(src).arg("-B").arg(build).args(args));

	let mut b = Command::new("cmake");
	b.arg("--build").arg(build).arg("--parallel");
	if let Some(t) = target {
		b.arg("--target").arg(t);
	}
	run(&mut b);
}

fn run(cmd: &mut Command) {
	let rendered = format!("{cmd:?}");
	let status = cmd
		.status()
		.unwrap_or_else(|e| panic!("failed to spawn {rendered}: {e} (is the tool installed?)"));
	assert!(status.success(), "command failed ({status}): {rendered}");
}
