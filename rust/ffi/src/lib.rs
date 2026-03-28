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

#[repr(C)]
pub struct CProveResult {
	pub proof_data: *const u8,
	pub proof_len: u32,
	pub public_inputs_data: *const u8,
	pub public_inputs_len: u32,
	pub error: *const std::ffi::c_char,
}

impl Default for CProveResult {
	fn default() -> Self {
		Self {
			proof_data: std::ptr::null(),
			proof_len: 0,
			public_inputs_data: std::ptr::null(),
			public_inputs_len: 0,
			error: std::ptr::null(),
		}
	}
}

extern "C" {
	pub fn APKSetup(srs_dir: *const std::ffi::c_char) -> u64;
	pub fn APKFreeHandle(handle: u64);

	pub fn APKProve(
		handle: u64,
		witness_data: *const u8,
		witness_len: u32,
		result: *mut CProveResult,
	) -> i32;

	pub fn APKFreeResult(result: *mut CProveResult);

	pub fn APKExportVK(handle: u64, result: *mut CBuffer) -> i32;

	pub fn APKFreeBuffer(buf: *mut CBuffer);
}

#[repr(C)]
pub struct CBuffer {
	pub data: *const u8,
	pub len: u32,
}

impl Default for CBuffer {
	fn default() -> Self {
		Self { data: std::ptr::null(), len: 0 }
	}
}
