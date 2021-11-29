#![feature(unboxed_closures, rustc_attrs, const_fn_trait_bound)]
#![warn(missing_docs)]
#![allow(unknown_lints)]

#[macro_use]
extern crate lazy_static;
extern crate kernel32;
extern crate libc;
extern crate winapi;

use std::ffi::OsStr;
use std::ops::Deref;
use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;
use std::{mem, ptr, result};

use function::{FnPointer, Function, HookableWith};

pub use error::Error;
pub use sync::AtomicInitCell;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::ntdef::{LPCSTR, WCHAR};
use winapi::um::winnls::CP_ACP;

mod error;
mod minhook;
mod sync;
#[macro_use]
mod macros;

pub mod function;
pub mod panic;

/// Result type for most functions and methods in this module.
pub type Result<T> = result::Result<T, Error>;

/// A queue of hook changes to be applied at once.
#[derive(Debug, Default)]
pub struct HookQueue(Vec<(FnPointer, bool)>);

impl HookQueue {
    /// Create a new empty queue.
    pub fn new() -> HookQueue {
        HookQueue(Vec::new())
    }

    /// Queue the given hook to be enabled.
    pub fn enable<T: Function>(&mut self, hook: &Hook<T>) -> &mut HookQueue {
        self.0.push((hook.target, true));
        self
    }

    /// Queue the given hook to be disabled.
    pub fn disable<T: Function>(&mut self, hook: &Hook<T>) -> &mut HookQueue {
        self.0.push((hook.target, false));
        self
    }

    /// Applies all the changes in this queue at once.
    pub fn apply(&mut self) -> Result<()> {
        lazy_static! {
            static ref LOCK: Mutex<()> = Mutex::new(());
        }

        initialize()?;
        let _lock = LOCK.lock().unwrap();

        unsafe {
            for &(target, enabled) in &self.0 {
                // Any failure at this point is a bug.
                if enabled {
                    s2r(minhook::MH_QueueEnableHook(target.to_raw())).unwrap();
                } else {
                    s2r(minhook::MH_QueueDisableHook(target.to_raw())).unwrap();
                }
            }
            s2r(minhook::MH_ApplyQueued())
        }
    }
}

/// A hook that is destroyed when it goes out of scope.
#[derive(Debug)]
pub struct Hook<T: Function> {
    target: FnPointer,
    trampoline: T,
}

impl<T: Function> Hook<T> {
    /// Create a new hook given a target function and a compatible detour function.
    ///
    /// The hook is disabled by default. Even when this function is succesful, there is no
    /// guaranteee that the detour function will actually get called when the target function gets
    /// called. An invocation of the target function might for example get inlined in which case
    /// it is impossible to hook at runtime.
    ///
    /// # Safety
    ///
    /// The given target function type must uniquely match the actual target function. This
    /// means two things: the given target function type has to be correct, but also there
    /// can not be two function pointers with different signatures pointing to the same
    /// code location. This last situation can for example happen when the Rust compiler
    /// or LLVM decide to merge multiple functions with the same code into one.
    pub unsafe fn create<D>(target: T, detour: D) -> Result<Hook<T>>
    where
        T: HookableWith<D>,
        D: Function,
    {
        initialize()?;

        let target = target.to_ptr();
        let detour = detour.to_ptr();
        let mut trampoline = mem::MaybeUninit::<LPVOID>::uninit();
        s2r(minhook::MH_CreateHook(
            target.to_raw(),
            detour.to_raw(),
            trampoline.as_mut_ptr(),
        ))?;

        Ok(Hook {
            target,
            trampoline: T::from_ptr(FnPointer::from_raw(trampoline.assume_init())),
        })
    }

    /// Create a new hook given the name of the module, the name of the function symbol and a
    /// compatible detour function.
    ///
    /// The module has to be loaded before this function is called. This function does not
    /// attempt to load the module first. The hook is disabled by default.
    ///
    /// # Safety
    ///
    /// The target module must remain loaded in memory for the entire duration of the hook.
    ///
    /// See `create()` for more safety requirements.
    pub unsafe fn create_api<M, D>(
        target_module: M,
        target_function: FunctionId,
        detour: D,
    ) -> Result<Hook<T>>
    where
        M: AsRef<OsStr>,
        T: HookableWith<D>,
        D: Function,
    {
        fn str_to_wstring(string: &OsStr) -> Option<Vec<WCHAR>> {
            let mut wide = string.encode_wide().collect::<Vec<_>>();
            if wide.contains(&0) {
                return None;
            }
            wide.push(0);
            Some(wide)
        }

        initialize()?;

        let module_name = str_to_wstring(target_module.as_ref()).ok_or(Error::InvalidModuleName)?;

        let (function_name, _data) = match target_function {
            FunctionId::Ordinal(ord) => (ord as LPCSTR, Vec::new()),
            FunctionId::Name(name) => {
                let symbol_name_wide = str_to_wstring(name).ok_or(Error::InvalidFunctionName)?;

                let size = kernel32::WideCharToMultiByte(
                    CP_ACP,
                    0,
                    symbol_name_wide.as_ptr(),
                    -1,
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                );
                if size == 0 {
                    return Err(Error::InvalidFunctionName);
                }

                let mut buffer = Vec::with_capacity(size as usize);
                buffer.set_len(size as usize);

                let size = kernel32::WideCharToMultiByte(
                    CP_ACP,
                    0,
                    symbol_name_wide.as_ptr(),
                    -1,
                    buffer.as_mut_ptr(),
                    size,
                    ptr::null(),
                    ptr::null_mut(),
                );
                if size == 0 {
                    return Err(Error::InvalidFunctionName);
                }

                (buffer.as_ptr(), buffer)
            }
        };

        let detour = detour.to_ptr();
        let mut trampoline = mem::MaybeUninit::<LPVOID>::uninit();
        let mut target = mem::MaybeUninit::<LPVOID>::uninit();

        s2r(minhook::MH_CreateHookApiEx(
            module_name.as_ptr(),
            function_name,
            detour.to_raw(),
            trampoline.as_mut_ptr(),
            target.as_mut_ptr(),
        ))?;

        Ok(Hook {
            target: FnPointer::from_raw(target.assume_init()),
            trampoline: T::from_ptr(FnPointer::from_raw(trampoline.assume_init())),
        })
    }

    /// Returns a pointer to the trampoline function.
    ///
    /// Calling the returned function is unsafe because it will point to invalid memory after the
    /// hook is destroyed.
    pub fn trampoline(&self) -> T::Unsafe {
        self.trampoline.to_unsafe()
    }

    /// Enables this hook.
    ///
    /// Consider using a `HookQueue` if you want to enable/disable a large amount of hooks at once.
    pub fn enable(&self) -> Result<()> {
        unsafe { s2r(minhook::MH_EnableHook(self.target.to_raw())) }
    }

    /// Disables this hook.
    ///
    /// Consider using a `HookQueue` if you want to enable/disable a large amount of hooks at once.
    pub fn disable(&self) -> Result<()> {
        unsafe { s2r(minhook::MH_DisableHook(self.target.to_raw())) }
    }
}

impl<T: Function> Drop for Hook<T> {
    fn drop(&mut self) {
        let _ = unsafe { s2r(minhook::MH_RemoveHook(self.target.to_raw())) };
    }
}

// Synchronization is done in the MinHook library.
unsafe impl<T: Function> Sync for Hook<T> {}
unsafe impl<T: Function> Send for Hook<T> {}

/// A function identifier used for dynamically looking up a function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionId<'a> {
    /// The function's ordinal value.
    Ordinal(u16),
    /// The function's name.
    Name(&'a OsStr),
}

impl<'a> FunctionId<'a> {
    /// Create a function identifier given it's ordinal value.
    pub fn ordinal(value: u16) -> FunctionId<'static> {
        FunctionId::Ordinal(value)
    }

    /// Create a function identifier given it's string name.
    pub fn name<N: ?Sized + AsRef<OsStr> + 'a>(name: &'a N) -> FunctionId<'a> {
        FunctionId::Name(name.as_ref())
    }
}

/// A hook with a static lifetime.
///
/// This hook can only be constructed using the `static_hooks!` macro. It has one of the
/// following forms:
///
/// ```ignore
/// #[ATTR]* pub? impl HOOK_VAR_NAME for PATH::TO::TARGET: FN_TYPE;
/// #[ATTR]* pub? impl HOOK_VAR_NAME for "FUNCTION" in "MODULE": FN_TYPE;
/// ```
///
/// Before accessing this hook it is **required** to call `initialize()`. Accessing the hook
/// before initializing or trying to initialize the hook more than once will result in a panic.
pub struct StaticHook<T: Function> {
    hook: &'static AtomicInitCell<__StaticHookInner<T>>,
    target: __StaticHookTarget<T>,
    detour: T,
}

impl<T: Function> StaticHook<T> {
    #[doc(hidden)]
    pub const fn __new(
        hook: &'static AtomicInitCell<__StaticHookInner<T>>,
        target: __StaticHookTarget<T>,
        detour: T,
    ) -> StaticHook<T> {
        StaticHook {
            hook: hook,
            target: target,
            detour: detour,
        }
    }

    /// Returns a reference to the trampoline function.
    pub fn trampoline(&self) -> T {
        self.inner().trampoline
    }

    unsafe fn initialize_ref(
        &self,
        closure: &'static (dyn Fn<T::Args, Output = T::Output> + Sync),
    ) -> Result<()> {
        let hook = match self.target {
            __StaticHookTarget::Static(target) => Hook::create(target, self.detour)?,
            __StaticHookTarget::Dynamic(module_name, function_name) => {
                Hook::create_api(module_name, FunctionId::name(function_name), self.detour)?
            }
        };

        Ok(self
            .hook
            .initialize(__StaticHookInner(hook, closure))
            .expect("static hook already initialized"))
    }

    unsafe fn initialize_box(
        &self,
        closure: Box<dyn Fn<T::Args, Output = T::Output> + Sync>,
    ) -> Result<()> {
        self.initialize_ref(&*(&*closure as *const _))?;
        mem::forget(closure);
        Ok(())
    }

    /// Initialize and install the underlying hook using a detour closure.
    ///
    /// # Panics
    ///
    /// Panics if the hook was already initialized.
    ///
    /// # Safety
    ///
    /// See documentation for [`Hook::create()`](struct.Hook.html#method.create) and
    /// [`Hook::create_api()`](struct.Hook.html#method.create_api)
    pub unsafe fn initialize<F>(&self, closure: F) -> Result<()>
    where
        F: Fn<T::Args, Output = T::Output> + Sync + 'static,
    {
        self.initialize_box(Box::new(closure))
    }

    fn inner(&self) -> &'static Hook<T> {
        let &__StaticHookInner(ref hook, _) = self
            .hook
            .get()
            .expect("attempt to access uninitialized static hook");
        hook
    }
}

impl<T: Function> Deref for StaticHook<T> {
    type Target = Hook<T>;

    fn deref(&self) -> &Hook<T> {
        self.inner()
    }
}

/// A hook with a static lifetime and a default detour closure.
///
/// This hook can only be constructed using the `static_hooks!` macro. It has one of the
/// following forms:
///
/// ```ignore
/// #[ATTR]* pub? impl HOOK_VAR_NAME for PATH::TO::TARGET: FN_TYPE = CLOSURE_EXPR;
/// #[ATTR]* pub? impl HOOK_VAR_NAME for "FUNCTION" in "MODULE": FN_TYPE = CLOSURE_EXPR;
/// ```
///
/// Before accessing this hook it is **required** to call `initialize()`. Accessing the hook
/// before initializing or trying to initialize the hook more than once will result in a panic.
pub struct StaticHookWithDefault<T: Function> {
    inner: StaticHook<T>,
    default: &'static (dyn Fn<T::Args, Output = T::Output> + Sync),
}

impl<T: Function> StaticHookWithDefault<T> {
    #[doc(hidden)]
    pub const fn __new(
        hook: StaticHook<T>,
        default: &'static (dyn Fn<T::Args, Output = T::Output> + Sync),
    ) -> StaticHookWithDefault<T> {
        StaticHookWithDefault {
            inner: hook,
            default: default,
        }
    }

    /// Initialize and install the underlying hook.
    ///
    /// # Panics
    ///
    /// Panics if the hook was already initialized.
    ///
    /// # Safety
    ///
    /// See documentation for [`Hook::create()`](struct.Hook.html#method.create) and
    /// [`Hook::create_api()`](struct.Hook.html#method.create_api)
    pub unsafe fn initialize(&self) -> Result<()> {
        self.inner.initialize_ref(self.default)
    }
}

impl<T: Function> Deref for StaticHookWithDefault<T> {
    type Target = StaticHook<T>;

    fn deref(&self) -> &StaticHook<T> {
        &self.inner
    }
}

fn initialize() -> Result<()> {
    // Clean-up is *required* in DLLs. If a DLL gets unloaded while static hooks are installed
    // the hook instructions will point to detour functions that are already unloaded.
    extern "C" fn cleanup() {
        let _ = unsafe { minhook::MH_Uninitialize() };
    }

    unsafe {
        s2r(minhook::MH_Initialize())
            .map(|_| {
                libc::atexit(cleanup);
            })
            .or_else(|error| match error {
                Error::AlreadyInitialized => Ok(()),
                error => Err(error),
            })
    }
}

fn s2r(status: minhook::MH_STATUS) -> Result<()> {
    Error::from_status(status).map_or(Ok(()), Err)
}

#[doc(hidden)]
pub struct __StaticHookInner<T: Function>(
    pub Hook<T>,
    pub &'static (dyn Fn<T::Args, Output = T::Output> + Sync),
);

#[doc(hidden)]
pub enum __StaticHookTarget<T: Function> {
    Static(T),
    Dynamic(&'static str, &'static str),
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::mem;
    use std::os::raw::c_int;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::Mutex;

    use {kernel32, winapi};

    use super::*;
    use winapi::shared::ntdef::{LPCSTR, LPCWSTR};

    #[test]
    fn local() {
        fn f(x: i32) -> i32 {
            x * 2
        }
        fn d(x: i32) -> i32 {
            x * 3
        }

        assert_eq!(f(5), 10);
        let h = unsafe { Hook::<fn(i32) -> i32>::create(f, d).unwrap() };
        assert_eq!(f(5), 10);
        h.enable().unwrap();
        assert_eq!(f(5), 15);
        h.disable().unwrap();
        assert_eq!(f(5), 10);
        h.enable().unwrap();
        assert_eq!(f(5), 15);
        mem::drop(h);
        assert_eq!(f(5), 10);
    }

    #[test]
    fn local_dynamic() {
        extern "system" fn lstrlen_w_detour(_string: LPCWSTR) -> c_int {
            -42
        }

        let foo = OsStr::new("foo")
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        unsafe {
            assert_eq!(kernel32::lstrlenW(foo.as_ptr()), 3);
            let h = Hook::<extern "system" fn(LPCWSTR) -> c_int>::create_api(
                "kernel32.dll",
                FunctionId::name("lstrlenW"),
                lstrlen_w_detour,
            )
            .unwrap();
            assert_eq!(kernel32::lstrlenW(foo.as_ptr()), 3);
            h.enable().unwrap();
            assert_eq!(kernel32::lstrlenW(foo.as_ptr()), -42);
            h.disable().unwrap();
            assert_eq!(kernel32::lstrlenW(foo.as_ptr()), 3);
        }
    }

    #[test]
    fn static_with_default() {
        fn f(x: i32, y: i32) -> i32 {
            x + y
        }

        static_hooks! {
            impl h for f: fn(i32, i32) -> i32 = |x, y| x * y;
        }

        assert_eq!(f(3, 6), 9);
        unsafe {
            h.initialize().unwrap();
        }
        assert_eq!(f(3, 6), 9);
        h.enable().unwrap();
        assert_eq!(f(3, 6), 18);
        h.disable().unwrap();
        assert_eq!(f(3, 6), 9);
    }

    #[test]
    fn static_no_default() {
        fn f(x: i32, y: i32) -> i32 {
            x + y
        }

        static_hooks! {
            impl h for f: fn(i32, i32) -> i32;
        }

        let y = Mutex::new(2);
        let d = move |x, _| {
            let mut y = y.lock().unwrap();
            let r = h.call_real(x, *y);
            *y += 1;
            r
        };

        assert_eq!(f(3, 6), 9);
        unsafe {
            h.initialize(d).unwrap();
        }
        assert_eq!(f(3, 6), 9);
        h.enable().unwrap();
        assert_eq!(f(3, 6), 5);
        assert_eq!(f(3, 6), 6);
        assert_eq!(f(3, 66), 7);
        h.disable().unwrap();
        assert_eq!(f(3, 6), 9);
    }

    #[test]
    fn static_dynamic() {
        static_hooks! {
            impl h for "lstrlenA" in "kernel32.dll": extern "system" fn(LPCSTR) -> c_int = |s| -h.call_real(s);
        }

        let foobar = b"foobar\0".as_ptr() as LPCSTR;
        unsafe {
            assert_eq!(kernel32::lstrlenA(foobar), 6);
            h.initialize().unwrap();
            assert_eq!(kernel32::lstrlenA(foobar), 6);
            h.enable().unwrap();
            assert_eq!(kernel32::lstrlenA(foobar), -6);
            h.disable().unwrap();
            assert_eq!(kernel32::lstrlenA(foobar), 6);
        }
    }

    #[test]
    #[should_panic]
    fn static_use_before_init() {
        fn f() {}

        static_hooks! {
            impl h for f: fn() = || ();
        }

        h.enable().unwrap();
    }

    #[test]
    fn queue() {
        fn f1(x: &str) -> &str {
            x
        }
        fn d1(_x: &str) -> &str {
            "bar"
        }

        fn f2(x: i32) -> i32 {
            x * 2
        }
        fn d2(x: i32) -> i32 {
            x + 2
        }

        fn f3(x: i32) -> Option<u32> {
            if x < 0 {
                None
            } else {
                Some(x as u32)
            }
        }
        fn d3(x: i32) -> Option<u32> {
            Some(x.abs() as u32)
        }

        let (h1, h2, h3) = unsafe {
            (
                Hook::<fn(&'static str) -> &'static str>::create(f1, d1).unwrap(),
                Hook::<fn(i32) -> i32>::create(f2, d2).unwrap(),
                Hook::<fn(i32) -> Option<u32>>::create(f3, d3).unwrap(),
            )
        };

        HookQueue::new()
            .enable(&h1)
            .disable(&h2)
            .enable(&h3)
            .disable(&h3)
            .apply()
            .unwrap();

        assert_eq!(f1("foo"), "bar");
        assert_eq!(f2(42), 84);
        assert_eq!(f3(-10), None);
    }
}
