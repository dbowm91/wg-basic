//! The only unsafe module in this crate.
//!
//! Layouts for `wireguard.h` are copied from the pinned header. Win32 calls
//! use `windows-sys`. Nothing here starts a process.

#![allow(unsafe_code)]
#![allow(clippy::undocumented_unsafe_blocks)]

use super::{DeviceConfig, HostAddress, HostRoute, NatObject, PeerConfig, ServiceSpec};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_MORE_DATA, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, FALSE, HANDLE, INVALID_HANDLE_VALUE, TRUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetIpForwardTable2, GetUnicastIpAddressTable,
    InitializeIpForwardEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserAdd, NetUserDel, NetUserGetLocalGroups, LG_INCLUDE_INDIRECT,
    LOCALGROUP_USERS_INFO_0, USER_INFO_1, USER_PRIV_USER,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, LookupAccountNameW, TokenIntegrityLevel, TokenUser,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileAttributesW, LockFileEx, CREATE_NEW, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, INVALID_FILE_ATTRIBUTES, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, RegSetKeyValueW, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
    KEY_SET_VALUE, REG_DWORD, RRF_RT_REG_DWORD,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, StartServiceW, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL,
    SERVICE_FAILURE_ACTIONSW, SERVICE_STATUS, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOEXW};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;
const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
const NERR_USER_EXISTS: u32 = 2224;
const NERR_USER_NOT_FOUND: u32 = 2221;
const UF_SCRIPT: u32 = 0x0001;
const UF_NORMAL_ACCOUNT: u32 = 0x0200;
const UF_DONT_EXPIRE_PASSWD: u32 = 0x10000;

#[derive(Clone, Debug)]
pub struct SysError {
    operation: &'static str,
    code: Option<u32>,
}

impl SysError {
    pub fn invalid(operation: &'static str) -> Self {
        Self {
            operation,
            code: None,
        }
    }

    fn os(operation: &'static str, code: u32) -> Self {
        Self {
            operation,
            code: Some(code),
        }
    }

    fn last(operation: &'static str) -> Self {
        Self::os(operation, unsafe { GetLastError() })
    }

    pub fn is_timeout(&self) -> bool {
        self.code == Some(258)
    }
}

impl std::fmt::Display for SysError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(formatter, "{} failed: os error {code}", self.operation),
            None => write!(formatter, "{} refused", self.operation),
        }
    }
}

impl std::error::Error for SysError {}

#[derive(Clone, Debug)]
pub struct OsFacts {
    pub caption: String,
    pub build: u32,
    pub architecture: String,
    pub installation_type: String,
}

pub struct PipeHandle {
    handle: HANDLE,
}

pub struct AcceptedRaw {
    pub io: File,
    pub peer_sid: String,
    pub high_integrity: bool,
}

pub type AdapterHandle = *mut std::ffi::c_void;

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn current_user_sid() -> Result<String, SysError> {
    unsafe {
        let mut token = INVALID_HANDLE_VALUE;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            return Err(SysError::last("OpenProcessToken"));
        }
        let sid = token_user_sid(token).map_err(|_| SysError::last("GetTokenInformation"))?;
        CloseHandle(token);
        sid_string(sid)
    }
}

pub fn lookup_account_sid(account: &str) -> Result<String, SysError> {
    let name = wide(account);
    unsafe {
        let mut sid = vec![0u8; 68];
        let mut sid_len = sid.len() as u32;
        let mut referenced = vec![0u16; 256];
        let mut referenced_len = referenced.len() as u32;
        let mut use_name = 0i32;
        if LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            referenced.as_mut_ptr(),
            &mut referenced_len,
            &mut use_name,
        ) == FALSE
        {
            return Err(SysError::last("LookupAccountNameW"));
        }
        sid_string(sid.as_mut_ptr().cast())
    }
}

unsafe fn token_user_sid(token: HANDLE) -> Result<*mut std::ffi::c_void, ()> {
    let mut needed = 0u32;
    GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    let mut buffer = vec![0u8; needed as usize];
    if GetTokenInformation(
        token,
        TokenUser,
        buffer.as_mut_ptr().cast(),
        needed,
        &mut needed,
    ) == FALSE
    {
        return Err(());
    }
    let user = &*(buffer.as_ptr() as *const TOKEN_USER);
    Ok(user.User.Sid)
}

unsafe fn sid_string(sid: *mut std::ffi::c_void) -> Result<String, SysError> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut raw = ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut raw) == FALSE || raw.is_null() {
        return Err(SysError::last("ConvertSidToStringSidW"));
    }
    let mut len = 0usize;
    while *raw.add(len) != 0 {
        len += 1;
    }
    let text = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
    windows_sys::Win32::Foundation::LocalFree(raw.cast());
    Ok(text)
}

pub fn create_pipe(name: &str, serve_sid: &str, own_sid: &str) -> Result<PipeHandle, SysError> {
    let sddl = format!("D:P(A;;GA;;;{serve_sid})(A;;GA;;;{own_sid})S:(ML;;NW;;;HI)");
    let sddl_w = wide(&sddl);
    let name_w = wide(name);
    unsafe {
        let mut sd = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            1,
            &mut sd,
            ptr::null_mut(),
        ) == FALSE
        {
            return Err(SysError::last("ConvertStringSecurityDescriptor"));
        }
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: FALSE,
        };
        let handle = CreateNamedPipeW(
            name_w.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            &security,
        );
        windows_sys::Win32::Foundation::LocalFree(sd.cast());
        if handle == INVALID_HANDLE_VALUE {
            let code = GetLastError();
            if code == ERROR_ACCESS_DENIED
                || code == ERROR_PIPE_BUSY
                || code == ERROR_ALREADY_EXISTS
            {
                return Err(SysError::os("pipe already exists", code));
            }
            return Err(SysError::os("CreateNamedPipeW", code));
        }
        Ok(PipeHandle { handle })
    }
}

pub fn disconnect_pipe(pipe: &PipeHandle) {
    unsafe {
        if pipe.handle != INVALID_HANDLE_VALUE {
            DisconnectNamedPipe(pipe.handle);
        }
    }
}

pub fn close_pipe(pipe: &mut PipeHandle) {
    unsafe {
        if pipe.handle != INVALID_HANDLE_VALUE {
            DisconnectNamedPipe(pipe.handle);
            CloseHandle(pipe.handle);
            pipe.handle = INVALID_HANDLE_VALUE;
        }
    }
}

pub fn accept_pipe(pipe: &PipeHandle) -> Result<AcceptedRaw, SysError> {
    unsafe {
        let mut overlapped = std::mem::zeroed::<OVERLAPPED>();
        let event = windows_sys::Win32::System::Threading::CreateEventW(
            ptr::null(),
            TRUE,
            FALSE,
            ptr::null(),
        );
        if event.is_null() {
            return Err(SysError::last("CreateEventW"));
        }
        overlapped.hEvent = event;
        let connected = ConnectNamedPipe(pipe.handle, &mut overlapped);
        if connected == FALSE {
            let code = GetLastError();
            if code == ERROR_PIPE_CONNECTED {
                // A client raced the connect. Fall through.
            } else if code == error_io_pending() {
                let wait = windows_sys::Win32::System::Threading::WaitForSingleObject(event, 200);
                if wait == WAIT_TIMEOUT {
                    windows_sys::Win32::System::IO::CancelIoEx(pipe.handle, &overlapped);
                    CloseHandle(event);
                    return Err(SysError::os("accept timeout", WAIT_TIMEOUT));
                }
                if wait != WAIT_OBJECT_0 {
                    CloseHandle(event);
                    return Err(SysError::os("WaitForSingleObject", wait));
                }
            } else {
                CloseHandle(event);
                return Err(SysError::os("ConnectNamedPipe", code));
            }
        }
        CloseHandle(event);
        let mut pid = 0u32;
        if GetNamedPipeClientProcessId(pipe.handle, &mut pid) == FALSE {
            return Err(SysError::last("GetNamedPipeClientProcessId"));
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if process.is_null() {
            return Err(SysError::last("OpenProcess"));
        }
        let mut token = INVALID_HANDLE_VALUE;
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == FALSE {
            CloseHandle(process);
            return Err(SysError::last("OpenProcessToken"));
        }
        let sid = match token_user_sid(token) {
            Ok(sid) => sid_string(sid),
            Err(()) => Err(SysError::last("peer token")),
        };
        let high = token_is_high(token);
        CloseHandle(token);
        CloseHandle(process);
        let sid = sid?;
        let io = File::from_raw_handle(pipe.handle as RawHandle);
        // The listener still owns the handle. Duplicate so the File drop does
        // not close the listening instance.
        drop(io);
        let duplicated = duplicate(pipe.handle)?;
        Ok(AcceptedRaw {
            io: File::from_raw_handle(duplicated as RawHandle),
            peer_sid: sid,
            high_integrity: high?,
        })
    }
}

fn error_io_pending() -> u32 {
    997
}

unsafe fn duplicate(handle: HANDLE) -> Result<HANDLE, SysError> {
    let mut out = INVALID_HANDLE_VALUE;
    if windows_sys::Win32::Foundation::DuplicateHandle(
        GetCurrentProcess(),
        handle,
        GetCurrentProcess(),
        &mut out,
        0,
        FALSE,
        0x00000002, // DUPLICATE_SAME_ACCESS
    ) == FALSE
    {
        return Err(SysError::last("DuplicateHandle"));
    }
    Ok(out)
}

unsafe fn token_is_high(token: HANDLE) -> Result<bool, SysError> {
    let mut needed = 0u32;
    GetTokenInformation(token, TokenIntegrityLevel, ptr::null_mut(), 0, &mut needed);
    if needed == 0 {
        return Err(SysError::last("TokenIntegrityLevel"));
    }
    let mut buffer = vec![0u8; needed as usize];
    if GetTokenInformation(
        token,
        TokenIntegrityLevel,
        buffer.as_mut_ptr().cast(),
        needed,
        &mut needed,
    ) == FALSE
    {
        return Err(SysError::last("TokenIntegrityLevel"));
    }
    // TOKEN_MANDATORY_LABEL { SidAndAttributes Label; } and the RID is the last sub-authority.
    let label_sid = *(buffer.as_ptr() as *const *mut std::ffi::c_void);
    let sid_text = sid_string(label_sid)?;
    // High is S-1-16-12288. System is S-1-16-16384.
    Ok(sid_text == "S-1-16-12288" || sid_text == "S-1-16-16384")
}

pub fn connect_pipe(name: &str) -> io::Result<File> {
    let name_w = wide(name);
    unsafe {
        let handle = CreateFileW(
            name_w.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(GetLastError() as i32));
        }
        Ok(File::from_raw_handle(handle as RawHandle))
    }
}

pub fn pipe_exists(name: &str) -> Result<bool, SysError> {
    match connect_pipe(name) {
        Ok(file) => {
            drop(file);
            Ok(true)
        }
        Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Ok(true),
    }
}

pub fn restrict_to_current_user(path: &str) -> Result<(), SysError> {
    let sid = current_user_sid()?;
    restrict_to_sid(path, &sid)
}

pub fn restrict_to_sid(path: &str, sid: &str) -> Result<(), SysError> {
    if !sid.starts_with("S-1-") || sid.contains(|ch: char| ch.is_whitespace() || ch == '"') {
        return Err(SysError::invalid("sid"));
    }
    let sddl = format!("D:P(A;;FA;;;{sid})");
    apply_sddl(path, &sddl)
}

pub fn is_private(path: &str) -> Result<bool, SysError> {
    if is_reparse(path)? {
        return Ok(false);
    }
    let sid = current_user_sid()?;
    // Re-apply is not a proof. Read the DACL and require exactly one allow ACE
    // for the current user by comparing to the SDDL we would have written:
    // a protected DACL whose only trustee is the current user.
    let path_w = wide(path);
    unsafe {
        let mut sd = ptr::null_mut();
        let mut dacl: *mut windows_sys::Win32::Security::ACL = ptr::null_mut();
        let mut owner: *mut std::ffi::c_void = ptr::null_mut();
        let code = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        );
        if code != 0 {
            return Err(SysError::os("GetNamedSecurityInfoW", code));
        }
        let owner_text = sid_string(owner)?;
        let private = owner_text == sid && dacl_only_user(dacl, owner);
        windows_sys::Win32::Foundation::LocalFree(sd.cast());
        Ok(private)
    }
}

unsafe fn dacl_only_user(
    dacl: *mut windows_sys::Win32::Security::ACL,
    owner: *mut std::ffi::c_void,
) -> bool {
    use windows_sys::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION,
    };
    if dacl.is_null() {
        return false;
    }
    let mut info = std::mem::zeroed::<ACL_SIZE_INFORMATION>();
    if GetAclInformation(
        dacl,
        &mut info as *mut _ as *mut _,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    ) == FALSE
    {
        return false;
    }
    if info.AceCount != 1 {
        return false;
    }
    let mut ace = ptr::null_mut();
    if GetAce(dacl, 0, &mut ace) == FALSE {
        return false;
    }
    let header = &*(ace as *const windows_sys::Win32::Security::ACE_HEADER);
    // ACCESS_ALLOWED_ACE_TYPE = 0
    if header.AceType != 0 {
        return false;
    }
    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
    EqualSid(
        std::ptr::addr_of!(allowed.SidStart).cast_mut().cast(),
        owner,
    ) == TRUE
}

fn is_reparse(path: &str) -> Result<bool, SysError> {
    let path_w = wide(path);
    unsafe {
        let attributes = GetFileAttributesW(path_w.as_ptr());
        if attributes == INVALID_FILE_ATTRIBUTES {
            return Err(SysError::last("GetFileAttributesW"));
        }
        Ok(attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
}

fn apply_sddl(path: &str, sddl: &str) -> Result<(), SysError> {
    let path_w = wide(path);
    let sddl_w = wide(sddl);
    unsafe {
        let mut sd = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            1,
            &mut sd,
            ptr::null_mut(),
        ) == FALSE
        {
            return Err(SysError::last("ConvertStringSecurityDescriptor"));
        }
        let mut dacl = ptr::null_mut();
        let present = 0i32;
        let defaulted = 0i32;
        if windows_sys::Win32::Security::GetSecurityDescriptorDacl(
            sd,
            &present as *const i32 as *mut _,
            &mut dacl,
            &defaulted as *const i32 as *mut _,
        ) == FALSE
        {
            windows_sys::Win32::Foundation::LocalFree(sd.cast());
            return Err(SysError::last("GetSecurityDescriptorDacl"));
        }
        let code = SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        );
        windows_sys::Win32::Foundation::LocalFree(sd.cast());
        if code != 0 {
            return Err(SysError::os("SetNamedSecurityInfoW", code));
        }
        Ok(())
    }
}

pub fn create_private_file(path: &str) -> io::Result<File> {
    let path_w = wide(path);
    unsafe {
        let handle = windows_sys::Win32::Storage::FileSystem::CreateFileW(
            path_w.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            ptr::null(),
            CREATE_NEW,
            0x80, // FILE_ATTRIBUTE_NORMAL
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(GetLastError() as i32));
        }
        let file = File::from_raw_handle(handle as RawHandle);
        restrict_to_current_user(path)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        Ok(file)
    }
}

pub fn lock_exclusive(file: &File) -> Result<(), bool> {
    lock(file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)
}

pub fn lock_shared(file: &File) -> Result<(), bool> {
    lock(file, LOCKFILE_FAIL_IMMEDIATELY)
}

fn lock(file: &File, flags: u32) -> Result<(), bool> {
    unsafe {
        let mut overlapped = std::mem::zeroed::<OVERLAPPED>();
        if LockFileEx(
            file.as_raw_handle() as HANDLE,
            flags,
            0,
            1,
            0,
            &mut overlapped,
        ) == FALSE
        {
            let code = GetLastError();
            if code == 33 {
                // ERROR_LOCK_VIOLATION
                return Err(true);
            }
            return Err(false);
        }
        Ok(())
    }
}

pub fn os_facts() -> Result<OsFacts, SysError> {
    unsafe {
        let mut info = std::mem::zeroed::<OSVERSIONINFOEXW>();
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
        if GetVersionExW(&mut info as *mut _ as *mut _) == FALSE {
            return Err(SysError::last("GetVersionExW"));
        }
        let installation_type = registry_string(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "InstallationType",
        )
        .unwrap_or_else(|_| "unknown".into());
        let caption = registry_string(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        )
        .unwrap_or_else(|_| "Windows".into());
        let architecture = std::env::consts::ARCH.to_owned();
        Ok(OsFacts {
            caption,
            build: info.dwBuildNumber,
            architecture,
            installation_type,
        })
    }
}

fn registry_string(key: &str, value: &str) -> Result<String, SysError> {
    let key_w = wide(key);
    let value_w = wide(value);
    unsafe {
        let mut opened = std::ptr::null_mut();
        let code = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut opened,
        );
        if code != 0 {
            return Err(SysError::os("RegOpenKeyExW", code));
        }
        let mut size = 0u32;
        let probe = windows_sys::Win32::System::Registry::RegGetValueW(
            opened,
            ptr::null(),
            value_w.as_ptr(),
            0x00000002, // RRF_RT_REG_SZ
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        );
        if probe != 0 {
            RegCloseKey(opened);
            return Err(SysError::os("RegGetValueW", probe));
        }
        let mut buffer = vec![0u16; (size as usize / 2) + 1];
        let mut size = (buffer.len() * 2) as u32;
        let code = windows_sys::Win32::System::Registry::RegGetValueW(
            opened,
            ptr::null(),
            value_w.as_ptr(),
            0x00000002,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        );
        RegCloseKey(opened);
        if code != 0 {
            return Err(SysError::os("RegGetValueW", code));
        }
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len());
        Ok(String::from_utf16_lossy(&buffer[..end]))
    }
}

pub fn load_wireguard(path: &str) -> Result<(), SysError> {
    let path_w = wide(path);
    unsafe {
        let module = LoadLibraryExW(
            path_w.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
        if module.is_null() {
            return Err(SysError::last("LoadLibraryExW"));
        }
        let api = Api {
            create: proc(module, b"WireGuardCreateAdapter\0")?,
            open: proc(module, b"WireGuardOpenAdapter\0")?,
            close: proc(module, b"WireGuardCloseAdapter\0")?,
            luid: proc(module, b"WireGuardGetAdapterLUID\0")?,
            set_config: proc(module, b"WireGuardSetConfiguration\0")?,
            get_config: proc(module, b"WireGuardGetConfiguration\0")?,
            set_state: proc(module, b"WireGuardSetAdapterState\0")?,
            get_state: proc(module, b"WireGuardGetAdapterState\0")?,
        };
        API.set(api)
            .map_err(|_| SysError::invalid("wireguard.dll already loaded"))?;
        Ok(())
    }
}

struct Api {
    create: CreateAdapter,
    open: OpenAdapter,
    close: CloseAdapter,
    luid: GetLuid,
    set_config: SetConfig,
    get_config: GetConfig,
    set_state: SetState,
    get_state: GetState,
}

type CreateAdapter = unsafe extern "system" fn(*const u16, *const u16, *const u8) -> AdapterHandle;
type OpenAdapter = unsafe extern "system" fn(*const u16) -> AdapterHandle;
type CloseAdapter = unsafe extern "system" fn(AdapterHandle);
type GetLuid = unsafe extern "system" fn(AdapterHandle, *mut u64);
type SetConfig = unsafe extern "system" fn(AdapterHandle, *const u8, u32) -> i32;
type GetConfig = unsafe extern "system" fn(AdapterHandle, *mut u8, *mut u32) -> i32;
type SetState = unsafe extern "system" fn(AdapterHandle, u32) -> i32;
type GetState = unsafe extern "system" fn(AdapterHandle, *mut u32) -> i32;

// Process-wide. The DLL is intentionally never unloaded.
static API: std::sync::OnceLock<Api> = std::sync::OnceLock::new();

unsafe fn proc<T>(
    module: windows_sys::Win32::Foundation::HMODULE,
    name: &[u8],
) -> Result<T, SysError> {
    let address = GetProcAddress(module, name.as_ptr());
    if address.is_none() {
        return Err(SysError::invalid("GetProcAddress"));
    }
    Ok(std::mem::transmute_copy(&address))
}

fn api() -> Result<&'static Api, SysError> {
    API.get()
        .ok_or_else(|| SysError::invalid("wireguard.dll is not loaded"))
}

pub fn create_adapter(name: &str, guid: &[u8; 16]) -> Result<(AdapterHandle, u64), SysError> {
    let api = api()?;
    let name_w = wide(name);
    let tunnel = wide("WireGuard");
    unsafe {
        let handle = (api.create)(name_w.as_ptr(), tunnel.as_ptr(), guid.as_ptr());
        if handle.is_null() {
            return Err(SysError::last("WireGuardCreateAdapter"));
        }
        let mut luid = 0u64;
        (api.luid)(handle, &mut luid);
        Ok((handle, luid))
    }
}

pub fn open_adapter(name: &str) -> Result<(AdapterHandle, u64, [u8; 16]), SysError> {
    let api = api()?;
    let name_w = wide(name);
    unsafe {
        let handle = (api.open)(name_w.as_ptr());
        if handle.is_null() {
            return Err(SysError::last("WireGuardOpenAdapter"));
        }
        let mut luid = 0u64;
        (api.luid)(handle, &mut luid);
        let guid = interface_guid(luid).unwrap_or([0u8; 16]);
        Ok((handle, luid, guid))
    }
}

pub fn close_adapter(handle: AdapterHandle) {
    if let Ok(api) = api() {
        unsafe { (api.close)(handle) }
    }
}

pub fn set_adapter_state(handle: AdapterHandle, up: bool) -> Result<(), SysError> {
    let api = api()?;
    unsafe {
        let ok = (api.set_state)(handle, u32::from(up));
        if ok == 0 {
            return Err(SysError::last("WireGuardSetAdapterState"));
        }
        Ok(())
    }
}

pub fn get_adapter_state(handle: AdapterHandle) -> Result<bool, SysError> {
    let api = api()?;
    unsafe {
        let mut state = 0u32;
        let ok = (api.get_state)(handle, &mut state);
        if ok == 0 {
            return Err(SysError::last("WireGuardGetAdapterState"));
        }
        Ok(state == 1)
    }
}

fn interface_guid(luid: u64) -> Result<[u8; 16], SysError> {
    unsafe {
        let mut guid = [0u8; 16];
        let code = windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid(
            &luid as *const u64 as *const _,
            guid.as_mut_ptr().cast(),
        );
        if code != 0 {
            return Err(SysError::os("ConvertInterfaceLuidToGuid", code));
        }
        Ok(guid)
    }
}

pub fn set_config(handle: AdapterHandle, config: &DeviceConfig) -> Result<(), SysError> {
    let api = api()?;
    let bytes = encode_config(config);
    unsafe {
        let ok = (api.set_config)(handle, bytes.as_ptr(), bytes.len() as u32);
        if ok == 0 {
            return Err(SysError::last("WireGuardSetConfiguration"));
        }
        Ok(())
    }
}

pub fn get_config(handle: AdapterHandle) -> Result<DeviceConfig, SysError> {
    let api = api()?;
    unsafe {
        let mut size = 4096u32;
        let mut buffer = vec![0u8; size as usize];
        let ok = (api.get_config)(handle, buffer.as_mut_ptr(), &mut size);
        if ok == 0 {
            let code = GetLastError();
            if code == ERROR_MORE_DATA {
                buffer.resize(size as usize, 0);
                let ok = (api.get_config)(handle, buffer.as_mut_ptr(), &mut size);
                if ok == 0 {
                    return Err(SysError::last("WireGuardGetConfiguration"));
                }
            } else {
                return Err(SysError::os("WireGuardGetConfiguration", code));
            }
        }
        buffer.truncate(size as usize);
        decode_config(&buffer)
    }
}

fn encode_config(config: &DeviceConfig) -> Vec<u8> {
    let mut bytes = vec![0u8; 80];
    let mut flags = 0u32;
    if let Some(key) = config.private_key {
        flags |= 1 << 1;
        // Flags (4) + ListenPort (2); the key arrays are not aligned past that.
        bytes[6..38].copy_from_slice(&key);
    }
    if let Some(key) = config.public_key {
        flags |= 1 << 0;
        bytes[38..70].copy_from_slice(&key);
    }
    if config.listen_port != 0 {
        flags |= 1 << 2;
    }
    flags |= 1 << 3; // replace peers
    bytes[0..4].copy_from_slice(&flags.to_le_bytes());
    bytes[4..6].copy_from_slice(&config.listen_port.to_le_bytes());
    bytes[72..76].copy_from_slice(&(config.peers.len() as u32).to_le_bytes());
    for peer in &config.peers {
        let start = bytes.len();
        bytes.resize(start + 136, 0);
        let slot = &mut bytes[start..];
        let mut peer_flags = 1u32; // public key
        slot[8..40].copy_from_slice(&peer.public_key);
        if let Some(key) = peer.preshared_key {
            peer_flags |= 1 << 1;
            slot[40..72].copy_from_slice(&key);
        }
        if peer.persistent_keepalive != 0 {
            peer_flags |= 1 << 2;
        }
        slot[72..74].copy_from_slice(&peer.persistent_keepalive.to_le_bytes());
        if let Some(endpoint) = peer.endpoint {
            peer_flags |= 1 << 3;
            write_endpoint(&mut slot[76..104], endpoint);
        }
        peer_flags |= 1 << 5; // replace allowed IPs
        slot[0..4].copy_from_slice(&peer_flags.to_le_bytes());
        slot[128..132].copy_from_slice(&(peer.allowed_ips.len() as u32).to_le_bytes());
        for (addr, cidr) in &peer.allowed_ips {
            let at = bytes.len();
            bytes.resize(at + 24, 0);
            write_allowed(&mut bytes[at..], *addr, *cidr);
        }
    }
    bytes
}

fn write_endpoint(slot: &mut [u8], endpoint: SocketAddr) {
    match endpoint {
        SocketAddr::V4(addr) => {
            slot[0..2].copy_from_slice(&2u16.to_le_bytes());
            slot[2..4].copy_from_slice(&addr.port().to_be_bytes());
            slot[4..8].copy_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            slot[0..2].copy_from_slice(&23u16.to_le_bytes());
            slot[2..4].copy_from_slice(&addr.port().to_be_bytes());
            slot[8..24].copy_from_slice(&addr.ip().octets());
        }
    }
}

fn write_allowed(slot: &mut [u8], addr: IpAddr, cidr: u8) {
    match addr {
        IpAddr::V4(addr) => {
            slot[0..4].copy_from_slice(&addr.octets());
            slot[16..18].copy_from_slice(&2u16.to_le_bytes());
        }
        IpAddr::V6(addr) => {
            slot[0..16].copy_from_slice(&addr.octets());
            slot[16..18].copy_from_slice(&23u16.to_le_bytes());
        }
    }
    slot[18] = cidr;
}

fn decode_config(bytes: &[u8]) -> Result<DeviceConfig, SysError> {
    if bytes.len() < 80 {
        return Err(SysError::invalid("short wireguard configuration"));
    }
    let flags = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let listen_port = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    let public_key = ((flags & 1) != 0).then(|| {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[38..70]);
        key
    });
    let peers_count = u32::from_le_bytes(bytes[72..76].try_into().unwrap()) as usize;
    let mut cursor = 80;
    let mut peers = Vec::with_capacity(peers_count);
    for _ in 0..peers_count {
        if bytes.len() < cursor + 136 {
            return Err(SysError::invalid("short wireguard peer"));
        }
        let slot = &bytes[cursor..cursor + 136];
        let peer_flags = u32::from_le_bytes(slot[0..4].try_into().unwrap());
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&slot[8..40]);
        let preshared = if peer_flags & (1 << 1) != 0 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&slot[40..72]);
            (key != [0u8; 32]).then_some(key)
        } else {
            None
        };
        let keepalive = u16::from_le_bytes(slot[72..74].try_into().unwrap());
        let endpoint = (peer_flags & (1 << 3) != 0)
            .then(|| read_endpoint(&slot[76..104]))
            .flatten();
        let tx = u64::from_le_bytes(slot[104..112].try_into().unwrap());
        let rx = u64::from_le_bytes(slot[112..120].try_into().unwrap());
        let handshake = u64::from_le_bytes(slot[120..128].try_into().unwrap());
        let allowed_count = u32::from_le_bytes(slot[128..132].try_into().unwrap()) as usize;
        cursor += 136;
        let mut allowed_ips = Vec::with_capacity(allowed_count);
        for _ in 0..allowed_count {
            if bytes.len() < cursor + 24 {
                return Err(SysError::invalid("short allowed ip"));
            }
            allowed_ips.push(read_allowed(&bytes[cursor..cursor + 24]));
            cursor += 24;
        }
        peers.push(PeerConfig {
            public_key,
            preshared_key: preshared,
            persistent_keepalive: keepalive,
            endpoint,
            allowed_ips,
            tx_bytes: tx,
            rx_bytes: rx,
            last_handshake: handshake,
        });
    }
    Ok(DeviceConfig {
        private_key: None,
        public_key,
        listen_port,
        peers,
    })
}

fn read_endpoint(slot: &[u8]) -> Option<SocketAddr> {
    let family = u16::from_le_bytes(slot[0..2].try_into().ok()?);
    let port = u16::from_be_bytes(slot[2..4].try_into().ok()?);
    match family {
        2 => {
            let octets: [u8; 4] = slot[4..8].try_into().ok()?;
            Some(SocketAddr::from((octets, port)))
        }
        23 => {
            let octets: [u8; 16] = slot[8..24].try_into().ok()?;
            Some(SocketAddr::from((octets, port)))
        }
        _ => None,
    }
}

fn read_allowed(slot: &[u8]) -> (IpAddr, u8) {
    let family = u16::from_le_bytes(slot[16..18].try_into().unwrap_or([0, 0]));
    let cidr = slot[18];
    let addr = if family == 23 {
        let octets: [u8; 16] = slot[0..16].try_into().unwrap_or([0; 16]);
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        let octets: [u8; 4] = slot[0..4].try_into().unwrap_or([0; 4]);
        IpAddr::V4(Ipv4Addr::from(octets))
    };
    (addr, cidr)
}

pub fn addresses_on(luid: u64) -> Result<Vec<HostAddress>, SysError> {
    unsafe {
        let mut table = ptr::null_mut();
        let code = GetUnicastIpAddressTable(0, &mut table);
        if code != 0 {
            return Err(SysError::os("GetUnicastIpAddressTable", code));
        }
        let mut found = Vec::new();
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        for row in rows {
            if std::mem::transmute_copy::<_, u64>(&row.InterfaceLuid) != luid {
                continue;
            }
            if let Some(addr) = read_sockaddr(&row.Address) {
                found.push(HostAddress {
                    addr,
                    prefix_len: row.OnLinkPrefixLength,
                });
            }
        }
        FreeMibTable(table.cast());
        Ok(found)
    }
}

pub fn add_address(luid: u64, address: &HostAddress) -> Result<(), SysError> {
    unsafe {
        let mut row = std::mem::zeroed::<MIB_UNICASTIPADDRESS_ROW>();
        InitializeUnicastIpAddressEntry(&mut row);
        write_luid(&mut row.InterfaceLuid, luid);
        write_sockaddr(&mut row.Address, address.addr);
        row.OnLinkPrefixLength = address.prefix_len;
        let code = CreateUnicastIpAddressEntry(&row);
        if code == ERROR_OBJECT_ALREADY_EXISTS {
            return Ok(());
        }
        if code != 0 {
            return Err(SysError::os("CreateUnicastIpAddressEntry", code));
        }
        Ok(())
    }
}

pub fn delete_address(luid: u64, address: &HostAddress) -> Result<(), SysError> {
    unsafe {
        let mut row = std::mem::zeroed::<MIB_UNICASTIPADDRESS_ROW>();
        InitializeUnicastIpAddressEntry(&mut row);
        write_luid(&mut row.InterfaceLuid, luid);
        write_sockaddr(&mut row.Address, address.addr);
        row.OnLinkPrefixLength = address.prefix_len;
        let code = DeleteUnicastIpAddressEntry(&row);
        if code == ERROR_NOT_FOUND {
            return Ok(());
        }
        if code != 0 {
            return Err(SysError::os("DeleteUnicastIpAddressEntry", code));
        }
        Ok(())
    }
}

pub fn routes_on(luid: u64) -> Result<Vec<HostRoute>, SysError> {
    unsafe {
        let mut table = ptr::null_mut();
        let code = GetIpForwardTable2(0, &mut table);
        if code != 0 {
            return Err(SysError::os("GetIpForwardTable2", code));
        }
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut found = Vec::new();
        for row in rows {
            let row_luid = std::mem::transmute_copy::<_, u64>(&row.InterfaceLuid);
            if row_luid != luid {
                continue;
            }
            let Some(destination) = read_sockaddr(&row.DestinationPrefix.Prefix) else {
                continue;
            };
            found.push(HostRoute {
                destination,
                prefix_len: row.DestinationPrefix.PrefixLength,
                gateway: read_sockaddr(&row.NextHop),
                luid,
                metric: row.Metric,
            });
        }
        FreeMibTable(table.cast());
        Ok(found)
    }
}

pub fn add_route(route: &HostRoute) -> Result<(), SysError> {
    mutate_route(route, true)
}

pub fn delete_route(route: &HostRoute) -> Result<(), SysError> {
    mutate_route(route, false)
}

fn mutate_route(route: &HostRoute, create: bool) -> Result<(), SysError> {
    unsafe {
        let mut row = std::mem::zeroed::<MIB_IPFORWARD_ROW2>();
        InitializeIpForwardEntry(&mut row);
        write_luid(&mut row.InterfaceLuid, route.luid);
        write_sockaddr(&mut row.DestinationPrefix.Prefix, route.destination);
        row.DestinationPrefix.PrefixLength = route.prefix_len;
        if let Some(gateway) = route.gateway {
            write_sockaddr(&mut row.NextHop, gateway);
        }
        row.Metric = route.metric;
        let code = if create {
            CreateIpForwardEntry2(&row)
        } else {
            DeleteIpForwardEntry2(&row)
        };
        if code == ERROR_OBJECT_ALREADY_EXISTS || code == ERROR_NOT_FOUND {
            return Ok(());
        }
        if code != 0 {
            return Err(SysError::os(
                if create {
                    "CreateIpForwardEntry2"
                } else {
                    "DeleteIpForwardEntry2"
                },
                code,
            ));
        }
        Ok(())
    }
}

pub fn default_route_luids() -> Result<Vec<u64>, SysError> {
    unsafe {
        let mut table = ptr::null_mut();
        let code = GetIpForwardTable2(AF_INET, &mut table);
        if code != 0 {
            return Err(SysError::os("GetIpForwardTable2", code));
        }
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut found = Vec::new();
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            let Some(destination) = read_sockaddr(&row.DestinationPrefix.Prefix) else {
                continue;
            };
            if destination != IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
                continue;
            }
            found.push(std::mem::transmute_copy::<_, u64>(&row.InterfaceLuid));
        }
        FreeMibTable(table.cast());
        Ok(found)
    }
}

fn write_luid(luid: &mut windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH, value: u64) {
    unsafe {
        *luid = std::mem::transmute::<u64, windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH>(
            value,
        );
    }
}

fn write_sockaddr(slot: &mut SOCKADDR_INET, addr: IpAddr) {
    match addr {
        IpAddr::V4(addr) => {
            slot.Ipv4.sin_family = AF_INET;
            slot.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
        }
        IpAddr::V6(addr) => {
            slot.Ipv6.sin6_family = AF_INET6;
            slot.Ipv6.sin6_addr.u.Byte = addr.octets();
        }
    }
}

fn read_sockaddr(slot: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        match slot.si_family {
            family if family == AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                slot.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            family if family == AF_INET6 => {
                Some(IpAddr::V6(Ipv6Addr::from(slot.Ipv6.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

const TCPIP_PARAMETERS: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

pub fn ipv4_forwarding_enabled() -> Result<bool, SysError> {
    let key_w = wide(TCPIP_PARAMETERS);
    let value_w = wide("IPEnableRouter");
    unsafe {
        let mut opened = ptr::null_mut();
        let code = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut opened,
        );
        if code != 0 {
            return Err(SysError::os("RegOpenKeyExW", code));
        }
        let mut data = 0u32;
        let mut size = 4u32;
        let code = RegGetValueW(
            opened,
            ptr::null(),
            value_w.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            &mut data as *mut u32 as *mut _,
            &mut size,
        );
        RegCloseKey(opened);
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(false);
        }
        if code != 0 {
            return Err(SysError::os("RegGetValueW", code));
        }
        Ok(data != 0)
    }
}

pub fn set_ipv4_forwarding(enabled: bool) -> Result<(), SysError> {
    let key_w = wide(TCPIP_PARAMETERS);
    let value_w = wide("IPEnableRouter");
    unsafe {
        let mut opened = ptr::null_mut();
        let code = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut opened,
        );
        if code != 0 {
            return Err(SysError::os("RegOpenKeyExW", code));
        }
        let data = u32::from(enabled);
        let code = RegSetKeyValueW(
            opened,
            ptr::null(),
            value_w.as_ptr(),
            REG_DWORD,
            &data as *const u32 as *const _,
            4,
        );
        RegCloseKey(opened);
        if code != 0 {
            return Err(SysError::os("RegSetKeyValueW", code));
        }
        Ok(())
    }
}

pub fn ipv6_forwarding_enabled() -> Result<Option<bool>, SysError> {
    // Gateway apply does not change IPv6 forwarding. Observation is best-effort
    // and `None` means this call did not prove a value.
    Ok(None)
}

pub fn list_nats() -> Result<Vec<NatObject>, SysError> {
    nat::list()
}

pub fn create_nat(name: &str, prefix: &str) -> Result<(), SysError> {
    nat::create(name, prefix)
}

pub fn delete_nat(name: &str) -> Result<(), SysError> {
    nat::delete(name)
}

pub fn install_filter(name: &str, listen_port: u16) -> Result<(), SysError> {
    nat::install_filter(name, listen_port)
}

pub fn delete_filter(name: &str) -> Result<(), SysError> {
    nat::delete_filter(name)
}

pub fn install_service(spec: &ServiceSpec) -> Result<(), SysError> {
    let name = wide(spec.name);
    let display = wide(spec.display);
    let command = wide(&spec.command);
    let account = spec
        .account
        .as_ref()
        .map(|(name, password)| (wide(&format!(r".\{name}")), wide(password)));
    unsafe {
        let manager = OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        );
        if manager.is_null() {
            return Err(SysError::last("OpenSCManagerW"));
        }
        let (account_ptr, password_ptr) = match &account {
            Some((account, password)) => (account.as_ptr(), password.as_ptr()),
            None => (ptr::null(), ptr::null()),
        };
        let service = CreateServiceW(
            manager,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            account_ptr,
            password_ptr,
        );
        if service.is_null() {
            let code = GetLastError();
            CloseServiceHandle(manager);
            return Err(SysError::os("CreateServiceW", code));
        }
        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 1_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 1_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 1_000,
            },
        ];
        let failure = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86_400,
            lpRebootMsg: ptr::null_mut(),
            lpCommand: ptr::null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        let configured = ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &failure as *const _ as *const _,
        );
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        if configured == FALSE {
            return Err(SysError::last("ChangeServiceConfig2W"));
        }
        Ok(())
    }
}

pub fn service_exists(name: &str) -> Result<bool, SysError> {
    with_service(name, |_| Ok(()))
        .map(|()| true)
        .or_else(|error| {
            if error.code == Some(ERROR_FILE_NOT_FOUND) || error.code == Some(1060) {
                Ok(false)
            } else {
                Err(error)
            }
        })
}

pub fn delete_service(name: &str) -> Result<(), SysError> {
    let _ = stop_service(name);
    with_service(name, |service| unsafe {
        if DeleteService(service) == FALSE {
            let code = GetLastError();
            if code == 1060 || code == ERROR_FILE_NOT_FOUND {
                return Ok(());
            }
            return Err(SysError::os("DeleteService", code));
        }
        Ok(())
    })
}

pub fn start_service(name: &str) -> Result<(), SysError> {
    with_service(name, |service| unsafe {
        if StartServiceW(service, 0, ptr::null()) == FALSE {
            let code = GetLastError();
            if code == 1056 {
                return Ok(());
            }
            return Err(SysError::os("StartServiceW", code));
        }
        Ok(())
    })
}

pub fn stop_service(name: &str) -> Result<(), SysError> {
    with_service(name, |service| unsafe {
        let mut status = std::mem::zeroed::<SERVICE_STATUS>();
        if ControlService(service, SERVICE_CONTROL_STOP, &mut status) == FALSE {
            let code = GetLastError();
            if code == 1062 {
                return Ok(());
            }
            return Err(SysError::os("ControlService", code));
        }
        let _ = status.dwCurrentState == SERVICE_STOPPED;
        Ok(())
    })
}

fn with_service<T>(
    name: &str,
    body: impl FnOnce(SC_HANDLE) -> Result<T, SysError>,
) -> Result<T, SysError> {
    let name_w = wide(name);
    unsafe {
        let manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err(SysError::last("OpenSCManagerW"));
        }
        let service = OpenServiceW(manager, name_w.as_ptr(), SERVICE_ALL_ACCESS);
        if service.is_null() {
            let code = GetLastError();
            CloseServiceHandle(manager);
            return Err(SysError::os("OpenServiceW", code));
        }
        let result = body(service);
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        result
    }
}

pub fn create_local_user(name: &str, password: &str) -> Result<(), SysError> {
    let mut name_w = wide(name);
    let mut password_w = wide(password);
    let comment = wide("wg-basic serve account");
    let empty = wide("");
    unsafe {
        let mut info = std::mem::zeroed::<USER_INFO_1>();
        info.usri1_name = name_w.as_mut_ptr();
        info.usri1_password = password_w.as_mut_ptr();
        info.usri1_priv = USER_PRIV_USER;
        info.usri1_comment = comment.as_ptr() as *mut _;
        info.usri1_home_dir = empty.as_ptr() as *mut _;
        info.usri1_script_path = empty.as_ptr() as *mut _;
        info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
        let mut parm = 0u32;
        let code = NetUserAdd(ptr::null(), 1, &info as *const _ as *const u8, &mut parm);
        if code == NERR_USER_EXISTS {
            return Err(SysError::os("NetUserAdd", code));
        }
        if code != 0 {
            return Err(SysError::os("NetUserAdd", code));
        }
        Ok(())
    }
}

pub fn delete_local_user(name: &str) -> Result<(), SysError> {
    let name_w = wide(name);
    unsafe {
        let code = NetUserDel(ptr::null(), name_w.as_ptr());
        if code == NERR_USER_NOT_FOUND {
            return Ok(());
        }
        if code != 0 {
            return Err(SysError::os("NetUserDel", code));
        }
        Ok(())
    }
}

pub fn account_in_administrators(account: &str) -> Result<bool, SysError> {
    let name_w = wide(account);
    unsafe {
        let mut buffer = ptr::null_mut();
        let mut entries = 0u32;
        let mut total = 0u32;
        let code = NetUserGetLocalGroups(
            ptr::null(),
            name_w.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut buffer,
            65_536,
            &mut entries,
            &mut total,
        );
        if code != 0 {
            return Err(SysError::os("NetUserGetLocalGroups", code));
        }
        let groups =
            std::slice::from_raw_parts(buffer as *const LOCALGROUP_USERS_INFO_0, entries as usize);
        let mut found = false;
        for group in groups {
            let mut len = 0usize;
            while *group.lgrui0_name.add(len) != 0 {
                len += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(group.lgrui0_name, len));
            if text.eq_ignore_ascii_case("Administrators") {
                found = true;
            }
        }
        NetApiBufferFree(buffer.cast());
        Ok(found)
    }
}

#[allow(non_snake_case, dead_code)]
mod nat {
    use super::{NatObject, SysError};
    use serde::{Deserialize, Serialize};
    use wmi::{COMLibrary, WMIConnection};

    pub fn list() -> Result<Vec<NatObject>, SysError> {
        let connection = connect()?;
        let rows: Vec<NatRow> = connection
            .raw_query("SELECT Name, InternalIPInterfaceAddressPrefix FROM MSFT_NetNat")
            .map_err(|_| SysError::invalid("MSFT_NetNat query"))?;
        Ok(rows
            .into_iter()
            .map(|row| NatObject {
                name: row.name,
                internal_prefix: row.prefix,
            })
            .collect())
    }

    pub fn create(name: &str, prefix: &str) -> Result<(), SysError> {
        let connection = connect()?;
        let _out: MethodOutput = connection
            .exec_class_method::<MSFT_NetNat, _, _>(
                "Create",
                NatCreate {
                    Name: name.to_owned(),
                    InternalIPInterfaceAddressPrefix: prefix.to_owned(),
                },
            )
            .map_err(|_| SysError::invalid("MSFT_NetNat.Create"))?;
        Ok(())
    }

    pub fn delete(name: &str) -> Result<(), SysError> {
        let connection = connect()?;
        let path = format!("MSFT_NetNat.Name=\"{name}\"");
        let _out: MethodOutput = connection
            .exec_instance_method::<MSFT_NetNat, _, _>("Delete_", &path, ())
            .map_err(|_| SysError::invalid("MSFT_NetNat delete"))?;
        Ok(())
    }

    pub fn install_filter(name: &str, listen_port: u16) -> Result<(), SysError> {
        let connection = connect()?;
        let _out: MethodOutput = connection
            .exec_class_method::<MSFT_NetFirewallRule, _, _>(
                "Create",
                FilterCreate {
                    DisplayName: name.to_owned(),
                    Direction: "Inbound".into(),
                    Action: "Allow".into(),
                    Protocol: "UDP".into(),
                    LocalPort: listen_port.to_string(),
                },
            )
            .map_err(|_| SysError::invalid("MSFT_NetFirewallRule.Create"))?;
        Ok(())
    }

    pub fn delete_filter(name: &str) -> Result<(), SysError> {
        let connection = connect()?;
        let path = format!("MSFT_NetFirewallRule.DisplayName=\"{name}\"");
        let _out: MethodOutput = connection
            .exec_instance_method::<MSFT_NetFirewallRule, _, _>("Delete_", &path, ())
            .map_err(|_| SysError::invalid("MSFT_NetFirewallRule delete"))?;
        Ok(())
    }

    fn connect() -> Result<WMIConnection, SysError> {
        let com = COMLibrary::new().map_err(|_| SysError::invalid("COM"))?;
        WMIConnection::with_namespace_path("root\\StandardCimv2", com)
            .map_err(|_| SysError::invalid("root\\StandardCimv2"))
    }

    #[derive(Deserialize)]
    struct NatRow {
        #[serde(rename = "Name")]
        name: String,
        #[serde(rename = "InternalIPInterfaceAddressPrefix")]
        prefix: String,
    }

    #[derive(Deserialize)]
    #[allow(non_camel_case_types)]
    struct MSFT_NetNat {
        #[serde(default)]
        Name: String,
    }

    #[derive(Deserialize)]
    #[allow(non_camel_case_types)]
    struct MSFT_NetFirewallRule {
        #[serde(default)]
        DisplayName: String,
    }

    #[derive(Serialize)]
    struct NatCreate {
        Name: String,
        InternalIPInterfaceAddressPrefix: String,
    }

    #[derive(Serialize)]
    struct FilterCreate {
        DisplayName: String,
        Direction: String,
        Action: String,
        Protocol: String,
        LocalPort: String,
    }

    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct MethodOutput {
        #[serde(default)]
        ReturnValue: i32,
    }
}
