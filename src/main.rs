use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Instant;
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
use windows::Win32::UI::WindowsAndMessaging::WHEEL_DELTA;
use windows::{
    core::*,
    Win32::Graphics::Direct3D9::*,
    Win32::Graphics::Gdi::HBRUSH,
    Win32::Storage::FileSystem::*,
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::System::ProcessStatus::*,
    Win32::System::Registry::*,
    Win32::System::Threading::*,
    Win32::UI::Shell::*,
    Win32::UI::WindowsAndMessaging::CreateWindowExW,
    Win32::UI::WindowsAndMessaging::DefWindowProcW,
    Win32::UI::WindowsAndMessaging::WNDCLASSEXW,
    Win32::{Foundation::*, System::LibraryLoader::GetModuleHandleW, UI::WindowsAndMessaging::*},
};

struct IgnoredClassPattern {
    title: Option<String>,
    class: String,
    title_hash: Option<u64>,
    class_hash: u64,
}

const IGNORED_PROCESSES: &[&str] = &[
    "virtual pc.exe",
    "startmenuexperiencehost.exe",
    "searchapp.exe",
    "searchui.exe",
    "osk.exe",
    "shellexperiencehost.exe",
    "cortana.exe",
    "textinputhost.exe",
    "lockapp.exe",
    "winlogon.exe",
    "dwm.exe",
    "sihost.exe",
];

static IGNORED_CLASS_PATTERNS_COMPILED: OnceLock<(HashSet<u64>, Vec<IgnoredClassPattern>)> =
    OnceLock::new();

// format: window title|classname
const IGNORED_CLASS_PATTERNS: &[&str] = &[
    "Program Manager|Progman",
    "*|MultitaskingViewFrame",
    "Volume Control|Tray Volume",
    "Volume Control|Windows.UI.Core.CoreWindow",
    "*|TaskSwitcherWnd",
    "*|TaskSwitcherOverlayWnd",
    "*|WorkerW",
    "*|Shell_TrayWnd",
    "*|BaseBar",
    "*|#32768",
    "*|XamlExplorerHostIslandWindow",
    "*|TSSHELLWND",
];

const WHEEL_DELTA_F64: f64 = WHEEL_DELTA as f64;

const BASE_MULTIPLIER: f64 = 1.0;
const MAX_MULTIPLIER: f64 = 3.0;
const RESET_TIMEOUT_MS: u64 = 50;
const MAX_VELOCITY: u32 = WHEEL_DELTA;

const INERTIA_BASE_DECAY: f64 = 0.88;
const INERTIA_THRESHOLD: f64 = 0.05;
const INERTIA_INTERVAL_MS: u32 = 15;
const MIN_MOMENTUM_FOR_INERTIA: f64 = 0.5;
const INERTIA_ACCUMULATION_FACTOR: f64 = 1.5;
const MAX_INERTIA_MOMENTUM: f64 = 9.0;

const INERTIA_TIMER_ID: usize = 1001;
const GAMEMODE_CHECK_TIMER_ID: usize = 1002;
const GAMEMODE_CHECK_INTERVAL_MS: u32 = 1000;

static mut HOOK_HANDLE: HHOOK = HHOOK(0);

static mut LAST_SCROLL_TIME: Option<Instant> = None;
static mut SCROLL_MOMENTUM: f64 = 0.0;
static mut MAX_SCROLL_MOMENTUM: f64 = 0.0;
static mut LAST_DIRECTION: i32 = 0;
static mut VELOCITY_INDEX: usize = 0;

thread_local! {
    static SCROLL_VELOCITIES: Cell<[f64; 8]> = Cell::new([0.0; 8]);
}

static mut INERTIA_MOMENTUM: f64 = 0.0;
static mut INERTIA_DIRECTION: i32 = 0;
static mut INERTIA_DECAY_RATE: f64 = INERTIA_BASE_DECAY;
static mut LAST_WINDOW: HWND = HWND(0);
static mut LAST_CURSOR_POS: POINT = POINT { x: 0, y: 0 };
static mut INERTIA_PROGRESS: f64 = 0.0;

static INERTIA_ACTIVE: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(true);

static GAME_MODE_DETECTED: AtomicBool = AtomicBool::new(false);
static mut LAST_FOREGROUND_WINDOW: HWND = HWND(0);
static mut TIMER_WINDOW: HWND = HWND(0);

static mut LAST_GAME_CHECK_TIME: Option<Instant> = None;
static mut CACHED_GAME_STATE: bool = false;
static mut CACHED_WINDOW: HWND = HWND(0);
const GAME_CHECK_CACHE_DURATION_MS: u32 = GAMEMODE_CHECK_INTERVAL_MS;

static mut WINDOW_CACHE: Option<HashMap<isize, (bool, Instant)>> = None;
const CACHE_DURATION_MS: u64 = 100;

fn main() -> Result<()> {
    compile_class_patterns();

    ctrlc::set_handler(move || {
        RUNNING.store(false, Ordering::SeqCst);
        unsafe {
            PostQuitMessage(0);
        }
    })
    .expect("Error setting Ctrl-C handler");

    unsafe {
        create_timer_window()?;
        install_mouse_hook()?;
        start_gamemode_check_timer();
    }

    unsafe {
        let mut msg = MSG::default();
        while RUNNING.load(Ordering::SeqCst) {
            if PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                match msg.message {
                    WM_TIMER | WM_MOUSEWHEEL => DispatchMessageW(&msg),
                    WM_QUIT => break,
                    _ => LRESULT(0),
                };
            } else {
                let _ = WaitMessage();
            }
        }
    }

    unsafe {
        cleanup();
    }

    Ok(())
}

fn compile_class_patterns() {
    let mut wildcard_classes = HashSet::new();
    let mut specific_patterns = Vec::new();

    for pattern in IGNORED_CLASS_PATTERNS {
        if let Some((title_part, class_part)) = pattern.split_once('|') {
            let class_hash = hash_string(class_part);

            if title_part == "*" {
                wildcard_classes.insert(class_hash);
            } else {
                specific_patterns.push(IgnoredClassPattern {
                    title: Some(title_part.to_string()),
                    class: class_part.to_string(),
                    title_hash: Some(hash_string(title_part)),
                    class_hash,
                });
            }
        }
    }

    let _ = IGNORED_CLASS_PATTERNS_COMPILED.set((wildcard_classes, specific_patterns));
}

fn hash_string(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

unsafe fn create_timer_window() -> Result<()> {
    let module = GetModuleHandleW(None)?;

    let class_name = w!("TimerWindowClass");

    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(timer_window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: module.into(),
        hIcon: HICON::default(),
        hCursor: HCURSOR::default(),
        hbrBackground: HBRUSH::default(),
        lpszMenuName: PCWSTR::null(),
        lpszClassName: class_name,
        hIconSm: HICON::default(),
    };

    let atom = RegisterClassExW(&wc);
    if atom == 0 {
        return Err(Error::from_win32());
    }

    TIMER_WINDOW = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class_name,
        w!("Timer Window"),
        WS_OVERLAPPED,
        0,
        0,
        0,
        0,
        None,
        None,
        module,
        None,
    );

    if TIMER_WINDOW.0 == 0 {
        return Err(Error::from_win32());
    }

    Ok(())
}

unsafe extern "system" fn timer_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TIMER => {
            match wparam.0 {
                INERTIA_TIMER_ID => handle_inertia_timer(),
                GAMEMODE_CHECK_TIMER_ID => handle_gamemode_check(),
                _ => {}
            }
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn handle_gamemode_check() {
    let foreground_window = GetForegroundWindow();
    let current_time = Instant::now();
    let should_check = foreground_window != LAST_FOREGROUND_WINDOW
        || LAST_GAME_CHECK_TIME
            .map(|last| {
                current_time.duration_since(last).as_millis() > GAME_CHECK_CACHE_DURATION_MS.into()
            })
            .unwrap_or(true);

    if should_check {
        let is_game = is_game_process(foreground_window);
        let was_game_detected = GAME_MODE_DETECTED.load(Ordering::SeqCst);
        CACHED_GAME_STATE = is_game;

        if is_game != was_game_detected {
            GAME_MODE_DETECTED.store(is_game, Ordering::SeqCst);
            if is_game {
                stop_inertia_timer();
            }
        }

        LAST_FOREGROUND_WINDOW = foreground_window;
        LAST_GAME_CHECK_TIME = Some(current_time);
        CACHED_WINDOW = foreground_window;
    }
}

unsafe fn is_window_cached(hwnd: HWND) -> Option<bool> {
    let cache = WINDOW_CACHE.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    if let Some((is_ignored, cached_time)) = cache.get(&hwnd.0) {
        if now.duration_since(*cached_time).as_millis() < CACHE_DURATION_MS.into() {
            return Some(*is_ignored);
        } else {
            cache.remove(&hwnd.0);
        }
    }

    static mut CLEANUP_COUNTER: u32 = 0;
    CLEANUP_COUNTER += 1;
    if CLEANUP_COUNTER % 1000 == 0 {
        cache.retain(|_, (_, time)| {
            now.duration_since(*time).as_millis() < CACHE_DURATION_MS.into()
        });
    }

    None
}

unsafe fn cache_window_result(hwnd: HWND, is_ignored: bool) {
    let cache = WINDOW_CACHE.get_or_insert_with(HashMap::new);
    cache.insert(hwnd.0, (is_ignored, Instant::now()));
}

unsafe fn is_window_ignored(hwnd: HWND) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    if let Some(cache) = is_window_cached(hwnd) {
        return cache;
    }

    let mut process_id = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut process_id));
    if process_id != 0 {
        let process_handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)
        {
            Ok(handle) => handle,
            Err(_) => {
                cache_window_result(hwnd, false);
                return false;
            }
        };

        let mut exe_path = [0u16; 260];
        let mut size = exe_path.len() as u32;

        let process_check_result = if QueryFullProcessImageNameW(
            process_handle,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            PWSTR(exe_path.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            let path = String::from_utf16_lossy(&exe_path[..size as usize]);
            let filename = path.split('\\').last().unwrap_or("").to_lowercase();

            IGNORED_PROCESSES.contains(&filename.as_str())
        } else {
            false
        };

        let _ = CloseHandle(process_handle);
        if process_check_result {
            cache_window_result(hwnd, process_check_result);
            return process_check_result;
        }
    }

    let mut class_name = [0u16; 256];
    let len = GetClassNameW(hwnd, &mut class_name);
    if len == 0 {
        cache_window_result(hwnd, false);
        return false;
    }

    let class_str = String::from_utf16_lossy(&class_name[..len as usize]);
    let class_hash = hash_string(&class_str);

    if let Some((wildcard_classes, specific_patterns)) = IGNORED_CLASS_PATTERNS_COMPILED.get() {
        if wildcard_classes.contains(&class_hash) {
            cache_window_result(hwnd, true);
            return true;
        }

        for pattern in specific_patterns {
            if pattern.class_hash == class_hash && pattern.class == class_str {
                if let Some(title_hash) = pattern.title_hash {
                    let window_title = get_window_title(hwnd);
                    if let Some(title) = window_title {
                        if hash_string(&title) == title_hash
                            && title == *pattern.title.as_ref().unwrap()
                        {
                            cache_window_result(hwnd, true);
                            return true;
                        }
                    }
                }
            }
        }
    }

    cache_window_result(hwnd, false);
    false
}

unsafe fn get_window_title(hwnd: HWND) -> Option<String> {
    let mut title = [0u16; 256];
    let len = GetWindowTextW(hwnd, &mut title);
    if len > 0 {
        Some(String::from_utf16_lossy(&title[..len as usize]))
    } else {
        None
    }
}

#[inline]
unsafe fn is_game_process(hwnd: HWND) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    if hwnd == CACHED_WINDOW {
        return CACHED_GAME_STATE;
    }

    if let Ok(state) = SHQueryUserNotificationState() {
        return state == QUNS_RUNNING_D3D_FULL_SCREEN;
    }

    false
}

unsafe fn start_gamemode_check_timer() {
    if TIMER_WINDOW.0 != 0 {
        let _ = SetTimer(
            TIMER_WINDOW,
            GAMEMODE_CHECK_TIMER_ID,
            GAMEMODE_CHECK_INTERVAL_MS,
            None,
        );
    }
}

#[inline]
unsafe fn stop_gamemode_check_timer() {
    if TIMER_WINDOW.0 != 0 {
        let _ = KillTimer(TIMER_WINDOW, GAMEMODE_CHECK_TIMER_ID);
    }
}

unsafe fn handle_inertia_timer() {
    if !RUNNING.load(Ordering::SeqCst)
        || !INERTIA_ACTIVE.load(Ordering::SeqCst)
        || INERTIA_MOMENTUM.abs() <= INERTIA_THRESHOLD
        || GAME_MODE_DETECTED.load(Ordering::SeqCst)
    {
        stop_inertia_timer();
        return;
    }

    INERTIA_PROGRESS += 16.0 / 1000.0;
    let base_delta = WHEEL_DELTA as f64 * INERTIA_DIRECTION as f64;
    let inertia_delta = (base_delta * INERTIA_MOMENTUM) as i32;

    if LAST_WINDOW.0 != 0 && inertia_delta.abs() > 5 {
        send_inertia_scroll(inertia_delta);
    }

    INERTIA_MOMENTUM *= INERTIA_DECAY_RATE;
    if inertia_delta == 0 || INERTIA_MOMENTUM.abs() <= INERTIA_THRESHOLD {
        stop_inertia_timer();
    }
}

#[inline]
unsafe fn start_inertia_timer() {
    if TIMER_WINDOW.0 != 0 {
        let _ = SetTimer(TIMER_WINDOW, INERTIA_TIMER_ID, INERTIA_INTERVAL_MS, None);
    }
}

#[inline]
unsafe fn stop_inertia_timer() {
    INERTIA_ACTIVE.store(false, Ordering::SeqCst);
    if TIMER_WINDOW.0 != 0 {
        let _ = KillTimer(TIMER_WINDOW, INERTIA_TIMER_ID);
    }
}

unsafe fn install_mouse_hook() -> Result<()> {
    let module = GetModuleHandleW(None)?;
    HOOK_HANDLE = SetWindowsHookExW(WH_MOUSE_LL, Some(low_level_mouse_proc), module, 0)?;
    if HOOK_HANDLE.0 == 0 {
        return Err(Error::from_win32());
    }

    Ok(())
}

unsafe extern "system" fn low_level_mouse_proc(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if !RUNNING.load(Ordering::SeqCst) {
        return CallNextHookEx(HOOK_HANDLE, code, wparam, lparam);
    }

    if GAME_MODE_DETECTED.load(Ordering::SeqCst) {
        return CallNextHookEx(HOOK_HANDLE, code, wparam, lparam);
    }

    if code >= 0 {
        match wparam.0 as u32 {
            WM_MOUSEWHEEL => {
                let mouse_data = *(lparam.0 as *const MSLLHOOKSTRUCT);
                let wheel_delta = get_wheel_delta(mouse_data.mouseData);

                let _ = GetCursorPos(&raw mut LAST_CURSOR_POS);
                LAST_WINDOW = WindowFromPoint(LAST_CURSOR_POS);

                if !is_window_ignored(LAST_WINDOW) {
                    if process_scroll_input(wheel_delta) {
                        return LRESULT(1);
                    }
                }
            }
            _ => {}
        }
    }

    CallNextHookEx(HOOK_HANDLE, code, wparam, lparam)
}

#[inline]
unsafe fn get_wheel_delta(mouse_data: u32) -> i32 {
    ((mouse_data >> 16) as i16) as i32
}

unsafe fn process_scroll_input(wheel_delta: i32) -> bool {
    if GAME_MODE_DETECTED.load(Ordering::SeqCst) {
        return false;
    }

    let current_time = Instant::now();
    let current_direction = if wheel_delta > 0 { 1 } else { -1 };
    let actual_time_since_last = match LAST_SCROLL_TIME {
        Some(last_time) => current_time.duration_since(last_time).as_millis() as f64,
        None => f64::MAX,
    };

    if INERTIA_ACTIVE.load(Ordering::SeqCst) && INERTIA_DIRECTION != current_direction {
        stop_inertia_timer();
        INERTIA_PROGRESS = 0.0;
        INERTIA_MOMENTUM = 0.0;
        SCROLL_VELOCITIES.set([0.0; 8]);
        VELOCITY_INDEX = 0;
    }

    if actual_time_since_last > RESET_TIMEOUT_MS as f64 || current_direction != LAST_DIRECTION {
        SCROLL_MOMENTUM = 0.0;
        MAX_SCROLL_MOMENTUM = 0.0;
        SCROLL_VELOCITIES.set([0.0; 8]);
        VELOCITY_INDEX = 0;
    }

    let scroll_strength = (wheel_delta.abs() as f64) * (1.0 / WHEEL_DELTA_F64);
    let time_delta = actual_time_since_last.max(1.0);
    let current_velocity = scroll_strength * 1000.0 / time_delta;

    let mut velocities = SCROLL_VELOCITIES.get();
    velocities[VELOCITY_INDEX] = current_velocity;

    SCROLL_VELOCITIES.set(velocities);
    VELOCITY_INDEX = (VELOCITY_INDEX + 1) % velocities.len();

    let avg_velocity = velocities.iter().sum::<f64>() / velocities.len() as f64;
    SCROLL_MOMENTUM = smoothstep(0.0, MAX_VELOCITY.into(), avg_velocity);

    LAST_SCROLL_TIME = Some(current_time);
    LAST_DIRECTION = current_direction;

    let acceleration_multiplier = get_acceleration_multiplier();
    send_accelerated_scroll(wheel_delta, acceleration_multiplier);

    let prev_max_scroll_momentum = MAX_SCROLL_MOMENTUM;
    if SCROLL_MOMENTUM > MAX_SCROLL_MOMENTUM {
        MAX_SCROLL_MOMENTUM = SCROLL_MOMENTUM
    }

    if SCROLL_MOMENTUM >= MIN_MOMENTUM_FOR_INERTIA {
        if prev_max_scroll_momentum != MAX_SCROLL_MOMENTUM {
            INERTIA_MOMENTUM = MAX_SCROLL_MOMENTUM;
            INERTIA_DECAY_RATE = INERTIA_MOMENTUM.min(0.9)
        }
        accumulate_inertia(SCROLL_MOMENTUM, current_direction);
    }

    true
}

unsafe fn get_acceleration_multiplier() -> f64 {
    let velocities = SCROLL_VELOCITIES.get();
    let avg_velocity = velocities.iter().sum::<f64>() / velocities.len() as f64;
    let velocity_trend = if velocities.len() >= 3 {
        let recent_avg = velocities[velocities.len() - 3..].iter().sum::<f64>() / 3.0;
        let older_avg =
            velocities[..velocities.len() - 3].iter().sum::<f64>() / (velocities.len() - 3) as f64;
        (recent_avg - older_avg).max(0.0) / MAX_VELOCITY as f64
    } else {
        0.0
    };

    let velocity_factor = (avg_velocity / MAX_VELOCITY as f64).min(1.0);
    let trend_factor = velocity_trend.min(0.5);
    let total_factor = velocity_factor * 0.7 + trend_factor * 0.3;
    let multiplier = BASE_MULTIPLIER + (MAX_MULTIPLIER - BASE_MULTIPLIER) * total_factor;
    multiplier
}

#[inline]
fn smoothstep(edge0: f64, edge1: f64, x: f64) -> f64 {
    let t = ((x - edge0) / (edge1 - edge0)).min(1.0).max(0.0);
    t * t * (3.0 - 2.0 * t)
}

unsafe fn send_accelerated_scroll(original_delta: i32, multiplier: f64) {
    let mut cursor_pos = POINT::default();
    if GetCursorPos(&mut cursor_pos).is_err() {
        return;
    }

    let hwnd = WindowFromPoint(cursor_pos);
    if hwnd.0 == 0 {
        return;
    }

    let accelerated_delta = (original_delta as f64 * multiplier) as i32;
    let wheel_data = ((accelerated_delta as u16) as u32) << 16;
    let lparam_pos = ((cursor_pos.y as u32) << 16) | (cursor_pos.x as u32);
    let _ = PostMessageW(
        hwnd,
        WM_MOUSEWHEEL,
        WPARAM(wheel_data as usize),
        LPARAM(lparam_pos as isize),
    );
}

unsafe fn accumulate_inertia(momentum: f64, direction: i32) {
    if INERTIA_ACTIVE.load(Ordering::SeqCst) && INERTIA_DIRECTION == direction {
        let new_inertia = momentum * INERTIA_ACCUMULATION_FACTOR;
        INERTIA_MOMENTUM = (INERTIA_MOMENTUM + new_inertia).min(MAX_INERTIA_MOMENTUM);
    } else {
        start_inertia(direction);
    }
}

unsafe fn start_inertia(direction: i32) {
    if GAME_MODE_DETECTED.load(Ordering::SeqCst) {
        return;
    }

    stop_inertia_timer();
    INERTIA_PROGRESS = 0.0;
    INERTIA_DIRECTION = direction;
    INERTIA_ACTIVE.store(true, Ordering::SeqCst);
    start_inertia_timer();
}

unsafe fn send_inertia_scroll(delta: i32) {
    if LAST_WINDOW.0 == 0 {
        return;
    }

    let current_time = Instant::now();
    let actual_time_since_last = match LAST_SCROLL_TIME {
        Some(last_time) => current_time.duration_since(last_time).as_millis() as f64,
        None => f64::MAX,
    };
    if actual_time_since_last < INERTIA_INTERVAL_MS.into() {
        return;
    }

    let wheel_data = ((delta as u16) as u32) << 16;
    let lparam_pos = ((LAST_CURSOR_POS.y as u32) << 16) | (LAST_CURSOR_POS.x as u32);
    let _ = PostMessageW(
        LAST_WINDOW,
        WM_MOUSEWHEEL,
        WPARAM(wheel_data as usize),
        LPARAM(lparam_pos as isize),
    );
}

unsafe fn cleanup() {
    stop_inertia_timer();
    stop_gamemode_check_timer();

    if HOOK_HANDLE.0 != 0 {
        let _ = UnhookWindowsHookEx(HOOK_HANDLE);
    }

    if TIMER_WINDOW.0 != 0 {
        let _ = DestroyWindow(TIMER_WINDOW);
    }

    if let Some(cache) = WINDOW_CACHE.as_mut() {
        cache.clear();
    }
}
