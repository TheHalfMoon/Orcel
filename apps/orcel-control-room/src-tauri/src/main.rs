//! The Orcel Control Room shell (SG-000119 slice A2, development builds
//! only). It keeps the console subsystem in this slice, so its refusals and
//! its exit report are visible where it was started.

fn main() {
    std::process::exit(orcel_control_room_shell::run(
        orcel_control_room_shell::Hooks::default(),
    ));
}
