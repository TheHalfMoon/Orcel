// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Unit tests for `linux.rs`. The seccomp-program tests are the donor's
//! (blob 9c1e66bb95351fe87272b53168389b600430ae97); the Landlock refusal tests
//! are Orcel's.

use super::*;

fn evaluate_filter(filter: &[SockFilter], syscall: libc::c_long, arg0: u32) -> u32 {
    let mut accumulator = 0_u32;
    let mut pc = 0_usize;
    loop {
        let instruction = filter[pc];
        match instruction.code {
            code if code == BPF_LD | BPF_W | BPF_ABS => {
                accumulator = match instruction.k {
                    SECCOMP_DATA_ARCH => AUDIT_ARCH,
                    SECCOMP_DATA_NR => syscall as u32,
                    SECCOMP_DATA_ARG0_LOW => arg0,
                    offset => panic!("unexpected seccomp_data offset {offset}"),
                };
                pc += 1;
            }
            code if code == BPF_JMP | BPF_JEQ | BPF_K => {
                pc += 1 + usize::from(if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                });
            }
            #[cfg(target_arch = "x86_64")]
            code if code == BPF_JMP | BPF_JGE | BPF_K => {
                pc += 1 + usize::from(if accumulator >= instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                });
            }
            code if code == BPF_ALU | BPF_AND | BPF_K => {
                accumulator &= instruction.k;
                pc += 1;
            }
            code if code == BPF_RET | BPF_K => return instruction.k,
            code => panic!("unexpected BPF instruction {code:#x}"),
        }
    }
}

#[test]
fn the_filter_denies_every_socket_and_io_uring_entry_point() {
    let denied = denied_syscalls();
    for required in [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_open_by_handle_at,
    ] {
        assert!(
            denied.contains(&required),
            "syscall {required} is not denied by the contained process filter"
        );
    }
}

#[test]
fn the_filter_fits_the_kernel_program_ceiling_with_single_byte_jumps() {
    let filter = assemble_seccomp_filter(SECCOMP_RET_KILL_PROCESS);
    assert!(
        filter.instructions.len() < 4096,
        "filter is {} long",
        filter.instructions.len()
    );
    assert!(
        filter
            .instructions
            .iter()
            .all(|instruction| instruction.jt <= 4 && instruction.jf <= 4),
        "a jump offset outside this filter's fixed layout would land on the wrong instruction"
    );
}

#[test]
fn signalling_requires_the_childs_exact_thread_group() {
    let mut filter = assemble_seccomp_filter(SECCOMP_RET_KILL_PROCESS);
    assert!(denied_syscalls().contains(&libc::SYS_kill));
    assert!(denied_syscalls().contains(&libc::SYS_tkill));
    assert!(denied_syscalls().contains(&libc::SYS_rt_sigqueueinfo));
    assert!(denied_syscalls().contains(&libc::SYS_rt_tgsigqueueinfo));
    assert!(!denied_syscalls().contains(&libc::SYS_tgkill));
    let check = filter.instructions[filter.child_tgid_instruction];
    assert_eq!(check.code, BPF_JMP | BPF_JEQ | BPF_K);
    assert_eq!((check.jt, check.jf, check.k), (1, 0, 0));

    filter.instructions[filter.child_tgid_instruction].k = 4242;
    let denied = SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xffff);
    assert_eq!(
        evaluate_filter(&filter.instructions, libc::SYS_tgkill, 4242),
        SECCOMP_RET_ALLOW
    );
    assert_eq!(
        evaluate_filter(&filter.instructions, libc::SYS_tgkill, 4243),
        denied
    );
    assert_eq!(
        evaluate_filter(&filter.instructions, libc::SYS_tkill, 4242),
        denied
    );
    assert_eq!(
        evaluate_filter(&filter.instructions, libc::SYS_kill, 4242),
        denied
    );
    assert_eq!(
        evaluate_filter(&filter.instructions, libc::SYS_rt_sigqueueinfo, 4242),
        denied
    );
    assert_eq!(
        evaluate_filter(&filter.instructions, libc::SYS_rt_tgsigqueueinfo, 4242),
        denied
    );
}

#[test]
fn writable_roots_never_grant_execute() {
    assert_eq!(LANDLOCK_WRITABLE_TREE & LANDLOCK_ACCESS_FS_EXECUTE, 0);
    assert_eq!(LANDLOCK_READ_TREE & LANDLOCK_ACCESS_FS_EXECUTE, 0);
    assert_ne!(LANDLOCK_WRITABLE_TREE & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
    assert_ne!(LANDLOCK_WRITABLE_TREE & LANDLOCK_ACCESS_FS_READ_FILE, 0);
    assert_ne!(LANDLOCK_EXECUTABLE_FILE & LANDLOCK_ACCESS_FS_EXECUTE, 0);
    assert_ne!(LANDLOCK_SYSTEM_READ_TREE & LANDLOCK_ACCESS_FS_EXECUTE, 0);
}

#[test]
fn the_device_allowlist_never_grants_a_directory_or_raw_memory() {
    for node in DEVICE_NODES {
        assert!(
            !matches!(*node, "/dev" | "/dev/mem" | "/dev/kmem" | "/dev/shm"),
            "{node} must not be in the child device allowlist"
        );
    }
}

fn empty_boundary() -> FilesystemBoundary {
    FilesystemBoundary {
        readable: Vec::new(),
        writable: Vec::new(),
        executables: Vec::new(),
    }
}

#[test]
fn a_kernel_without_landlock_is_a_refusal_not_a_weaker_launch() {
    let refused = build_landlock_ruleset(None, &empty_boundary())
        .err()
        .map(|refusal| refusal.code);
    assert_eq!(
        refused,
        Some(crate::containment::ErrorCode::UnsupportedPlatform)
    );
}

#[test]
fn a_landlock_abi_that_cannot_restrict_truncation_is_refused() {
    for abi in [1, 2] {
        let refused = build_landlock_ruleset(Some(abi), &empty_boundary())
            .err()
            .map(|refusal| refusal.code);
        assert_eq!(
            refused,
            Some(crate::containment::ErrorCode::UnsupportedPlatform),
            "Landlock ABI {abi} was accepted"
        );
    }
}
