#![cfg(all(unix, feature = "native_composed_transport_test_helper"))]

use nomad_connector::supervise_test_proxy_and_adopter;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

fn binaries() -> (&'static Path, &'static Path) {
    (
        Path::new(env!("CARGO_BIN_EXE_native-proxy-peer")),
        Path::new(env!("CARGO_BIN_EXE_actual-launch-adopter")),
    )
}

#[test]
fn real_proxy_and_adopter_complete_one_shared_binding() {
    let (proxy, adopter) = binaries();
    supervise_test_proxy_and_adopter(proxy, adopter).unwrap();
}

#[test]
fn wrong_proxy_or_adopter_blocks_content_free() {
    let (proxy, adopter) = binaries();
    assert!(supervise_test_proxy_and_adopter(adopter, adopter).is_err());
    assert!(supervise_test_proxy_and_adopter(proxy, proxy).is_err());
}

#[test]
fn explicitly_inheritable_unrelated_writer_is_not_inherited() {
    let (proxy, adopter) = binaries();
    let mut descriptors = [-1; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let flags = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
        0
    );
    let worker = thread::spawn(move || supervise_test_proxy_and_adopter(proxy, adopter));
    drop(write);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut byte = [0_u8; 1];
    loop {
        let count = unsafe { libc::read(read.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        if count == 0 {
            break;
        }
        if count < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        assert!(count >= 0);
    }
    worker.join().unwrap().unwrap();
}
