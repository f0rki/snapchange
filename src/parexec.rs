//! Helper code to abstract executing multiple testcases on multiple cores in parallel.

use anyhow::{ensure, Context, Result};

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::{RwLock, RwLockWriteGuard};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::config::Config;
use crate::fuzz_input::InputWithMetadata;
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::{CoverageBreakpoints, FuzzVm, FuzzVmExit, ResetBreakpoints};
use crate::memory::Memory;
use crate::utils::get_files;
use crate::{cmdline, fuzzvm, unblock_sigalrm, SymbolList, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

/*
use crossbeam::channel;
use crossbeam::queue::SegQueue;

// type SetupFunc = FnOnce(&ProjectState, Arc<RwLock<Memory>>, Option<&mut SymbolList>, Option<&mut SymbolList>, Option<&mut fuzzvm::ResetBreakpoints>) -> Result<()>;

struct Task<INPUT, FUNC, FUZZER>
where
    FUZZER: Fuzzer,
    FUNC: Fn(
        &ProjectState,
        &mut FUZZER,
        &mut FuzzVm<FUZZER>,
        Option<&SymbolList>,
        Option<&ResetBreakpoints>,
        &CoverageBreakpoints,
        Arc<INPUT>,
    ),
    FUNC: Send + 'static,
    INPUT: Send + 'static,
{
    input: Arc<INPUT>,
    func: Box<FUNC>,
}

pub struct ParallelVMExecutor<'a, FUZZER: Fuzzer, INPUT: Send, RESULT: Send> {
    threads: Vec<JoinHandle<Result<()>>>,
    kick_cores_thread: JoinHandle<Result<()>>,
    jobs: Arc<SegQueue<Task<INPUT>>>,
    results: Receiver<RESULT>,
}
*/

/// common setup function to gather and pre-write coverage breakpoints into clean snapshot
pub fn gather_and_write_coverage_breakpoints(
    project_state: &ProjectState,
    clean_snapshot: Arc<RwLock<Memory>>,
    _symbols: Option<&mut SymbolList>,
    _reset_breakpoints: Option<&mut fuzzvm::ResetBreakpoints>,
    coverage_breakpoints: &mut fuzzvm::CoverageBreakpoints,
) -> Result<()> {
    if let Some(cov_bbs) = project_state.coverage_basic_blocks.as_ref() {
        let mut curr_clean_snapshot = clean_snapshot.write().unwrap();
        let cr3 = Cr3(project_state.vbcpu.cr3);
        for addr in cov_bbs.keys().copied() {
            if let Ok(orig_byte) = curr_clean_snapshot.read_byte(addr, cr3) {
                curr_clean_snapshot.write_bytes(addr, cr3, &[0xcc])?;
                coverage_breakpoints.insert(addr, orig_byte);
            }
        }
    }
    Ok(())
}

///
pub fn gather_coverage_breakpoints(
    project_state: &ProjectState,
    clean_snapshot: Arc<RwLock<Memory>>,
    _symbols: Option<&mut SymbolList>,
    _reset_breakpoints: Option<&mut fuzzvm::ResetBreakpoints>,
    coverage_breakpoints: &mut fuzzvm::CoverageBreakpoints,
) -> Result<()> {
    if let Some(cov_bbs) = project_state.coverage_basic_blocks.as_ref() {
        let mut curr_clean_snapshot = clean_snapshot.read().unwrap();
        let cr3 = Cr3(project_state.vbcpu.cr3);
        for addr in cov_bbs.keys().copied() {
            if let Ok(orig_byte) = curr_clean_snapshot.read_byte(addr, cr3) {
                coverage_breakpoints.insert(addr, orig_byte);
            }
        }
    }
    Ok(())
}

/// VM Data shared to thread
pub struct SharedVMData<FUZZER: Fuzzer> {
    /// current fuzzer
    pub fuzzer: FUZZER,
    /// associated fuzzvm
    pub fuzzvm: FuzzVm<FUZZER>,
    /// global project state
    pub project_state: Arc<ProjectState>,
    /// and clean snapshot
    pub clean_snapshot: Arc<RwLock<Memory>>,
    // pub symbols: Arc<Option<SymbolList>>,
    // pub reset_breakpoints: Arc<Option<ResetBreakpoints>>,
    // pub coverage_breakpoints: CoverageBreakpoints,
}

struct PVMEInner<FUZZER: Fuzzer> {
    threads: Arc<RwLock<Vec<Option<u64>>>>,
    vmdata: Vec<Arc<RwLock<SharedVMData<FUZZER>>>>,
    kick_cores_thread: Option<JoinHandle<()>>,
}

/// wrapper to allow retrieving a FuzzVm
pub struct ParallelVMPool<FUZZER: Fuzzer> {
    inner: Arc<PVMEInner<FUZZER>>,
}

impl<FUZZER: Fuzzer> Drop for PVMEInner<FUZZER> {
    fn drop(&mut self) {
        log::debug!("cleaning up vm pool");
        crate::FINISHED.store(true, Ordering::SeqCst);
        self.kick_cores_thread.take().unwrap().join().unwrap();
    }
}

impl<FUZZER: Fuzzer> Clone for ParallelVMPool<FUZZER> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<FUZZER: Fuzzer> Drop for ParallelVMPool<FUZZER> {
    fn drop(&mut self) {
        let my_thread_id = unsafe { libc::pthread_self() };
        log::debug!("thread {} returns VM", my_thread_id);
        let mut threads = self.inner.threads.write().unwrap();
        for thread_id in threads.iter_mut() {
            if thread_id.is_some_and(|tid| tid == my_thread_id) {
                *thread_id = None;
            }
        }
    }
}

impl<FUZZER: Fuzzer> ParallelVMPool<FUZZER> {
    /// Create a VM pool and initialize all with breakpoints loaded from the project state.
    pub fn with_breakpoints(project_state: ProjectState, cores: NonZeroUsize) -> Result<Self> {
        Self::with_setup(project_state, cores, gather_and_write_coverage_breakpoints)
    }

    /// create vm pool with common setup function
    pub fn with_setup<SF>(
        project_state: ProjectState,
        cores: NonZeroUsize,
        setup_func: SF,
    ) -> Result<Self>
    where
        SF: FnOnce(
            &ProjectState,
            Arc<RwLock<Memory>>,
            Option<&mut SymbolList>,
            Option<&mut fuzzvm::ResetBreakpoints>,
            &mut fuzzvm::CoverageBreakpoints,
        ) -> Result<()>,
    {
        rayon::ThreadPoolBuilder::new().num_threads(cores.into()).build_global().unwrap();
    
        let KvmEnvironment {
            kvm,
            cpuids,
            physmem_file,
            clean_snapshot,
            mut symbols,
            mut symbol_breakpoints,
        } = init_environment(&project_state)?;

        let mut coverage_breakpoints = fuzzvm::CoverageBreakpoints::default();

        setup_func(
            &project_state,
            clean_snapshot.clone(),
            symbols.as_mut(),
            symbol_breakpoints.as_mut(),
            &mut coverage_breakpoints,
        )?;

        let mut threads = Arc::new(RwLock::new(vec![None; cores.into()]));
        let project_state_arc = Arc::new(project_state.clone());
        let mut vmdata = vec![];

        let symbols_arc = Arc::new(symbols.clone());
        let reset_breakpoints_arc = Arc::new(symbol_breakpoints.clone());
        let reset_breakpoints = symbol_breakpoints;

        // Sanity check that the given fuzzer matches the snapshot
        ensure!(
            FUZZER::START_ADDRESS == project_state.vbcpu.rip,
            fuzzvm::Error::SnapshotMismatch
        );

        for core_id in 0_usize..(cores.into()) {
            // Create the VM for this core
            let vm = match kvm.create_vm().context("Failed to create VM from KVM") {
                Ok(vmfd) => vmfd,
                Err(e) => {
                    log::error!(
                        "Failed to create VM from KVM on core {} reason {}",
                        core_id,
                        e
                    );
                    continue;
                }
            };

            // Use the current fuzzer
            let mut fuzzer = FUZZER::default();
            let clean_snapshot = clean_snapshot.clone();
            let coverage_breakpoints = coverage_breakpoints.clone();

            let symbols_arc = symbols_arc.clone();

            // Create a 64-bit VM for fuzzing
            let fuzzvm = {
                // Get the variables for this thread
                let vbcpu = project_state.vbcpu.clone();
                let cpuids = cpuids.clone();
                let physmem_file_fd = physmem_file.as_raw_fd();
                let symbols = symbols.clone();
                let reset_breakpoints = reset_breakpoints.clone();
                let clean_snapshot = clean_snapshot.clone();
                let coverage_breakpoints = coverage_breakpoints.clone();
                let project_state = project_state.clone();
                #[cfg(feature = "redqueen")]
                let redqueen_breakpoints = project_state.redqueen_breakpoints.clone();

                FuzzVm::<FUZZER>::create(
                    u64::try_from(core_id)?,
                    &mut fuzzer,
                    vm,
                    vbcpu,
                    &cpuids,
                    physmem_file_fd,
                    clean_snapshot,
                    Some(coverage_breakpoints),
                    reset_breakpoints,
                    symbols,
                    project_state.config.clone(),
                    crate::stack_unwinder::StackUnwinders::default(),
                    #[cfg(feature = "redqueen")]
                    redqueen_breakpoints,
                )?
            };

            let v = Arc::new(RwLock::new(SharedVMData {
                fuzzer,
                fuzzvm,
                project_state: project_state_arc.clone(),
                clean_snapshot,
            }));

            vmdata.push(v);
        }

        let kick_cores_thread = {
            let threads = threads.clone();
            // Spawn the kick cores thread to prevent cores being stuck in an infinite loop
            std::thread::spawn(move || {
                // Ignore the SIGALRM for this thread
                crate::block_sigalrm().unwrap();

                // Set the core affinity for this core to always be 0
                core_affinity::set_for_current(CoreId { id: 0 });

                // Reset the finished marker
                crate::FINISHED.store(false, Ordering::SeqCst);

                // Start the kick cores worker
                loop {
                    if crate::FINISHED.load(Ordering::SeqCst) {
                        log::info!("[kick_cores] FINISHED");
                        break;
                    }

                    // If the kick timer has elapsed, it sets this variable
                    if crate::KICK_CORES.load(Ordering::SeqCst) {
                        if let Ok(threads) = threads.try_read() {
                            // Send SIGALRM to all executing threads
                            for thread_id in threads.iter() {
                                if let Some(thread_id) = thread_id {
                                    // Send SIGALRM to the current thread
                                    unsafe {
                                        libc::pthread_kill(*thread_id, libc::SIGALRM);
                                    }
                                }
                            }
                        }
                        // Reset the kick cores
                        crate::KICK_CORES.store(false, Ordering::SeqCst);
                    }

                    // Minimal sleep to avoid too much processor churn
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                }
            })
        };

        Ok(Self {
            inner: Arc::new(PVMEInner {
                threads,
                vmdata,
                kick_cores_thread: Some(kick_cores_thread),
            }),
        })
    }

    /// borrow a vm
    pub fn get_vm(&mut self) -> Result<std::sync::RwLockWriteGuard<SharedVMData<FUZZER>>> {
        let my_thread_id = unsafe { libc::pthread_self() };
        log::debug!("thread {} borrows VM", my_thread_id);
        let mut threads = self.inner.threads.write().unwrap();
        let mut core_id = None;
        let usable_cores = threads.len();
        log::debug!("threads: {:?} (cores: {})", threads, usable_cores);
        for c in 0..usable_cores {
            if let Some(thread_id) = threads.get_mut(c) {
                if thread_id.is_none() {
                    *thread_id = Some(my_thread_id);
                    core_id = Some(c);
                    break;
                }
            }
        }

        if core_id.is_none() {
            anyhow::bail!("failed to obtain a VM core");
        }
        let core_id = core_id.unwrap();

        // Set the core affinity for this core
        core_affinity::set_for_current(CoreId { id: core_id });

        // Unblock SIGALRM to enable this thread to handle SIGALRM
        unblock_sigalrm()?;

        Ok(self.inner.vmdata[core_id].write().unwrap())
    }
}
