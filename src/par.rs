//! Running independent work on several threads with the output of one.
//!
//! The rule: whatever the number of threads, the CSV, stderr and every other
//! file written are byte for byte those of a run on one thread. Three things
//! make it hold.
//!
//! * Results are put together in the order of the inputs, never in the order
//!   the threads finish.
//! * The library writes to stderr through [`say`]. Work run by [`ordered`]
//!   keeps its messages, and they are printed, input by input, in that same
//!   order, so stderr reads as if one input followed the other. Progress bars
//!   are hidden meanwhile: they would draw over each other.
//! * The hunt numbers volumes and records as the parsers meet them. Each input
//!   numbers its own from zero, and they are moved, in input order, to the
//!   numbers a sequential run gives (see [`crate::hunt::scoped_ids`]).

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;

use crate::timeline::TimelineEntry;

thread_local! {
    static CAPTURE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    /// Where the work of this thread sits in the run, for the names of its
    /// temporary files: the place of every input it is inside of, and how
    /// many names it has taken there.
    static PLACE: RefCell<(String, u64)> = const { RefCell::new((String::new(), 0)) };
}

/// A name for a temporary file or folder, unique in the run and the same on
/// any number of threads: it says where the work that asks for it sits
/// (input 3 of the second list read inside input 1: `1-0.3-1.`) and counts
/// from there. Temporary paths are printed on stderr; a counter shared by
/// the threads would number them in the order the threads get there.
pub fn unique_name() -> String {
    PLACE.with(|p| {
        let mut p = p.borrow_mut();
        let n = p.1;
        p.1 += 1;
        format!("{}{}", p.0, n)
    })
}

/// Runs `f` as item `index` of a list that took `list` from the names of the place it runs in.
fn at_place<T>(prefix: &str, index: usize, f: impl FnOnce() -> T) -> T {
    struct Back(Option<(String, u64)>);
    impl Drop for Back {
        fn drop(&mut self) {
            if let Some(prev) = self.0.take() {
                PLACE.with(|p| *p.borrow_mut() = prev);
            }
        }
    }
    let _back = Back(Some(PLACE.with(|p| std::mem::replace(&mut *p.borrow_mut(), (format!("{prefix}{index}."), 0)))));
    f()
}

/// One line on stderr, or in the messages of the work running on this thread.
pub fn say(msg: String) {
    let direct = CAPTURE.with(|c| match c.borrow_mut().as_mut() {
        Some(buf) => {
            buf.push(msg);
            None
        }
        None => Some(msg),
    });
    if let Some(m) = direct {
        eprintln!("{}", m);
    }
}

/// `eprintln!` for the library: see [`say`].
#[macro_export]
macro_rules! say {
    ($($t:tt)*) => { $crate::par::say(format!($($t)*)) };
}

/// True while the messages of this thread are being kept: progress bars stay hidden.
pub fn capturing() -> bool {
    CAPTURE.with(|c| c.borrow().is_some())
}

/// Puts back what [`captured`] replaced, also when the work panics.
struct Restore(Option<Option<Vec<String>>>);

impl Drop for Restore {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            CAPTURE.with(|c| *c.borrow_mut() = prev);
        }
    }
}

/// Runs `f` keeping its messages instead of printing them.
pub fn captured<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    let mut guard = Restore(Some(CAPTURE.with(|c| c.borrow_mut().replace(Vec::new()))));
    let out = f();
    let prev = guard.0.take().unwrap_or(None);
    let mine = CAPTURE.with(|c| std::mem::replace(&mut *c.borrow_mut(), prev)).unwrap_or_default();
    (out, mine)
}

/// What [`ordered`] renumbers once an input's place in the run is known.
pub trait Rebase {
    fn rebase(&mut self, volume_base: u32, unit_base: u64);
}

impl Rebase for Vec<TimelineEntry> {
    fn rebase(&mut self, volume_base: u32, unit_base: u64) {
        crate::hunt::rebase(self, volume_base, unit_base);
    }
}

impl<T: Rebase> Rebase for Option<T> {
    fn rebase(&mut self, v: u32, u: u64) {
        if let Some(t) = self {
            t.rebase(v, u);
        }
    }
}

impl<T: Rebase, E> Rebase for Result<T, E> {
    fn rebase(&mut self, v: u32, u: u64) {
        if let Ok(t) = self {
            t.rebase(v, u);
        }
    }
}

impl<A: Rebase, B> Rebase for (A, B) {
    fn rebase(&mut self, v: u32, u: u64) {
        self.0.rebase(v, u);
    }
}

static ONE_INPUT_AT_A_TIME: AtomicBool = AtomicBool::new(false);

/// Inputs are read one after another, in the order given, when what they do
/// outside the timeline depends on that order: the resident dump names a
/// second file with the same path `.rec<N>`, and which source gets the plain
/// name must not depend on which thread is faster.
pub fn one_input_at_a_time(on: bool) {
    ONE_INPUT_AT_A_TIME.store(on, Ordering::Relaxed);
}

/// Runs `f` on every item, several at a time when there is more than one,
/// and hands the results to `then` in item order, each after the messages
/// its work printed. A single item runs right here, printing as it goes.
pub fn ordered<I, T>(items: &[I], f: impl Fn(&I) -> T + Sync, mut then: impl FnMut(T))
where
    I: Sync,
    T: Send + Rebase,
{
    // Every list takes one name of the place it is read in, so two lists read
    // one after the other give their items different places.
    let prefix = format!("{}-", unique_name());
    if items.len() <= 1 || ONE_INPUT_AT_A_TIME.load(Ordering::Relaxed) {
        for (k, i) in items.iter().enumerate() {
            then(at_place(&prefix, k, || f(i)));
        }
        return;
    }
    let done: Vec<(T, Vec<String>, (u32, u64))> = items
        .par_iter()
        .enumerate()
        .map(|(k, i)| {
            let ((t, ids), msgs) = captured(|| crate::hunt::scoped_ids(|| at_place(&prefix, k, || f(i))));
            (t, msgs, ids)
        })
        .collect();
    for (mut t, msgs, (volumes, units)) in done {
        let (vb, ub) = crate::hunt::reserve_ids(volumes, units);
        t.rebase(vb, ub);
        for m in msgs {
            say(m);
        }
        then(t);
    }
}

/// Threads for a run: `requested`, or every logical processor the system
/// reports when it is 0.
pub fn thread_count(requested: usize) -> usize {
    if requested > 0 {
        requested
    } else {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    }
}

/// Sets up the threads of the run. Large stacks: path resolution recurses,
/// and a worker thread must hold what the main thread holds.
pub fn init(requested: usize) -> usize {
    let n = thread_count(requested);
    let _ = rayon::ThreadPoolBuilder::new().num_threads(n).stack_size(16 << 20).build_global();
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_messages_are_kept_and_nest() {
        let ((inner, outer_after), outer) = captured(|| {
            say("a".into());
            let (_, inner) = captured(|| say("b".into()));
            say("c".into());
            (inner, capturing())
        });
        assert_eq!(inner, vec!["b"]);
        assert_eq!(outer, vec!["a", "c"]);
        assert!(outer_after);
        assert!(!capturing());
    }

    struct Names(Vec<String>);
    impl Rebase for Names {
        fn rebase(&mut self, _: u32, _: u64) {}
    }

    /// Two lists one after the other, items of the first with a list of their
    /// own, items finishing in reverse order: every name is fixed by place.
    fn names_taken() -> Vec<String> {
        let mut all = Vec::new();
        let outer: Vec<usize> = (0..12).collect();
        for _ in 0..2 {
            ordered(
                &outer,
                |&k| {
                    std::thread::sleep(std::time::Duration::from_micros(((12 - k) * 300) as u64));
                    let mut v = vec![unique_name(), unique_name()];
                    let inner: Vec<usize> = (0..3).collect();
                    ordered(&inner, |_| Names(vec![unique_name()]), |n| v.extend(n.0));
                    v.push(unique_name());
                    Names(v)
                },
                |n| all.extend(n.0),
            );
        }
        all
    }

    #[test]
    fn temporary_names_depend_on_place_not_on_threads() {
        let pool = |n| rayon::ThreadPoolBuilder::new().num_threads(n).build().unwrap();
        let one = pool(1).install(names_taken);
        let eight = pool(8).install(names_taken);
        assert_eq!(one, eight);
        let mut expected = Vec::new();
        for list in 0..2 {
            for k in 0..12 {
                expected.push(format!("{list}-{k}.0"));
                expected.push(format!("{list}-{k}.1"));
                for j in 0..3 {
                    expected.push(format!("{list}-{k}.2-{j}.0"));
                }
                expected.push(format!("{list}-{k}.3"));
            }
        }
        assert_eq!(one, expected);
        let unique: std::collections::HashSet<&String> = one.iter().collect();
        assert_eq!(unique.len(), one.len());
    }

    #[test]
    fn ordered_hands_results_back_in_item_order() {
        struct N(usize);
        impl Rebase for N {
            fn rebase(&mut self, _: u32, _: u64) {}
        }
        let items: Vec<usize> = (0..64).collect();
        let mut got = Vec::new();
        let (_, msgs) = captured(|| {
            ordered(&items, |&i| {
                std::thread::sleep(std::time::Duration::from_micros(((64 - i) * 50) as u64));
                say(format!("item {i}"));
                N(i)
            }, |n| got.push(n.0))
        });
        assert_eq!(got, items);
        assert_eq!(msgs, items.iter().map(|i| format!("item {i}")).collect::<Vec<_>>());
    }
}
