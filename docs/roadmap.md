# Roadmap

[← README](../README.md)

What could come next, and why it is not done yet. Every item that touches how evidence is read has to keep the rule the rest of the tool keeps: the output is byte for byte the same on any number of threads (`scripts/same_output.py`), and the run leaves no trace on the evidence ([How it was checked](validation.md)).

## Speed on a single machine

With several machines, each one is read on its own thread (eight hosts: 38 s to 21 s on 12 logical processors). A single machine is read mostly on one thread: its partitions one after another, its `$MFT` in one pass. Only the free-space search of `--carve`, the sort and the CSV use every processor (one 437,000-record `$MFT`: 17.9 s to 13.4 s; carving an E01: about half the time). Judged not worth it for now:

| Idea | Gain | Why not yet |
|---|---|---|
| Partitions and logical volumes of one image read at the same time | Only on images with several large volumes, up to about half the time there | Each volume needs its own reader (and, for an E01, its own chunk cache): more memory for a case that is not the common one |
| The `$MFT` parsed on several threads | Up to about 45 % on one large `$MFT` | The path resolver keeps state and extension records point at other records: a mistake there changes paths without any error. Only with a proof of identical output on every sample, and after profiling the single-threaded parse, which may give as much without threads |
| The `FILE`/`INDX` signature scan and E01 decompression of `--carve` on several threads | Most of what carving still spends | It changes how blocks are walked and where the scanner skips; the free-space search, which needed no such change, is already parallel |

## Inputs read at the same time

Up to one input per logical processor is read at once. Neither memory nor the disk is taken into account: twelve very large images at once add up their memory, and on a single spinning disk several inputs at once make it seek between them and can be slower than one. A limit on inputs at a time (by option, or from free memory) would not change the output, since the number of threads never does.

## Reading without a trace

- **Ex01 (EWF2) images** are opened by the `ewf` crate from their paths, so their access time is not frozen (the run says so). It needs the crate to read EWF2 from handles it is given, as it already does for E01.
- **ZIP times** are DOS local times with no zone and are read as UTC. The extended timestamp field (`UT`, 0x5455), when present, holds the modification time in UTC and would make those rows exact.
