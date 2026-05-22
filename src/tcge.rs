//! Topological Code Geometry Engine (TCGE)
//!
//! TEM Module 2 — Structural topology analysis of binary execution logic.
//!
//! Analyzes the mathematical SHAPE of a binary's execution logic rather
//! than its semantic content. Code is treated as geometry, not language.
//!
//! Methods:
//!   1. Format-aware section parsing via goblin (PE, ELF, Mach-O)
//!   2. x86 basic block extraction and causal graph construction
//!   3. Graph metrics (back-edges, clustering, SCCs, circuit rank)
//!   4. Algebraic cycle count (persistent homology fallback)

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::Path;

// ============================================================
// Anomaly flags
// ============================================================

pub const TOPO_ANOMALY_NONE: u32 = 0x0000;
pub const TOPO_ANOMALY_HIGH_BACK_EDGES: u32 = 0x0001;
pub const TOPO_ANOMALY_HIGH_DENSITY: u32 = 0x0002;
pub const TOPO_ANOMALY_LARGE_SCC: u32 = 0x0004;
pub const TOPO_ANOMALY_DEEP_NESTING: u32 = 0x0008;
pub const TOPO_ANOMALY_HIGH_CYCLES: u32 = 0x0010;
pub const TOPO_ANOMALY_SELF_LOOPS: u32 = 0x0020;
pub const TOPO_ANOMALY_FLAT_DISPATCH: u32 = 0x0040;

// ============================================================
// Output type — strictly numeric
// ============================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct TopologyProfile {
    pub file_size: usize,
    pub format_detected: u8, // 0=unknown, 1=PE, 2=ELF, 3=MachO

    // Graph metrics
    pub node_count: usize,
    pub edge_count: usize,
    pub back_edge_count: usize,
    pub back_edge_ratio: f64,
    pub graph_density: f64,
    pub avg_degree: f64,
    pub max_degree: usize,
    pub self_loop_count: usize,

    // Connectivity
    pub connected_components: usize,
    pub strongly_connected_count: usize,
    pub largest_scc_size: usize,
    pub scc_ratio: f64,

    // Cycles
    pub cycle_count: usize, // circuit rank = edges - nodes + components

    // Verdicts
    pub topology_anomaly: bool,
    pub anomaly_flags: u32,
}

// ============================================================
// Directed graph (adjacency list — replaces NetworkX)
// ============================================================

struct DiGraph {
    adjacency: HashMap<u64, Vec<u64>>,
    nodes: HashSet<u64>,
}

impl DiGraph {
    fn new() -> Self {
        DiGraph {
            adjacency: HashMap::new(),
            nodes: HashSet::new(),
        }
    }

    fn add_node(&mut self, n: u64) {
        self.nodes.insert(n);
        self.adjacency.entry(n).or_default();
    }

    fn add_edge(&mut self, from: u64, to: u64) {
        self.nodes.insert(from);
        self.nodes.insert(to);
        self.adjacency.entry(from).or_default().push(to);
        self.adjacency.entry(to).or_default();
    }

    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn edge_count(&self) -> usize {
        self.adjacency.values().map(|v| v.len()).sum()
    }

    fn density(&self) -> f64 {
        let n = self.node_count();
        if n <= 1 {
            return 0.0;
        }
        let e = self.edge_count();
        e as f64 / (n as f64 * (n as f64 - 1.0))
    }

    fn degrees(&self) -> Vec<usize> {
        // In-degree + out-degree for each node
        let mut in_deg: HashMap<u64, usize> = HashMap::new();
        for neighbors in self.adjacency.values() {
            for &n in neighbors {
                *in_deg.entry(n).or_insert(0) += 1;
            }
        }
        self.nodes
            .iter()
            .map(|&n| {
                let out = self.adjacency.get(&n).map(|v| v.len()).unwrap_or(0);
                let ind = in_deg.get(&n).copied().unwrap_or(0);
                out + ind
            })
            .collect()
    }

    fn self_loops(&self) -> usize {
        let mut count = 0;
        for (&node, neighbors) in &self.adjacency {
            count += neighbors.iter().filter(|&&n| n == node).count();
        }
        count
    }

    /// Count back edges using DFS. A back edge points from a node to one of its
    /// ancestors in the DFS tree — indicating a loop.
    fn back_edge_count(&self) -> usize {
        let mut visited = HashSet::new();
        let mut on_stack = HashSet::new();
        let mut back_edges = 0;

        for &start in &self.nodes {
            if visited.contains(&start) {
                continue;
            }
            let mut stack: Vec<(u64, usize)> = vec![(start, 0)];
            visited.insert(start);
            on_stack.insert(start);

            while let Some((node, idx)) = stack.last_mut() {
                let neighbors = self.adjacency.get(node).cloned().unwrap_or_default();
                if *idx < neighbors.len() {
                    let neighbor = neighbors[*idx];
                    *idx += 1;
                    if on_stack.contains(&neighbor) {
                        back_edges += 1;
                    } else if !visited.contains(&neighbor) {
                        visited.insert(neighbor);
                        on_stack.insert(neighbor);
                        stack.push((neighbor, 0));
                    }
                } else {
                    on_stack.remove(node);
                    stack.pop();
                }
            }
        }
        back_edges
    }

    /// Find connected components (undirected view) using BFS.
    fn connected_components(&self) -> Vec<Vec<u64>> {
        // Build undirected adjacency
        let mut undirected: HashMap<u64, HashSet<u64>> = HashMap::new();
        for &n in &self.nodes {
            undirected.entry(n).or_default();
        }
        for (&from, neighbors) in &self.adjacency {
            for &to in neighbors {
                undirected.entry(from).or_default().insert(to);
                undirected.entry(to).or_default().insert(from);
            }
        }

        let mut visited = HashSet::new();
        let mut components = Vec::new();

        for &start in &self.nodes {
            if visited.contains(&start) {
                continue;
            }
            let mut component = Vec::new();
            let mut queue = VecDeque::new();
            queue.push_back(start);
            visited.insert(start);

            while let Some(node) = queue.pop_front() {
                component.push(node);
                if let Some(neighbors) = undirected.get(&node) {
                    for &n in neighbors {
                        if !visited.contains(&n) {
                            visited.insert(n);
                            queue.push_back(n);
                        }
                    }
                }
            }
            components.push(component);
        }
        components
    }

    /// Tarjan's algorithm for strongly connected components.
    fn strongly_connected_components(&self) -> Vec<Vec<u64>> {
        let mut index_counter = 0u64;
        let mut stack = Vec::new();
        let mut on_stack = HashSet::new();
        let mut indices: HashMap<u64, u64> = HashMap::new();
        let mut lowlinks: HashMap<u64, u64> = HashMap::new();
        let mut result = Vec::new();

        for &node in &self.nodes {
            if !indices.contains_key(&node) {
                self.tarjan_dfs(
                    node,
                    &mut index_counter,
                    &mut stack,
                    &mut on_stack,
                    &mut indices,
                    &mut lowlinks,
                    &mut result,
                );
            }
        }
        result
    }

    #[allow(clippy::too_many_arguments)] // Tarjan's SCC carries algorithm state across the DFS
    fn tarjan_dfs(
        &self,
        v: u64,
        index_counter: &mut u64,
        stack: &mut Vec<u64>,
        on_stack: &mut HashSet<u64>,
        indices: &mut HashMap<u64, u64>,
        lowlinks: &mut HashMap<u64, u64>,
        result: &mut Vec<Vec<u64>>,
    ) {
        // Iterative Tarjan's to avoid stack overflow on deep graphs
        struct Frame {
            node: u64,
            neighbor_idx: usize,
        }

        let mut call_stack = vec![Frame {
            node: v,
            neighbor_idx: 0,
        }];

        indices.insert(v, *index_counter);
        lowlinks.insert(v, *index_counter);
        *index_counter += 1;
        stack.push(v);
        on_stack.insert(v);

        while let Some(frame) = call_stack.last_mut() {
            let node = frame.node;
            let neighbors = self.adjacency.get(&node).cloned().unwrap_or_default();

            if frame.neighbor_idx < neighbors.len() {
                let w = neighbors[frame.neighbor_idx];
                frame.neighbor_idx += 1;

                if let std::collections::hash_map::Entry::Vacant(e) = indices.entry(w) {
                    e.insert(*index_counter);
                    lowlinks.insert(w, *index_counter);
                    *index_counter += 1;
                    stack.push(w);
                    on_stack.insert(w);
                    call_stack.push(Frame {
                        node: w,
                        neighbor_idx: 0,
                    });
                } else if on_stack.contains(&w) {
                    let w_idx = indices[&w];
                    let cur_low = lowlinks[&node];
                    if w_idx < cur_low {
                        lowlinks.insert(node, w_idx);
                    }
                }
            } else {
                // All neighbors processed — check if root of SCC
                if lowlinks[&node] == indices[&node] {
                    let mut scc = Vec::new();
                    while let Some(w) = stack.pop() {
                        on_stack.remove(&w);
                        scc.push(w);
                        if w == node {
                            break;
                        }
                    }
                    result.push(scc);
                }

                // Propagate lowlink to caller
                call_stack.pop();
                if let Some(parent_frame) = call_stack.last() {
                    let parent = parent_frame.node;
                    let child_low = lowlinks[&node];
                    let parent_low = lowlinks[&parent];
                    if child_low < parent_low {
                        lowlinks.insert(parent, child_low);
                    }
                }
            }
        }
    }
}

// ============================================================
// Binary section extraction via goblin
// ============================================================

struct SectionInfo {
    virtual_addr: u64,
    raw_offset: usize,
    raw_size: usize,
    is_executable: bool,
}

fn extract_sections(data: &[u8]) -> (Vec<SectionInfo>, u8) {
    let mut sections = Vec::new();
    let format_code;

    match goblin::Object::parse(data) {
        Ok(goblin::Object::PE(pe)) => {
            format_code = 1;
            for section in pe.sections {
                let chars = section.characteristics;
                let is_exec = (chars & 0x2000_0000) != 0; // IMAGE_SCN_MEM_EXECUTE
                sections.push(SectionInfo {
                    virtual_addr: section.virtual_address as u64,
                    raw_offset: section.pointer_to_raw_data as usize,
                    raw_size: section.size_of_raw_data as usize,
                    is_executable: is_exec,
                });
            }
        }
        Ok(goblin::Object::Elf(elf)) => {
            format_code = 2;
            for phdr in &elf.program_headers {
                if phdr.p_type == goblin::elf::program_header::PT_LOAD {
                    let is_exec = (phdr.p_flags & 0x1) != 0; // PF_X
                    sections.push(SectionInfo {
                        virtual_addr: phdr.p_vaddr,
                        raw_offset: phdr.p_offset as usize,
                        raw_size: phdr.p_filesz as usize,
                        is_executable: is_exec,
                    });
                }
            }
        }
        Ok(goblin::Object::Mach(mach)) => {
            format_code = 3;
            if let goblin::mach::Mach::Binary(macho) = mach {
                for seg in &macho.segments {
                    let is_exec = (seg.flags & 0x4) != 0; // SG_NORELOC or check initprot
                                                          // Check initprot for execute permission
                    let exec_perm = (seg.initprot & 0x4) != 0;
                    for (section, _) in seg.sections().unwrap_or_default() {
                        sections.push(SectionInfo {
                            virtual_addr: section.addr,
                            raw_offset: section.offset as usize,
                            raw_size: section.size as usize,
                            is_executable: is_exec || exec_perm,
                        });
                    }
                }
            }
        }
        _ => {
            format_code = 0;
        }
    }

    (sections, format_code)
}

// ============================================================
// x86 basic block graph extraction
// ============================================================

fn build_basic_block_graph(data: &[u8], sections: &[SectionInfo], max_nodes: usize) -> DiGraph {
    let mut graph = DiGraph::new();

    for sec in sections {
        if !sec.is_executable {
            continue;
        }

        let start = sec.raw_offset;
        let end = (start + sec.raw_size).min(data.len());
        if start >= end || end - start < 4 {
            continue;
        }
        let sec_data = &data[start..end];

        let mut block_starts: HashSet<usize> = HashSet::new();
        block_starts.insert(0);

        struct BranchTarget {
            src: usize,
            target: Option<usize>, // jump target (-1 = none)
            fallthrough: Option<usize>,
        }
        let mut branches: Vec<BranchTarget> = Vec::new();

        let mut i = 0;
        while i < sec_data.len().saturating_sub(1) {
            let opcode = sec_data[i];

            match opcode {
                // Short conditional jumps (0x70-0x7F)
                0x70..=0x7F => {
                    if i + 1 < sec_data.len() {
                        let offset = sec_data[i + 1] as i8 as isize;
                        let target = (i as isize + 2 + offset) as usize;
                        let fallthrough = i + 2;
                        block_starts.insert(fallthrough);
                        if target < sec_data.len() {
                            block_starts.insert(target);
                            branches.push(BranchTarget {
                                src: i,
                                target: Some(target),
                                fallthrough: Some(fallthrough),
                            });
                        }
                    }
                    i += 2;
                }
                // Short unconditional jump
                0xEB => {
                    if i + 1 < sec_data.len() {
                        let offset = sec_data[i + 1] as i8 as isize;
                        let target = (i as isize + 2 + offset) as usize;
                        if target < sec_data.len() {
                            block_starts.insert(target);
                            branches.push(BranchTarget {
                                src: i,
                                target: Some(target),
                                fallthrough: None,
                            });
                        }
                    }
                    i += 2;
                }
                // Near unconditional jump
                0xE9 => {
                    if i + 4 < sec_data.len() {
                        let offset = i32::from_le_bytes([
                            sec_data[i + 1],
                            sec_data[i + 2],
                            sec_data[i + 3],
                            sec_data[i + 4],
                        ]) as isize;
                        let target = (i as isize + 5 + offset) as usize;
                        if target < sec_data.len() {
                            block_starts.insert(target);
                            branches.push(BranchTarget {
                                src: i,
                                target: Some(target),
                                fallthrough: None,
                            });
                        }
                    }
                    i += 5;
                }
                // CALL rel32
                0xE8 => {
                    if i + 4 < sec_data.len() {
                        let offset = i32::from_le_bytes([
                            sec_data[i + 1],
                            sec_data[i + 2],
                            sec_data[i + 3],
                            sec_data[i + 4],
                        ]) as isize;
                        let target = (i as isize + 5 + offset) as usize;
                        let fallthrough = i + 5;
                        block_starts.insert(fallthrough);
                        if target < sec_data.len() {
                            block_starts.insert(target);
                            branches.push(BranchTarget {
                                src: i,
                                target: Some(target),
                                fallthrough: Some(fallthrough),
                            });
                        }
                    }
                    i += 5;
                }
                // Two-byte conditional jump (0x0F 0x80-0x8F)
                0x0F if i + 1 < sec_data.len() && (0x80..=0x8F).contains(&sec_data[i + 1]) => {
                    if i + 5 < sec_data.len() {
                        let offset = i32::from_le_bytes([
                            sec_data[i + 2],
                            sec_data[i + 3],
                            sec_data[i + 4],
                            sec_data[i + 5],
                        ]) as isize;
                        let target = (i as isize + 6 + offset) as usize;
                        let fallthrough = i + 6;
                        block_starts.insert(fallthrough);
                        if target < sec_data.len() {
                            block_starts.insert(target);
                            branches.push(BranchTarget {
                                src: i,
                                target: Some(target),
                                fallthrough: Some(fallthrough),
                            });
                        }
                    }
                    i += 6;
                }
                // RET / INT3
                0xC3 | 0xC2 | 0xCB | 0xCC => {
                    if i + 1 < sec_data.len() {
                        block_starts.insert(i + 1);
                    }
                    branches.push(BranchTarget {
                        src: i,
                        target: None,
                        fallthrough: None,
                    });
                    i += 1;
                }
                _ => {
                    i += 1;
                }
            }

            if block_starts.len() > max_nodes {
                break;
            }
        }

        // Build nodes from sorted block starts
        let mut sorted_blocks: Vec<usize> = block_starts.into_iter().collect();
        sorted_blocks.sort();
        sorted_blocks.truncate(max_nodes);

        let mut block_map: HashMap<usize, u64> = HashMap::new();
        for &bs in &sorted_blocks {
            let node_id = sec.virtual_addr + bs as u64;
            graph.add_node(node_id);
            block_map.insert(bs, node_id);
        }

        // Build edges from branches
        for branch in &branches {
            // Find which block contains this branch instruction
            let src_block = sorted_blocks
                .iter()
                .rev()
                .find(|&&bs| bs <= branch.src)
                .copied();

            let src_id = src_block.and_then(|b| block_map.get(&b).copied());
            let Some(src_id) = src_id else { continue };

            if let Some(target) = branch.target {
                let tgt_block = sorted_blocks
                    .iter()
                    .rev()
                    .find(|&&bs| bs <= target)
                    .copied();
                if let Some(tgt_id) = tgt_block.and_then(|b| block_map.get(&b).copied()) {
                    graph.add_edge(src_id, tgt_id);
                }
            }

            if let Some(ft) = branch.fallthrough {
                if let Some(&ft_id) = block_map.get(&ft) {
                    graph.add_edge(src_id, ft_id);
                }
            }
        }
    }

    graph
}

/// Build a generic graph for non-executable files using byte-level
/// structural block analysis.
fn build_generic_graph(data: &[u8], max_nodes: usize) -> DiGraph {
    let mut graph = DiGraph::new();

    let block_size = (data.len() / max_nodes).max(64);
    let num_blocks = (data.len() / block_size).min(max_nodes);

    if num_blocks < 2 {
        graph.add_node(0);
        return graph;
    }

    // Sequential flow edges
    for i in 0..num_blocks {
        graph.add_node(i as u64);
        if i > 0 {
            graph.add_edge((i - 1) as u64, i as u64);
        }
    }

    // Cross-reference edges (4-byte values that look like offsets)
    for i in 0..num_blocks {
        let start = i * block_size;
        let end = (start + block_size).min(data.len());
        let block_data = &data[start..end];

        let mut edge_added = 0;
        for j in (0..block_data.len().saturating_sub(3)).step_by(4) {
            if j + 4 > block_data.len() {
                break;
            }
            let ref_val = u32::from_le_bytes([
                block_data[j],
                block_data[j + 1],
                block_data[j + 2],
                block_data[j + 3],
            ]) as usize;
            let target_block = ref_val / block_size;
            if target_block < num_blocks && target_block != i {
                graph.add_edge(i as u64, target_block as u64);
                edge_added += 1;
                if edge_added > 8 {
                    break;
                } // Cap edges per block
            }
        }

        if graph.edge_count() > max_nodes * 8 {
            break;
        }
    }

    graph
}

// ============================================================
// Main analysis function
// ============================================================

/// Perform full TCGE analysis on raw bytes.
pub fn analyze_bytes(data: &[u8]) -> TopologyProfile {
    let file_size = data.len();
    let max_nodes = 4096;

    let (sections, format_code) = extract_sections(data);
    let has_exec_sections = sections.iter().any(|s| s.is_executable);

    // Build the causal graph
    let graph = if has_exec_sections {
        build_basic_block_graph(data, &sections, max_nodes)
    } else {
        build_generic_graph(data, max_nodes.min(2048))
    };

    // Ensure non-empty
    let node_count = graph.node_count().max(1);
    let edge_count = graph.edge_count();
    let density = graph.density();

    // Back edges
    let back_edges = graph.back_edge_count();
    let back_edge_ratio = back_edges as f64 / edge_count.max(1) as f64;

    // Degree statistics
    let degrees = graph.degrees();
    let avg_degree = if !degrees.is_empty() {
        degrees.iter().sum::<usize>() as f64 / degrees.len() as f64
    } else {
        0.0
    };
    let max_degree = degrees.iter().cloned().max().unwrap_or(0);

    // Self-loops
    let self_loops = graph.self_loops();

    // Connected components (undirected)
    let components = graph.connected_components();
    let num_components = components.len().max(1);

    // Strongly connected components
    let sccs = graph.strongly_connected_components();
    let scc_count = sccs.len();
    let largest_scc = sccs.iter().map(|s| s.len()).max().unwrap_or(0);
    let scc_ratio = largest_scc as f64 / node_count as f64;

    // Circuit rank (algebraic cycle count) = edges - nodes + components
    let cycle_count = if edge_count > node_count {
        edge_count - node_count + num_components
    } else {
        0
    };

    // Anomaly detection
    let mut anomaly_flags: u32 = TOPO_ANOMALY_NONE;

    if back_edge_ratio > 0.3 {
        anomaly_flags |= TOPO_ANOMALY_HIGH_BACK_EDGES;
    }
    if density > 0.1 && node_count > 20 {
        anomaly_flags |= TOPO_ANOMALY_HIGH_DENSITY;
    }
    if scc_ratio > 0.5 && largest_scc > 10 {
        anomaly_flags |= TOPO_ANOMALY_LARGE_SCC;
    }
    if cycle_count > 20 {
        anomaly_flags |= TOPO_ANOMALY_HIGH_CYCLES;
    }
    if self_loops > 5 {
        anomaly_flags |= TOPO_ANOMALY_SELF_LOOPS;
    }
    // Control-flow flattening signature
    if max_degree > node_count / 3 && density < 0.1 && back_edge_ratio > 0.2 {
        anomaly_flags |= TOPO_ANOMALY_FLAT_DISPATCH;
    }

    let topology_anomaly = anomaly_flags != TOPO_ANOMALY_NONE;

    TopologyProfile {
        file_size,
        format_detected: format_code,
        node_count,
        edge_count,
        back_edge_count: back_edges,
        back_edge_ratio,
        graph_density: density,
        avg_degree,
        max_degree,
        self_loop_count: self_loops,
        connected_components: num_components,
        strongly_connected_count: scc_count,
        largest_scc_size: largest_scc,
        scc_ratio,
        cycle_count,
        topology_anomaly,
        anomaly_flags,
    }
}

/// Perform TCGE analysis on a file at the given path.
pub fn analyze(path: &Path) -> io::Result<TopologyProfile> {
    let data = std::fs::read(path)?;
    Ok(analyze_bytes(&data))
}
