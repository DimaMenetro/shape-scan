//! Section-aware analysis for known executable formats (ELF, PE, Mach-O).
//!
//! Falls back gracefully to a single "<file>" pseudo-section for
//! anything that isn't recognised by `goblin`.

use goblin::Object;
use serde::Serialize;

use crate::entropy::shannon_entropy;

/// Per-section entropy summary.
#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropy {
    pub name: String,
    pub size: u64,
    pub shannon_bits_per_byte: f64,
}

/// Top-level section report.
#[derive(Debug, Clone, Serialize)]
pub struct SectionReport {
    /// Detected format: "elf", "pe", "mach", "archive", or "unknown".
    pub format: String,
    pub sections: Vec<SectionEntropy>,
}

impl SectionReport {
    /// Parse `data` and produce per-section entropy. Never fails: on
    /// unrecognised input it returns a single pseudo-section covering
    /// the whole file.
    pub fn from_bytes(data: &[u8]) -> Self {
        match Object::parse(data) {
            Ok(Object::Elf(elf)) => Self::from_elf(&elf, data),
            Ok(Object::PE(pe)) => Self::from_pe(&pe, data),
            Ok(Object::Mach(mach)) => Self::from_mach(&mach, data),
            Ok(Object::Archive(_)) => Self::fallback("archive", data),
            _ => Self::fallback("unknown", data),
        }
    }

    fn fallback(format: &str, data: &[u8]) -> Self {
        Self {
            format: format.to_string(),
            sections: vec![SectionEntropy {
                name: "<file>".to_string(),
                size: data.len() as u64,
                shannon_bits_per_byte: shannon_entropy(data),
            }],
        }
    }

    fn from_elf(elf: &goblin::elf::Elf, data: &[u8]) -> Self {
        let mut sections = Vec::with_capacity(elf.section_headers.len());
        for sh in &elf.section_headers {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("<unnamed>")
                .to_string();
            let start = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            let end = start.saturating_add(size).min(data.len());
            let bytes = if start < data.len() {
                &data[start..end]
            } else {
                &[][..]
            };
            sections.push(SectionEntropy {
                name,
                size: bytes.len() as u64,
                shannon_bits_per_byte: shannon_entropy(bytes),
            });
        }
        Self {
            format: "elf".to_string(),
            sections,
        }
    }

    fn from_pe(pe: &goblin::pe::PE, data: &[u8]) -> Self {
        let mut sections = Vec::with_capacity(pe.sections.len());
        for s in &pe.sections {
            let name = String::from_utf8_lossy(
                &s.name[..s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len())],
            )
            .into_owned();
            let start = s.pointer_to_raw_data as usize;
            let size = s.size_of_raw_data as usize;
            let end = start.saturating_add(size).min(data.len());
            let bytes = if start < data.len() {
                &data[start..end]
            } else {
                &[][..]
            };
            sections.push(SectionEntropy {
                name,
                size: bytes.len() as u64,
                shannon_bits_per_byte: shannon_entropy(bytes),
            });
        }
        Self {
            format: "pe".to_string(),
            sections,
        }
    }

    fn from_mach(mach: &goblin::mach::Mach, data: &[u8]) -> Self {
        let mut sections = Vec::new();
        match mach {
            goblin::mach::Mach::Binary(bin) => {
                Self::push_mach_sections(bin, data, &mut sections);
            }
            goblin::mach::Mach::Fat(fat) => {
                if let Ok(arches) = fat.arches() {
                    for arch in arches {
                        if let Ok(goblin::mach::SingleArch::MachO(bin)) =
                            fat.get(arch.offset as usize)
                        {
                            Self::push_mach_sections(&bin, data, &mut sections);
                        }
                    }
                }
            }
        }
        Self {
            format: "mach".to_string(),
            sections,
        }
    }

    fn push_mach_sections(bin: &goblin::mach::MachO, data: &[u8], out: &mut Vec<SectionEntropy>) {
        for seg in &bin.segments {
            if let Ok(secs) = seg.sections() {
                for (s, _bytes) in secs {
                    let name =
                        format!("{},{}", s.segname().unwrap_or("?"), s.name().unwrap_or("?"));
                    let start = s.offset as usize;
                    let size = s.size as usize;
                    let end = start.saturating_add(size).min(data.len());
                    let slice = if start < data.len() {
                        &data[start..end]
                    } else {
                        &[][..]
                    };
                    out.push(SectionEntropy {
                        name,
                        size: slice.len() as u64,
                        shannon_bits_per_byte: shannon_entropy(slice),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_input_yields_pseudo_section() {
        let r = SectionReport::from_bytes(b"hello, world");
        assert_eq!(r.format, "unknown");
        assert_eq!(r.sections.len(), 1);
        assert_eq!(r.sections[0].name, "<file>");
    }
}
