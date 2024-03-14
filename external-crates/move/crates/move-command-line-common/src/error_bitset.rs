// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

pub struct ErrorBitset {
    // |<tagbit>|<reserved>|<line number>|<identifier index>|<constant index>|
    //   1-bit    15-bits       16-bits        16-bits          16-bits
    pub bits: u64,
}

impl ErrorBitset {
    pub fn new(line_number: u16, identifier_index: u16, constant_index: u16) -> Self {
        let mut bits = 0u64;
        bits |= 1u64 << 63;
        bits |= (line_number as u64) << 32;
        bits |= (identifier_index as u64) << 16;
        bits |= constant_index as u64;
        Self { bits }
    }

    pub fn from_u64(bits: u64) -> Option<Self> {
        if Self::is_tagged_error(bits) {
            Some(Self { bits })
        } else {
            None
        }
    }

    pub fn is_tagged_error(bits: u64) -> bool {
        bits >> 63 == 1
    }

    pub fn line_number(&self) -> u16 {
        (self.bits >> 32) as u16
    }

    pub fn identifier_index(&self) -> Option<u16> {
        let idx = (self.bits >> 16) as u16;
        if idx == u16::MAX {
            None
        } else {
            Some(idx)
        }
    }

    pub fn constant_index(&self) -> Option<u16> {
        // NB: purposeful truncation
        let idx = self.bits as u16;
        if idx == u16::MAX {
            None
        } else {
            Some(idx)
        }
    }
}
