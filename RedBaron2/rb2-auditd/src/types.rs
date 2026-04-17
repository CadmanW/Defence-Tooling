/// Bitflags selecting which correlated audit event kinds to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEventFlags(u8);

impl AuditEventFlags {
    pub const NONE: Self = Self(0);
    pub const EXEC: Self = Self(1 << 0);
    pub const NETWORK: Self = Self(1 << 1);
    pub const ALL: Self = Self(Self::EXEC.0 | Self::NETWORK.0);

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for AuditEventFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for AuditEventFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Startup options for the audit daemon.
#[derive(Debug, Clone, Copy)]
pub struct AuditDaemonConfig {
    pub event_flags: AuditEventFlags,
}

impl Default for AuditDaemonConfig {
    fn default() -> Self {
        Self {
            event_flags: AuditEventFlags::EXEC,
        }
    }
}
