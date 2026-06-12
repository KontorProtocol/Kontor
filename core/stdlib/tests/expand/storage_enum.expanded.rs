use stdlib::Storage;
enum ChallengeStatus {
    Active,
    Proven,
    Failed(u64),
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for ChallengeStatus {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
        value: ChallengeStatus,
    ) {
        stdlib::WriteStorage::__delete_matching_paths(
            ctx,
            &base_path,
            &["active", "proven", "failed"],
        );
        match value {
            ChallengeStatus::Active => {
                stdlib::WriteStorage::__set(ctx, base_path.push("active"), ())
            }
            ChallengeStatus::Proven => {
                stdlib::WriteStorage::__set(ctx, base_path.push("proven"), ())
            }
            ChallengeStatus::Failed(inner) => {
                stdlib::WriteStorage::__set(ctx, base_path.push("failed"), inner)
            }
        }
    }
}
pub enum ChallengeStatusModel {
    Active,
    Proven,
    Failed(u64),
}
impl ChallengeStatusModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        stdlib::ReadStorage::__extend_path_with_match(
                &ctx,
                &base_path,
                &["active", "proven", "failed"],
            )
            .map(|path| match path {
                p if p.starts_with(base_path.push("active").as_ref()) => {
                    ChallengeStatusModel::Active
                }
                p if p.starts_with(base_path.push("proven").as_ref()) => {
                    ChallengeStatusModel::Proven
                }
                p if p.starts_with(base_path.push("failed").as_ref()) => {
                    ChallengeStatusModel::Failed(
                        stdlib::ReadStorage::__get(&ctx, base_path.push("failed"))
                            .unwrap(),
                    )
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Matching path not found"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> ChallengeStatus {
        match self {
            ChallengeStatusModel::Active => ChallengeStatus::Active,
            ChallengeStatusModel::Proven => ChallengeStatus::Proven,
            ChallengeStatusModel::Failed(inner) => ChallengeStatus::Failed(inner.clone()),
        }
    }
}
pub enum ChallengeStatusWriteModel {
    Active,
    Proven,
    Failed(u64),
}
impl ChallengeStatusWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        stdlib::ReadStorage::__extend_path_with_match(
                &ctx,
                &base_path,
                &["active", "proven", "failed"],
            )
            .map(|path| match path {
                p if p.starts_with(base_path.push("active").as_ref()) => {
                    ChallengeStatusWriteModel::Active
                }
                p if p.starts_with(base_path.push("proven").as_ref()) => {
                    ChallengeStatusWriteModel::Proven
                }
                p if p.starts_with(base_path.push("failed").as_ref()) => {
                    ChallengeStatusWriteModel::Failed(
                        stdlib::ReadStorage::__get(&ctx, base_path.push("failed"))
                            .unwrap(),
                    )
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Matching path not found"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> ChallengeStatus {
        match self {
            ChallengeStatusWriteModel::Active => ChallengeStatus::Active,
            ChallengeStatusWriteModel::Proven => ChallengeStatus::Proven,
            ChallengeStatusWriteModel::Failed(inner) => {
                ChallengeStatus::Failed(inner.clone())
            }
        }
    }
}
#[automatically_derived]
pub enum ChallengeStatusKind {
    Active,
    Proven,
    Failed,
}
#[automatically_derived]
#[doc(hidden)]
unsafe impl ::core::clone::TrivialClone for ChallengeStatusKind {}
#[automatically_derived]
impl ::core::clone::Clone for ChallengeStatusKind {
    #[inline]
    fn clone(&self) -> ChallengeStatusKind {
        *self
    }
}
#[automatically_derived]
impl ::core::marker::Copy for ChallengeStatusKind {}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for ChallengeStatusKind {}
#[automatically_derived]
impl ::core::cmp::PartialEq for ChallengeStatusKind {
    #[inline]
    fn eq(&self, other: &ChallengeStatusKind) -> bool {
        let __self_discr = ::core::intrinsics::discriminant_value(self);
        let __arg1_discr = ::core::intrinsics::discriminant_value(other);
        __self_discr == __arg1_discr
    }
}
#[automatically_derived]
impl ::core::cmp::Eq for ChallengeStatusKind {
    #[doc(hidden)]
    #[coverage(off)]
    fn assert_fields_are_eq(&self) {}
}
#[automatically_derived]
impl ::core::fmt::Debug for ChallengeStatusKind {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::write_str(
            f,
            match self {
                ChallengeStatusKind::Active => "Active",
                ChallengeStatusKind::Proven => "Proven",
                ChallengeStatusKind::Failed => "Failed",
            },
        )
    }
}
#[automatically_derived]
impl ChallengeStatusKind {
    /// The discriminant's index-bucket key (lowercased case name).
    pub fn index_key_str(&self) -> &'static str {
        match self {
            ChallengeStatusKind::Active => "active",
            ChallengeStatusKind::Proven => "proven",
            ChallengeStatusKind::Failed => "failed",
        }
    }
}
#[automatically_derived]
impl core::convert::From<&ChallengeStatus> for ChallengeStatusKind {
    fn from(value: &ChallengeStatus) -> Self {
        match value {
            ChallengeStatus::Active => ChallengeStatusKind::Active,
            ChallengeStatus::Proven => ChallengeStatusKind::Proven,
            ChallengeStatus::Failed(..) => ChallengeStatusKind::Failed,
        }
    }
}
#[automatically_derived]
impl core::convert::From<ChallengeStatus> for ChallengeStatusKind {
    fn from(value: ChallengeStatus) -> Self {
        <ChallengeStatusKind as core::convert::From<&ChallengeStatus>>::from(&value)
    }
}
#[automatically_derived]
impl stdlib::IndexKey for ChallengeStatusKind {
    fn index_key(&self) -> alloc::borrow::Cow<'static, str> {
        alloc::borrow::Cow::Borrowed(self.index_key_str())
    }
}
#[automatically_derived]
impl stdlib::IndexKey for ChallengeStatus {
    fn index_key(&self) -> alloc::borrow::Cow<'static, str> {
        stdlib::IndexKey::index_key(&ChallengeStatusKind::from(self))
    }
}
