use stdlib::Storage;
#[index(cheapest, by = active, sort = price, include = (title, seller))]
#[index(by_seller, by = seller, include = (price))]
struct Listing {
    active: bool,
    price: u64,
    title: String,
    seller: u64,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for Listing {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
        value: Listing,
    ) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.active);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(1u8), value.price);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(2u8), value.title);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(3u8), value.seller);
    }
}
pub struct ListingModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl ListingModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let __idx_active = self.active();
        let __idx_price = self.price();
        let __idx_title = self.title();
        let __idx_seller = self.seller();
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name_id: 0u8,
                bucket: (/*ERROR*/),
                sort: Some(stdlib::KeyElement::encode(&__idx_price)),
                projection: {
                    let mut __proj = alloc::vec::Vec::new();
                    __proj.extend_from_slice(&stdlib::KeyElement::encode(&__idx_title));
                    __proj.extend_from_slice(&stdlib::KeyElement::encode(&__idx_seller));
                    Some(__proj)
                },
            });
        entries
            .push(stdlib::IndexEntry {
                name_id: 1u8,
                bucket: (/*ERROR*/),
                sort: None,
                projection: {
                    let mut __proj = alloc::vec::Vec::new();
                    __proj.extend_from_slice(&stdlib::KeyElement::encode(&__idx_price));
                    Some(__proj)
                },
            });
        entries
    }
    pub fn active(&self) -> bool {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn price(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn title(&self) -> String {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(2u8)).unwrap()
    }
    pub fn seller(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(3u8)).unwrap()
    }
    pub fn load(&self) -> Listing {
        Listing {
            active: self.active(),
            price: self.price(),
            title: self.title(),
            seller: self.seller(),
        }
    }
}
pub struct ListingWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: ListingModel,
}
impl ListingWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: ListingModel::new(alloc::rc::Rc::new(view_storage), base_path.clone()),
        }
    }
    pub fn with_index(
        mut self,
        index_root: stdlib::KeyPath,
        index_key: alloc::vec::Vec<u8>,
    ) -> Self {
        self.index_binding = Some((index_root, index_key));
        self
    }
    pub fn active(&self) -> bool {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn price(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn title(&self) -> String {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(2u8)).unwrap()
    }
    pub fn seller(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(3u8)).unwrap()
    }
    pub fn set_active(&self, value: bool) {
        let path = self.base_path.push_interned(0u8);
        let old: bool = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_price = self.price();
            let __idx_title = self.title();
            let __idx_seller = self.seller();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_price)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_price)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_active(&self, f: impl Fn(bool) -> bool) {
        let path = self.base_path.push_interned(0u8);
        let old: bool = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_price = self.price();
            let __idx_title = self.title();
            let __idx_seller = self.seller();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_price)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_price)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_active(
        &self,
        f: impl Fn(bool) -> Result<bool, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: bool = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_price = self.price();
            let __idx_title = self.title();
            let __idx_seller = self.seller();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_price)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_price)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_price(&self, value: u64) {
        let path = self.base_path.push_interned(1u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_active = self.active();
            let __idx_title = self.title();
            let __idx_seller = self.seller();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_price(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(1u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_active = self.active();
            let __idx_title = self.title();
            let __idx_seller = self.seller();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_price(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(1u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_active = self.active();
            let __idx_title = self.title();
            let __idx_seller = self.seller();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_title),
                                );
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_seller),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_title(&self, value: String) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(2u8), value);
    }
    pub fn update_title(&self, f: impl Fn(String) -> String) {
        let path = self.base_path.push_interned(2u8);
        let old: String = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_title(
        &self,
        f: impl Fn(String) -> Result<String, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(2u8);
        let old: String = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_seller(&self, value: u64) {
        let path = self.base_path.push_interned(3u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_price = self.price();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_price),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_price),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_seller(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(3u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_price = self.price();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_price),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_price),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_seller(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(3u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_price = self.price();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_price),
                                );
                            Some(__proj)
                        },
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: {
                            let mut __proj = alloc::vec::Vec::new();
                            __proj
                                .extend_from_slice(
                                    &stdlib::KeyElement::encode(&__idx_price),
                                );
                            Some(__proj)
                        },
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> Listing {
        Listing {
            active: self.active(),
            price: self.price(),
            title: self.title(),
            seller: self.seller(),
        }
    }
}
impl core::ops::Deref for ListingWriteModel {
    type Target = ListingModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
#[automatically_derived]
impl stdlib::Indexed for Listing {
    const HAS_INDEXES: bool = true;
    fn index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name_id: 0u8,
                bucket: (/*ERROR*/),
                sort: Some(stdlib::KeyElement::encode(&self.price)),
                projection: {
                    let mut __proj = alloc::vec::Vec::new();
                    __proj.extend_from_slice(&stdlib::KeyElement::encode(&self.title));
                    __proj.extend_from_slice(&stdlib::KeyElement::encode(&self.seller));
                    Some(__proj)
                },
            });
        entries
            .push(stdlib::IndexEntry {
                name_id: 1u8,
                bucket: (/*ERROR*/),
                sort: None,
                projection: {
                    let mut __proj = alloc::vec::Vec::new();
                    __proj.extend_from_slice(&stdlib::KeyElement::encode(&self.price));
                    Some(__proj)
                },
            });
        entries
    }
}
pub struct ListingCheapestValue {
    pub price: u64,
    pub title: String,
    pub seller: u64,
}
#[automatically_derived]
impl ::core::clone::Clone for ListingCheapestValue {
    #[inline]
    fn clone(&self) -> ListingCheapestValue {
        ListingCheapestValue {
            price: ::core::clone::Clone::clone(&self.price),
            title: ::core::clone::Clone::clone(&self.title),
            seller: ::core::clone::Clone::clone(&self.seller),
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for ListingCheapestValue {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field3_finish(
            f,
            "ListingCheapestValue",
            "price",
            &self.price,
            "title",
            &self.title,
            "seller",
            &&self.seller,
        )
    }
}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for ListingCheapestValue {}
#[automatically_derived]
impl ::core::cmp::PartialEq for ListingCheapestValue {
    #[inline]
    fn eq(&self, other: &ListingCheapestValue) -> bool {
        self.price == other.price && self.seller == other.seller
            && self.title == other.title
    }
}
impl ListingCheapestValue {
    /// Rebuild the covered value from a leaf's raw projection bytes (and,
    /// for a sorted index, the member's sort value). The `build` fn the
    /// covering query calls per row — generated, not called directly.
    #[doc(hidden)]
    pub fn __from_covering(sort: &u64, __proj: &[u8]) -> Self {
        let (title, __proj) = <String as stdlib::KeyElement>::decode_from(__proj)
            .expect("covering projection decodes into its declared field types");
        let (seller, __proj) = <u64 as stdlib::KeyElement>::decode_from(__proj)
            .expect("covering projection decodes into its declared field types");
        let _ = __proj;
        Self {
            price: sort.clone(),
            title,
            seller,
        }
    }
}
pub struct ListingBySellerValue {
    pub price: u64,
}
#[automatically_derived]
impl ::core::clone::Clone for ListingBySellerValue {
    #[inline]
    fn clone(&self) -> ListingBySellerValue {
        ListingBySellerValue {
            price: ::core::clone::Clone::clone(&self.price),
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for ListingBySellerValue {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field1_finish(
            f,
            "ListingBySellerValue",
            "price",
            &&self.price,
        )
    }
}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for ListingBySellerValue {}
#[automatically_derived]
impl ::core::cmp::PartialEq for ListingBySellerValue {
    #[inline]
    fn eq(&self, other: &ListingBySellerValue) -> bool {
        self.price == other.price
    }
}
impl ListingBySellerValue {
    /// Rebuild the covered value from a leaf's raw projection bytes (and,
    /// for a sorted index, the member's sort value). The `build` fn the
    /// covering query calls per row — generated, not called directly.
    #[doc(hidden)]
    pub fn __from_covering(__proj: &[u8]) -> Self {
        let (price, __proj) = <u64 as stdlib::KeyElement>::decode_from(__proj)
            .expect("covering projection decodes into its declared field types");
        let _ = __proj;
        Self { price }
    }
}
pub trait ListingIndex<K>: stdlib::IndexScan<K> + Sized
where
    K: stdlib::KeyElement + Clone + 'static,
{
    fn cheapest(
        &self,
        active: bool,
    ) -> stdlib::SortedCoveringQuery<'_, K, u64, ListingCheapestValue, Self> {
        let __b0 = stdlib::IndexKey::index_key(&active);
        stdlib::SortedCoveringQuery::new(
            self,
            0u8,
            alloc::vec::Vec::from([__b0]),
            ListingCheapestValue::__from_covering,
        )
    }
    fn by_seller(
        &self,
        seller: u64,
    ) -> stdlib::CoveringQuery<'_, K, ListingBySellerValue, Self> {
        let __b0 = stdlib::IndexKey::index_key(&seller);
        stdlib::CoveringQuery::new(
            self,
            1u8,
            alloc::vec::Vec::from([__b0]),
            ListingBySellerValue::__from_covering,
        )
    }
}
