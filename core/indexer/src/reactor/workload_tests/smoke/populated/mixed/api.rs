use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use indexer_types::{Inst, OpStatus, OpWithResult};

use super::{GAS_LIMIT, MixedWorkload};

pub(in super::super) struct ApiRecipe {
    recipe: MixedWorkload,
    payer: u64,
    per_request: usize,
    instructions: Vec<Inst>,
}

impl ApiRecipe {
    pub(in super::super) fn file_ids(&self) -> Vec<String> {
        self.recipe.file_ids()
    }
    pub(in super::super) fn new(
        canonical: &MixedWorkload,
        payer: u64,
        requests: usize,
        per_request: usize,
    ) -> Result<Self> {
        ensure!(matches!(per_request, 2 | 4));
        let operations = requests
            .checked_mul(per_request)
            .context("API mix overflow")?;
        ensure!(operations >= 40 && operations.is_multiple_of(20));
        let mut recipe = canonical.clone();
        recipe.rounds = operations / 20;
        recipe.file_round_start = 0;
        recipe.stakes_before.clear();
        recipe.files = Some(
            canonical
                .files()?
                .api_descriptors(recipe.rounds * if per_request == 2 { 1 } else { 2 })?,
        );
        let instructions = recipe.instructions();
        Ok(Self {
            recipe,
            payer,
            per_request,
            instructions,
        })
    }

    pub(in super::super) fn instructions(&self, request: usize) -> Result<&[Inst]> {
        let start = request
            .checked_mul(self.per_request)
            .context("API index overflow")?;
        let end = start
            .checked_add(self.per_request)
            .context("API index overflow")?;
        self.instructions
            .get(start..end)
            .context("API horizon exhausted")
    }

    pub(in super::super) fn check(
        &self,
        request: usize,
        height: u64,
        txid: &str,
        results: &[OpWithResult],
    ) -> Result<()> {
        self.instructions(request)?;
        ensure!(results.len() == self.per_request);
        // This signer is never used by canonical inputs. Every request begins
        // without a bond and all speculative deposits must roll back.
        let mut stakes = BTreeMap::new();
        for (offset, result) in results.iter().enumerate() {
            let index = request * self.per_request + offset;
            let slot = index % 20;
            ensure!(result.op().is_some() && result.error_message().is_none());
            let root = result
                .result()
                .context("API operation omitted its result")?;
            let nested = matches!(slot, 13..=15)
                || (matches!(slot, 16..=17) && self.recipe.file_index(index / 20, slot).is_none());
            ensure!(
                root.height == height
                    && root.tx_index == Some(0)
                    && root.input_index == Some(0)
                    && root.op_index == Some(u32::try_from(offset)?)
                    && root.result_index == u32::from(nested)
                    && root.txid.as_deref() == Some(txid)
                    && root.signer_id == self.payer
                    && root.payer_signer_id == Some(self.payer)
                    && root.gas > 0
                    && root.gas <= GAS_LIMIT
                    && root.status
                        == if matches!(slot, 11..=12) {
                            OpStatus::ContractErr
                        } else {
                            OpStatus::Ok
                        },
                "timed API result identity or outcome changed"
            );
            self.recipe
                .check_return(root, index, self.payer, &mut stakes)?;
        }
        Ok(())
    }
}
