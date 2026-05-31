#![no_std]
contract!(name = "congestion");

use stdlib::*;

// ─────────────────────────────────────────────────────────────────
// Congestion-pricing parameters (economics spec §Congestion Pricing).
//   β(t) = ⎧ β(t-1)·λ_decay                                if u < u_low
//          ⎨ max(S(x), β(t-1)·λ_decay)                      if u_low ≤ u < u_high
//          ⎩ max(β(t-1), 1)·(1 + κ_cong·(u - u_high))       if u ≥ u_high
//   x = (u - u_low)/(u_high - u_low),  S(x) = 3x² - 2x³  (smoothstep)
//   Fee = φ_base · β
// ─────────────────────────────────────────────────────────────────

const BPS_DENOM: u64 = 10_000;

/// Lower utilization threshold (β decays toward 0 below it). 20%.
const DEFAULT_U_LOW_BPS: u64 = 2_000;
/// Upper utilization threshold (β grows multiplicatively above it). 80%.
const DEFAULT_U_HIGH_BPS: u64 = 8_000;
/// Per-block decay factor when u < u_low. 0.95.
const DEFAULT_LAMBDA_DECAY_BPS: u64 = 9_500;
/// Congestion growth rate above u_high. 2.0.
const DEFAULT_KAPPA_CONG_BPS: u64 = 20_000;
/// Smart-contract base fee φ_base (KOR per gas unit), calibrated in
/// Documentation `modeling/analyses/12`. 2.5e-7.
const DEFAULT_PHI_BASE: &str = "0.00000025";

#[derive(Clone, Default, StorageRoot)]
struct CongestionState {
    /// Current congestion multiplier β(t).
    pub beta: Decimal,
    pub u_low_bps: u64,
    pub u_high_bps: u64,
    pub lambda_decay_bps: u64,
    pub kappa_cong_bps: u64,
    /// φ_base, the KOR-per-gas numeraire (fixed-point, not bps).
    pub phi_base: Decimal,
}

impl Guest for Congestion {
    fn init(ctx: &ProcContext) -> Contract {
        let zero: Decimal = 0u64.try_into().expect("zero fits in Decimal");
        let phi_base: Decimal = DEFAULT_PHI_BASE.into();
        CongestionState {
            // β starts at 0: at genesis utilization is low, fees ≈ 0.
            beta: zero,
            u_low_bps: DEFAULT_U_LOW_BPS,
            u_high_bps: DEFAULT_U_HIGH_BPS,
            lambda_decay_bps: DEFAULT_LAMBDA_DECAY_BPS,
            kappa_cong_bps: DEFAULT_KAPPA_CONG_BPS,
            phi_base,
        }
        .init(ctx);
        ctx.contract()
    }

    /// Advance β from the prior block's `utilization` (a fraction in [0,1]).
    /// Core-context: the reactor calls this once per block.
    fn update_beta(ctx: &CoreContext, utilization: Decimal) -> Result<Decimal, Error> {
        let model = ctx.proc_context().model();
        let denom: Decimal = BPS_DENOM.try_into()?;
        let u_low = bps_to_decimal(model.u_low_bps(), denom)?;
        let u_high = bps_to_decimal(model.u_high_bps(), denom)?;
        let lambda_decay = bps_to_decimal(model.lambda_decay_bps(), denom)?;
        let kappa_cong = bps_to_decimal(model.kappa_cong_bps(), denom)?;

        let beta = beta_step(
            model.beta(),
            utilization,
            u_low,
            u_high,
            lambda_decay,
            kappa_cong,
        )?;
        model.set_beta(beta);
        Ok(beta)
    }

    fn get_beta(ctx: &ViewContext) -> Decimal {
        ctx.model().beta()
    }

    /// φ_base · β — the gas-fee multiplier the runtime applies per unit of gas.
    fn fee_multiplier(ctx: &ViewContext) -> Result<Decimal, Error> {
        let model = ctx.model();
        model.phi_base().mul(model.beta())
    }

    fn get_congestion_params(ctx: &ViewContext) -> CongestionParams {
        let model = ctx.model();
        CongestionParams {
            u_low_bps: model.u_low_bps(),
            u_high_bps: model.u_high_bps(),
            lambda_decay_bps: model.lambda_decay_bps(),
            kappa_cong_bps: model.kappa_cong_bps(),
            phi_base: model.phi_base(),
        }
    }

    fn set_congestion_params(ctx: &CoreContext, params: CongestionParams) -> Result<(), Error> {
        if params.u_low_bps >= params.u_high_bps {
            return Err(Error::Message("u_low_bps must be < u_high_bps".to_string()));
        }
        if params.u_high_bps > BPS_DENOM {
            return Err(Error::Message("u_high_bps must be <= 10000".to_string()));
        }
        let model = ctx.proc_context().model();
        model.set_u_low_bps(params.u_low_bps);
        model.set_u_high_bps(params.u_high_bps);
        model.set_lambda_decay_bps(params.lambda_decay_bps);
        model.set_kappa_cong_bps(params.kappa_cong_bps);
        model.set_phi_base(params.phi_base);
        Ok(())
    }
}

fn bps_to_decimal(bps: u64, denom: Decimal) -> Result<Decimal, Error> {
    let v: Decimal = bps.try_into()?;
    v.div(denom)
}

/// One step of the β(t) recurrence. Pure deterministic fixed-point math.
fn beta_step(
    beta_prev: Decimal,
    u: Decimal,
    u_low: Decimal,
    u_high: Decimal,
    lambda_decay: Decimal,
    kappa_cong: Decimal,
) -> Result<Decimal, Error> {
    if u < u_low {
        // Region 1 (free): decay toward 0.
        return beta_prev.mul(lambda_decay);
    }
    if u < u_high {
        // Region 2 (smoothstep ramp): max(S(x), decayed).
        // x = (u - u_low)/(u_high - u_low) ∈ [0,1); S(x) = 3x² - 2x³ = x²(3 - 2x).
        let x = u.sub(u_low)?.div(u_high.sub(u_low)?)?;
        let three: Decimal = 3u64.try_into()?;
        let two: Decimal = 2u64.try_into()?;
        let s = x.mul(x)?.mul(three.sub(two.mul(x)?)?)?;
        let decayed = beta_prev.mul(lambda_decay)?;
        return Ok(if s > decayed { s } else { decayed });
    }
    // Region 3 (multiplicative growth): max(β, 1)·(1 + κ·(u - u_high)).
    let one: Decimal = 1u64.try_into()?;
    let base = if beta_prev > one { beta_prev } else { one };
    let growth = one.add(kappa_cong.mul(u.sub(u_high)?)?)?;
    base.mul(growth)
}
