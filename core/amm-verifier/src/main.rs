use z3::{
    ast::{Ast, Int},
    Config, Context, SatResult, Solver,
};

fn constant_product(ctx: &Context) {
    let reserve_a = Int::new_const(ctx, "reserve_a");
    let reserve_b = Int::new_const(ctx, "reserve_b");
    let amount_in = Int::new_const(ctx, "amount_in");

    let fee_num = Int::from_i64(ctx, 997);
    let thousand = Int::from_i64(ctx, 1000);
    let amount_in_fee = amount_in.clone() * fee_num.clone();
    let num = amount_in_fee.clone() * reserve_b.clone();
    let den = reserve_a.clone() * thousand + amount_in_fee.clone();
    let amount_out = num / den;

    let lhs = (reserve_a.clone() + amount_in.clone()) * (reserve_b.clone() - amount_out.clone());
    let rhs = reserve_a.clone() * reserve_b.clone();

    let solver = Solver::new(ctx);
    solver.assert(&reserve_a.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&reserve_b.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&amount_in.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&lhs.lt(&rhs));

    match solver.check() {
        SatResult::Unsat => println!("constant product preserved"),
        SatResult::Sat => println!("counterexample: {}", solver.get_model().unwrap()),
        SatResult::Unknown => println!("solver returned Unknown"),
    }
}

fn no_overdraw(ctx: &Context) {
    let reserve_a = Int::new_const(ctx, "reserve_a_n");
    let reserve_b = Int::new_const(ctx, "reserve_b_n");
    let amount_in = Int::new_const(ctx, "amount_in_n");

    let fee_num = Int::from_i64(ctx, 997);
    let thousand = Int::from_i64(ctx, 1000);
    let amount_in_fee = amount_in.clone() * fee_num.clone();
    let num = amount_in_fee.clone() * reserve_b.clone();
    let den = reserve_a.clone() * thousand + amount_in_fee.clone();
    let amount_out = num / den;

    let solver = Solver::new(ctx);
    solver.assert(&reserve_a.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&reserve_b.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&amount_in.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&amount_out.ge(&reserve_b));

    match solver.check() {
        SatResult::Unsat => println!("swap cannot overdraw token B"),
        SatResult::Sat => println!("overdraw model: {}", solver.get_model().unwrap()),
        SatResult::Unknown => println!("solver returned Unknown"),
    }
}

fn liquidity_removal_counterexample(ctx: &Context) {
    let reserve_a = Int::new_const(ctx, "reserve_a_l");
    let reserve_b = Int::new_const(ctx, "reserve_b_l");
    let total_shares = Int::new_const(ctx, "total_shares");
    let share = Int::new_const(ctx, "share");

    let amount_a = reserve_a.clone() * share.clone() / total_shares.clone();
    let amount_b = reserve_b.clone() * share.clone() / total_shares.clone();
    let reserve_a_after = reserve_a.clone() - amount_a.clone();
    let reserve_b_after = reserve_b.clone() - amount_b.clone();

    let solver = Solver::new(ctx);
    solver.assert(&reserve_a.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&reserve_b.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&total_shares.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&share.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&total_shares.gt(&share));
    solver.assert(&reserve_a_after.gt(&Int::from_i64(ctx, 0)));
    solver.assert(&reserve_b_after.gt(&Int::from_i64(ctx, 0)));
    let neq = (reserve_a.clone() * reserve_b_after.clone())
        ._eq(&(reserve_b.clone() * reserve_a_after.clone()))
        .not();
    solver.assert(&neq);

    match solver.check() {
        SatResult::Sat => println!(
            "liquidity removal counterexample: {}",
            solver.get_model().unwrap()
        ),
        SatResult::Unsat => println!("no rounding counterexample found"),
        SatResult::Unknown => println!("solver returned Unknown"),
    }
}

fn main() {
    let mut cfg = Config::new();
    cfg.set_model_generation(true);
    let ctx = Context::new(&cfg);

    constant_product(&ctx);
    no_overdraw(&ctx);
    liquidity_removal_counterexample(&ctx);
}
