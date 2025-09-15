use stdlib::*;

contract!(name = "token");

// Asset management types and traits for this contract
/// An InFlightBalance represents a quantity of this token that has been
/// withdrawn from its ledger and is now "in-flight" for the duration of a transaction.
#[derive(Debug)]
#[must_use = "in-flight balances must be deposited or explicitly handled"]
pub struct InFlightBalance {
    token_addr: foreign::ContractAddress,
    amount: numbers::Integer,
    _private: (),
}

impl InFlightBalance {
    /// Creates a new InFlightBalance. Only callable within this module.
    fn new(token_addr: foreign::ContractAddress, amount: numbers::Integer) -> Self {
        Self { 
            token_addr, 
            amount, 
            _private: () 
        }
    }

    /// Consumes the InFlightBalance, returning its constituent parts.
    pub fn into_value(self) -> (foreign::ContractAddress, numbers::Integer) {
        (self.token_addr, self.amount)
    }

    /// Returns the amount without consuming the balance.
    pub fn amount(&self) -> numbers::Integer {
        self.amount
    }
}

/// The Asset trait defines the interface for tokens that support resource-like semantics.
pub trait Asset {
    /// Returns the contract address for this asset.
    fn contract_address() -> foreign::ContractAddress;

    /// Withdraws the specified amount from the caller's balance, returning an InFlightBalance.
    fn withdraw(ctx: &ProcContext, amount: numbers::Integer) -> Result<InFlightBalance, error::Error>;

    /// Deposits an InFlightBalance into the specified recipient's account.
    fn deposit(ctx: &ProcContext, recipient: String, balance: InFlightBalance) -> Result<(), error::Error>;
}

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, numbers::Integer>,
    pub operators: Map<String, bool>, // "owner:operator" -> approved (flattened)
    pub total_supply: numbers::Integer,
}

// Implement the Asset trait for Token
impl Asset for Token {
    fn contract_address() -> foreign::ContractAddress {
        // For now, return a placeholder. In a real implementation, this would
        // need to be set during contract initialization or derived from context.
        foreign::ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 1, // This would need to be the actual deployed address
        }
    }

    fn withdraw(ctx: &ProcContext, amount: numbers::Integer) -> Result<InFlightBalance, error::Error> {
        let owner = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let balance = ledger.get(ctx, &owner).unwrap_or_default();

        if balance < amount {
            return Err(error::Error::Message("insufficient funds".to_string()));
        }

        // Decrease ledger balance
        ledger.set(ctx, owner, numbers::sub_integer(balance, amount));
        
        // Return the in-flight balance
        Ok(InFlightBalance::new(Self::contract_address(), amount))
    }

    fn deposit(ctx: &ProcContext, recipient: String, balance: InFlightBalance) -> Result<(), error::Error> {
        let (token_addr, amount) = balance.into_value();

        // Security check: ensure the InFlightBalance originated from THIS token contract
        if token_addr != Self::contract_address() {
            return Err(error::Error::Message("invalid balance object for this token".to_string()));
        }

        let ledger = storage(ctx).ledger();
        let recipient_balance = ledger.get(ctx, &recipient).unwrap_or_default();
        ledger.set(ctx, recipient, numbers::add_integer(recipient_balance, amount));

        Ok(())
    }
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn mint(ctx: &ProcContext, n: numbers::Integer) {
        let to = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let current_supply = storage(ctx).total_supply(ctx);

        let balance = ledger.get(ctx, &to).unwrap_or_default();
        ledger.set(ctx, to, numbers::add_integer(balance, n));

        storage(ctx).set_total_supply(ctx, numbers::add_integer(current_supply, n));
    }

    fn transfer(ctx: &ProcContext, to: String, n: numbers::Integer) -> Result<(), error::Error> {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let from_balance = ledger.get(ctx, &from).unwrap_or_default();
        let to_balance = ledger.get(ctx, &to).unwrap_or_default();

        if from_balance < n {
            return Err(error::Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, numbers::sub_integer(from_balance, n));
        ledger.set(ctx, to, numbers::add_integer(to_balance, n));
        Ok(())
    }

    fn set_operator(ctx: &ProcContext, operator: String, approved: u64) -> Result<(), error::Error> {
        let owner = ctx.signer().to_string();
        let operators = storage(ctx).operators();

        let key = format!("{}:{}", owner, operator);
        operators.set(ctx, key, approved != 0);

        Ok(())
    }

    fn is_operator(ctx: &ViewContext, owner: String, operator: String) -> u64 {
        let operators = storage(ctx).operators();
        let key = format!("{}:{}", owner, operator);
        if operators.get(ctx, key).unwrap_or(false) { 1 } else { 0 }
    }

    fn transfer_as_operator(ctx: &ProcContext, owner: String, to: String, amount: numbers::Integer) -> Result<(), error::Error> {
        let operator = ctx.signer().to_string();
        let operators = storage(ctx).operators();
        let ledger = storage(ctx).ledger();
        
        // Check operator permission
        let operator_key = format!("{}:{}", owner, operator);
        if !operators.get(ctx, &operator_key).unwrap_or(false) {
            return Err(error::Error::Message("not an approved operator".to_string()));
        }
        
        // Check balance
        let owner_balance = ledger.get(ctx, &owner).unwrap_or_default();
        if owner_balance < amount {
            return Err(error::Error::Message("insufficient funds".to_string()));
        }
        
        // Update balances
        let to_balance = ledger.get(ctx, &to).unwrap_or_default();
        ledger.set(ctx, owner, numbers::sub_integer(owner_balance, amount));
        ledger.set(ctx, to, numbers::add_integer(to_balance, amount));
        
        Ok(())
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<numbers::Integer> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc)
    }
    
    fn balance_or_zero(ctx: &ViewContext, acc: String) -> numbers::Integer {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc).unwrap_or_default()
    }
    
    fn total_supply(ctx: &ViewContext) -> numbers::Integer {
        storage(ctx).total_supply(ctx)
    }

    fn balance_log10(ctx: &ViewContext, acc: String) -> Option<numbers::Decimal> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc).map(|i| numbers::log10(numbers::integer_to_decimal(i)))
    }
    
    // Asset management functions - bridge between WIT and our Asset trait
    fn withdraw(ctx: &ProcContext, amount: numbers::Integer) -> Result<Balance, error::Error> {
        let in_flight = <Token as Asset>::withdraw(ctx, amount)?;
        let (token_addr, amount) = in_flight.into_value();
        
        // Convert InFlightBalance to WIT Balance
        Ok(Balance {
            token_addr,
            amount,
        })
    }
    
    fn deposit(ctx: &ProcContext, recipient: String, balance: Balance) -> Result<(), error::Error> {
        // Convert WIT Balance to InFlightBalance
        let in_flight = InFlightBalance::new(balance.token_addr, balance.amount);
        
        <Token as Asset>::deposit(ctx, recipient, in_flight)
    }
}