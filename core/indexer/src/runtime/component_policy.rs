use anyhow::{Result, bail};
use wasmparser::{
    CanonicalFunction, ComponentDefinedType, ComponentType, ComponentTypeDeclaration,
    InstanceTypeDeclaration, Parser, Payload,
};

use super::ExecutionError;

pub(super) fn validate(bytes: &[u8]) -> Result<(), ExecutionError> {
    validate_features(bytes).map_err(|error| {
        ExecutionError::Deterministic(error.context("contract component failed feature policy"))
    })
}

fn validate_features(bytes: &[u8]) -> Result<()> {
    // Surface WIT omits internal operations. parse_all also visits embedded
    // components, so the policy applies before any user component is compiled.
    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::ComponentTypeSection(types) => {
                for ty in types {
                    validate_type(&ty?)?;
                }
            }
            Payload::ComponentCanonicalSection(functions) => {
                for function in functions {
                    match function? {
                        CanonicalFunction::StreamNew { .. }
                        | CanonicalFunction::StreamRead { .. }
                        | CanonicalFunction::StreamWrite { .. }
                        | CanonicalFunction::StreamCancelRead { .. }
                        | CanonicalFunction::StreamCancelWrite { .. }
                        | CanonicalFunction::StreamDropReadable { .. }
                        | CanonicalFunction::StreamDropWritable { .. } => {
                            bail!("stream operations are not supported in user contracts");
                        }
                        CanonicalFunction::FutureNew { .. }
                        | CanonicalFunction::FutureRead { .. }
                        | CanonicalFunction::FutureWrite { .. }
                        | CanonicalFunction::FutureCancelRead { .. }
                        | CanonicalFunction::FutureCancelWrite { .. }
                        | CanonicalFunction::FutureDropReadable { .. }
                        | CanonicalFunction::FutureDropWritable { .. } => {
                            bail!("future operations are not supported in user contracts");
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_type(ty: &ComponentType<'_>) -> Result<()> {
    match ty {
        ComponentType::Defined(ComponentDefinedType::Stream(_)) => {
            bail!("stream types are not supported in user contracts");
        }
        ComponentType::Defined(ComponentDefinedType::Future(_)) => {
            bail!("future types are not supported in user contracts");
        }
        ComponentType::Component(declarations) => {
            for declaration in declarations {
                if let ComponentTypeDeclaration::Type(ty) = declaration {
                    validate_type(ty)?;
                }
            }
        }
        ComponentType::Instance(declarations) => {
            for declaration in declarations {
                if let InstanceTypeDeclaration::Type(ty) = declaration {
                    validate_type(ty)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use wasm_encoder::{
        CanonicalFunctionSection, CanonicalOption, Component,
        ComponentType as EncodedComponentType, ComponentTypeSection, InstanceType, Module,
        ModuleSection, NestedComponentSection, PrimitiveValType,
    };

    use super::{ExecutionError, validate};

    fn assert_rejected(component: &Component, expected: &str) {
        let error = validate(component.as_slice()).expect_err("policy must reject component");
        assert!(matches!(error, ExecutionError::Deterministic(_)));
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }

    #[test]
    fn rejects_unexported_stream_and_future_types() {
        for payload in [None, Some(PrimitiveValType::U8.into())] {
            let mut types = ComponentTypeSection::new();
            types.defined_type().stream(payload);
            let mut component = Component::new();
            component.section(&types);
            assert_rejected(&component, "stream types");

            let mut types = ComponentTypeSection::new();
            types.defined_type().future(payload);
            let mut component = Component::new();
            component.section(&types);
            assert_rejected(&component, "future types");
        }
    }

    #[test]
    fn rejects_types_in_nested_components_and_type_declarations() {
        let mut types = ComponentTypeSection::new();
        types.defined_type().stream(None);
        let mut nested = Component::new();
        nested.section(&types);
        let mut outer = Component::new();
        outer.section(&NestedComponentSection(&nested));
        assert_rejected(&outer, "stream types");

        let mut instance = InstanceType::new();
        instance.ty().defined_type().future(None);
        let mut component_type = EncodedComponentType::new();
        component_type.ty().instance(&instance);
        let mut types = ComponentTypeSection::new();
        types.component(&component_type);
        let mut component = Component::new();
        component.section(&types);
        assert_rejected(&component, "future types");
    }

    #[test]
    fn rejects_stream_and_future_operations_without_surface_exports() {
        // Omitting type definitions prevents a type rejection from masking a
        // missing operation check. Compilation still performs semantic validation.
        for index in 0..14 {
            let mut functions = CanonicalFunctionSection::new();
            let options = [CanonicalOption::Async];
            match index {
                0 => functions.stream_new(0),
                1 => functions.stream_read(0, options),
                2 => functions.stream_write(0, options),
                3 => functions.stream_cancel_read(0, true),
                4 => functions.stream_cancel_write(0, true),
                5 => functions.stream_drop_readable(0),
                6 => functions.stream_drop_writable(0),
                7 => functions.future_new(0),
                8 => functions.future_read(0, options),
                9 => functions.future_write(0, options),
                10 => functions.future_cancel_read(0, true),
                11 => functions.future_cancel_write(0, true),
                12 => functions.future_drop_readable(0),
                13 => functions.future_drop_writable(0),
                _ => unreachable!(),
            };
            let mut component = Component::new();
            component.section(&functions);
            let expected = if index < 7 {
                "stream operations"
            } else {
                "future operations"
            };
            assert_rejected(&component, expected);
            let mut outer = Component::new();
            outer.section(&NestedComponentSection(&component));
            assert_rejected(&outer, expected);
        }
    }

    #[test]
    fn permits_async_functions_and_core_modules() {
        let mut types = ComponentTypeSection::new();
        types
            .function()
            .async_(true)
            .params([("value", PrimitiveValType::String)])
            .result(None);
        let mut functions = CanonicalFunctionSection::new();
        functions.task_return(None, []);
        let mut component = Component::new();
        component.section(&ModuleSection(&Module::new()));
        component.section(&types);
        component.section(&functions);
        validate(component.as_slice())
            .expect("ordinary async component features must remain allowed");
    }

    #[test]
    fn malformed_policy_input_is_deterministic() {
        let error = validate(b"invalid component").expect_err("invalid binary must be rejected");
        assert!(matches!(error, ExecutionError::Deterministic(_)));
    }
}
