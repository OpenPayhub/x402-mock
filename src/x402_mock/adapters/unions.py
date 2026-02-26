"""
Blockchain Polymorphic Types (Discriminated Unions)

Defines type unions that automatically discriminate between blockchain-specific implementations
using discriminator fields (permit_type, payment_type, signature_type).

Pydantic's Discriminated Union automatically:
- Validates and selects the correct model based on the discriminator field value
- Provides type safety and IDE autocomplete for all variants
- Eliminates the need for manual type detection and conversion logic

To add support for new blockchains:
1. Define blockchain-specific models in their own module (e.g., svm/schemas.py)
2. Import and add them to the Union below
3. No additional registration or mapping code required

Example usage:
    # Pydantic automatically selects EIP2612Permit when permit_type="EIP2612"
    permit: Permit = Permit.model_validate({
        "permit_type": "EIP2612",
        "owner": "0x...",
        ...
    })
"""

from typing import Union, Dict, Type, Optional
from typing_extensions import Annotated
from pydantic import Field

from .evm.schemas import (
    ERC3009Authorization,
    EVMPaymentComponent,
    Permit2Signature,
    EVMECDSASignature,
    EVMVerificationResult,
    EVMTransactionConfirmation,
)
from ..schemas.bases import (
    BasePermit,
    BasePaymentComponent,
    BaseVerificationResult,
    BaseTransactionConfirmation,
)


# Discriminated Union for blockchain-specific permit types
# Automatically selects correct model based on 'permit_type' field value
# Current support: EIP2612 (EVM)
# Future: Add SolanaPermit, etc.
PermitTypes = Annotated[
    Union[
        ERC3009Authorization,  # permit_type: "ERC3009"
        Permit2Signature,      # permit_type: "Permit2"
    ],
    Field(discriminator='permit_type')
]


# Discriminated Union for blockchain-specific payment component types
# Automatically selects correct model based on 'payment_type' field value
# Current support: evm
# Future: Add SVMPaymentComponent, etc.
PaymentComponentTypes = Annotated[
    Union[
        EVMPaymentComponent,  # payment_type: "evm"
    ],
    Field(discriminator='payment_type')
]


# Discriminated Union for blockchain-specific signature types
# Automatically selects correct model based on 'signature_type' field value
# Current support: EIP2612
# Future: Add SolanaSignature, etc.
SignatureTypes = Annotated[
    Union[
        EVMECDSASignature,  # signature_type: "EIP2612"
    ],
    Field(discriminator='signature_type')
]


# Discriminated Union for blockchain-specific verification result types
# Automatically selects correct model based on 'verification_type' field value
# Current support: evm
# Future: Add SVMVerificationResult, etc.
VerificationResultTypes = Annotated[
    Union[
        EVMVerificationResult,  # verification_type: "evm"
    ],
    Field(discriminator='verification_type')
]


# Discriminated Union for blockchain-specific transaction confirmation types
# Automatically selects correct model based on 'confirmation_type' field value
# Current support: evm
# Future: Add SVMTransactionConfirmation, etc.
TransactionConfirmationTypes = Annotated[
    Union[
        EVMTransactionConfirmation,  # confirmation_type: "evm"
    ],
    Field(discriminator='confirmation_type')
]


# ============================================================================
# Adapter Type Registry
# ============================================================================

# Type mapping: discriminator values to unified adapter type strings
# Maps all discriminator values (permit_type, payment_type, signature_type) to
# standardized adapter type identifiers used in AdapterHub._adapter_factories
ADAPTER_TYPE_MAPPING: Dict[str, str] = {}


def _initialize_adapter_type_mapping():
    """
    Lazy initialization of adapter type mapping to avoid circular import issues.
    
    This function is called on first access to populate the type mapping with
    discriminator value to adapter type identifier mappings.
    """
    global ADAPTER_TYPE_MAPPING
    
    if ADAPTER_TYPE_MAPPING:
        return  # Already initialized
    
    # Map all discriminator values to unified adapter type identifier
    # This maps to the keys used in AdapterHub._adapter_factories
    ADAPTER_TYPE_MAPPING.update({
        "evm": "evm",               # EVM payment_type -> "evm"
        "ERC3009": "evm",           # ERC-3009 permit_type -> "evm"
        "Permit2": "evm",           # Permit2 permit_type -> "evm"
        "ethereum": "evm",          # Ethereum chain -> "evm"
        "polygon": "evm",           # Polygon chain -> "evm"
        "arbitrum": "evm",          # Arbitrum chain -> "evm"
    })
    
    # Future: Add Solana adapter type mapping
    # ADAPTER_TYPE_MAPPING.update({
    #     "solana": "svm",            # Solana payment_type -> "svm"
    #     "svm": "svm",               # SVM payment_type -> "svm"
    #     "spl": "svm",               # SPL permit_type -> "svm"
    # })


def get_adapter_type(
    obj: Union[
        PermitTypes,
        PaymentComponentTypes,
        SignatureTypes,
        VerificationResultTypes,
        TransactionConfirmationTypes,
        BasePermit,
        BasePaymentComponent,
        BaseVerificationResult,
        BaseTransactionConfirmation,
    ]
) -> Optional[str]:
    """
    Retrieve the unified adapter type identifier for a given permit, payment component, 
    signature, verification result, or transaction confirmation.
    
    Automatically extracts the type discriminator field (permit_type, payment_type, 
    signature_type, verification_type, or confirmation_type) from the object and returns 
    the standardized adapter type string that can be used as a key in 
    AdapterHub._adapter_factories.
    
    This function maps all blockchain-specific discriminator values to their unified
    adapter type identifiers (e.g., "EIP2612" -> "evm", "polygon" -> "evm", "spl" -> "svm").
    
    Args:
        obj: A permit, payment component, signature, verification result, or transaction
             confirmation instance containing a type discriminator field. Supports both 
             typed instances and base classes.
    
    Returns:
        The unified adapter type string (e.g., "evm", "svm") that corresponds to
        the object's blockchain type. Returns None if no matching adapter type is found.
    
    Examples:
        >>> # EIP-2612 permit maps to "evm"
        >>> permit = EIP2612Permit(permit_type="EIP2612", owner="0x...", ...)
        >>> adapter_type = get_adapter_type(permit)  # Returns "evm"
        >>> adapter = hub._adapter_factories[adapter_type]
        
        >>> # EVM payment component maps to "evm"
        >>> component = EVMPaymentComponent(payment_type="evm", token="0x...", ...)
        >>> adapter_type = get_adapter_type(component)  # Returns "evm"
        >>> adapter = hub._adapter_factories[adapter_type]
        
        >>> # EVM verification result maps to "evm"
        >>> result = EVMVerificationResult(verification_type="evm", ...)
        >>> adapter_type = get_adapter_type(result)  # Returns "evm"
        
        >>> # Polygon payment also maps to "evm"
        >>> component = EVMPaymentComponent(payment_type="polygon", ...)
        >>> adapter_type = get_adapter_type(component)  # Returns "evm"
    
    Note:
        The type mapping is lazily initialized on first call to avoid circular imports.
        To add support for new blockchains, update _initialize_adapter_type_mapping()
        with new type mappings in ADAPTER_TYPE_MAPPING.
    """
    # Lazy initialization of type mapping
    _initialize_adapter_type_mapping()
    
    # Extract type discriminator from object
    # Try all possible discriminator fields in order of likelihood
    type_value = (
        getattr(obj, 'permit_type', None) or
        getattr(obj, 'payment_type', None) or
        getattr(obj, 'signature_type', None) or
        getattr(obj, 'verification_type', None) or
        getattr(obj, 'confirmation_type', None)
    )
    
    if not type_value:
        return None
    
    return ADAPTER_TYPE_MAPPING.get(type_value)

