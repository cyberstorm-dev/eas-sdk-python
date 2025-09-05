#!/usr/bin/env python3
"""
Multi-Chain EAS SDK Usage Examples

This script demonstrates how to use the EAS Python SDK with comprehensive
multi-chain support, including the factory methods and configuration system.
"""

import os
import sys

# Add the src directory to the path
sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src", "main")
)


def demonstrate_config_system():
    """Demonstrate the configuration system."""
    print("=" * 70)
    print("📋 CONFIGURATION SYSTEM EXAMPLES")
    print("=" * 70)

    # Import config functions directly to avoid dependency issues in demo
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "config",
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "src",
            "main",
            "EAS",
            "config.py",
        ),
    )
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)

    # Example 1: List all supported chains
    print("1. List all supported chains:")
    all_chains = config.list_supported_chains()
    print(f"   Total chains: {len(all_chains)}")
    print(f"   Chains: {', '.join(all_chains)}")
    print()

    # Example 2: Get mainnet vs testnet chains
    print("2. Filter by network type:")
    mainnet_chains = config.get_mainnet_chains()
    testnet_chains = config.get_testnet_chains()
    print(f"   Mainnet chains: {', '.join(mainnet_chains)}")
    print(f"   Testnet chains: {', '.join(testnet_chains)}")
    print()

    # Example 3: Get chain configurations
    print("3. Get chain configurations:")
    sample_chains = ["ethereum", "base", "sepolia", "arbitrum"]
    for chain in sample_chains:
        chain_config = config.get_network_config(chain)
        print(f"   {chain}:")
        print(f"     - Chain ID: {chain_config['chain_id']}")
        print(f"     - Contract: {chain_config['contract_address']}")
        print(f"     - Network Type: {chain_config['network_type']}")
        print(f"     - Explorer: {chain_config['explorer_url']}")
    print()

    # Example 4: Error handling
    print("4. Error handling example:")
    try:
        config.get_network_config("nonexistent_network")
    except ValueError as e:
        print(f"   ✓ Correctly handled invalid network: {str(e)[:50]}...")
    print()


def demonstrate_factory_methods():
    """Demonstrate the factory methods (concept only due to dependencies)."""
    print("=" * 70)
    print("🏭 FACTORY METHODS EXAMPLES")
    print("=" * 70)

    print("1. EAS.from_chain() method usage:")
    print(
        """
   # Create EAS instance for Ethereum mainnet
   eas = EAS.from_chain(
       chain_name='ethereum',
       private_key='0x1234567890abcdef...',
       from_account='0x1234567890123456789012345678901234567890'
   )

   # Create EAS instance for Base with custom RPC
   eas = EAS.from_chain(
       chain_name='base',
       private_key='0x1234567890abcdef...',
       from_account='0x1234567890123456789012345678901234567890',
       rpc_url='https://my-custom-base-rpc.com'
   )

   # Create EAS instance for Sepolia testnet
   eas = EAS.from_chain(
       chain_name='sepolia',
       private_key='0x1234567890abcdef...',
       from_account='0x1234567890123456789012345678901234567890'
   )
    """
    )

    print("2. EAS.from_environment() method usage:")
    print(
        """
   # Set environment variables:
   export EAS_CHAIN=ethereum
   export EAS_PRIVATE_KEY=0x1234567890abcdef...
   export EAS_FROM_ACCOUNT=0x1234567890123456789012345678901234567890
   export EAS_RPC_URL=https://my-custom-rpc.com  # optional
   export EAS_CONTRACT_ADDRESS=0x1111...  # optional

   # Create EAS instance from environment
   eas = EAS.from_environment()
    """
    )

    print("3. Backward compatibility:")
    print(
        """
   # Old way still works
   from EAS.config import create_eas_instance

   eas = create_eas_instance(
       network_name='mainnet',  # or 'sepolia', 'goerli', etc.
       from_account='0x1234...',
       private_key='0x1234...'
   )
    """
    )
    print()


def demonstrate_migration_guide():
    """Show how to migrate from old to current multi-chain support."""
    print("=" * 70)
    print("🔄 MIGRATION GUIDE")
    print("=" * 70)

    print("BEFORE (limited chains):")
    print(
        """
   # Old way - limited to 4 hardcoded networks
   from EAS.config import create_eas_instance

   eas = create_eas_instance(
       network_name='mainnet',  # Only mainnet, sepolia, goerli, base-sepolia
       from_account=account,
       private_key=private_key
   )
    """
    )

    print("CURRENT APPROACH (comprehensive multi-chain support):")
    print(
        """
   # Current way - supports all EAS-deployed chains
   from EAS.core import EAS

   # Method 1: Direct chain specification
   eas = EAS.from_chain(
       chain_name='ethereum',  # or 'base', 'arbitrum', 'optimism', 'polygon', etc.
       private_key=private_key,
       from_account=account
   )

   # Method 2: Environment-based configuration
   eas = EAS.from_environment()  # Reads EAS_CHAIN, EAS_PRIVATE_KEY, etc.

   # Method 3: Custom overrides
   eas = EAS.from_chain(
       chain_name='base',
       private_key=private_key,
       from_account=account,
       rpc_url='https://my-base-rpc.com',  # Custom RPC
       contract_address='0x...'  # Custom contract if needed
   )
    """
    )

    print("BENEFITS of this approach:")
    print("✓ Support for 12+ chains (all major EAS deployments)")
    print("✓ Automatic contract address resolution")
    print("✓ Environment variable support")
    print("✓ Robust validation and error handling")
    print("✓ Full backward compatibility")
    print("✓ Easy chain switching for multi-chain applications")
    print()


def demonstrate_supported_chains():
    """Show all supported chains and their details."""
    print("=" * 70)
    print("🌐 SUPPORTED CHAINS REFERENCE")
    print("=" * 70)

    # Import config module
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "config",
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "src",
            "main",
            "EAS",
            "config.py",
        ),
    )
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)

    print("MAINNET CHAINS:")
    for chain in sorted(config.get_mainnet_chains()):
        chain_config = config.get_network_config(chain)
        print(f"  • {chain}")
        print(f"    Chain ID: {chain_config['chain_id']}")
        print(f"    Contract: {chain_config['contract_address']}")
        print(f"    Explorer: {chain_config['explorer_url']}")
        print()

    print("TESTNET CHAINS:")
    for chain in sorted(config.get_testnet_chains()):
        chain_config = config.get_network_config(chain)
        print(f"  • {chain}")
        print(f"    Chain ID: {chain_config['chain_id']}")
        print(f"    Contract: {chain_config['contract_address']}")
        print(f"    Explorer: {chain_config['explorer_url']}")
        print()


def main():
    """Run all demonstrations."""
    print("🚀 EAS PYTHON SDK - MULTI-CHAIN SUPPORT DEMONSTRATION")
    print("=" * 70)
    print("This script demonstrates the comprehensive multi-chain support")
    print("provided by the EAS Python SDK, including factory methods and")
    print("configuration management.")
    print()

    demonstrate_config_system()
    demonstrate_factory_methods()
    demonstrate_migration_guide()
    demonstrate_supported_chains()

    print("=" * 70)
    print("🎉 MULTI-CHAIN SUPPORT AVAILABLE!")
    print("=" * 70)
    print("The EAS Python SDK supports:")
    print("✅ 12+ blockchain networks (all major EAS deployments)")
    print("✅ Automatic contract address resolution")
    print("✅ Factory methods for easy instantiation")
    print("✅ Environment variable configuration")
    print("✅ Comprehensive validation and error handling")
    print("✅ Full backward compatibility")
    print("✅ Type hints and proper documentation")
    print()
    print("Ready for production use across multiple chains!")
    print("=" * 70)


if __name__ == "__main__":
    main()
