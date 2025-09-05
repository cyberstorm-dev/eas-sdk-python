#!/usr/bin/env python3
"""
EAS SDK Quick Start Example

This example demonstrates the most common use cases for the EAS SDK,
designed to get developers up and running quickly.

Prerequisites:
1. Set up environment variables in .env file:
   EAS_CHAIN=sepolia  # or any supported chain
   EAS_PRIVATE_KEY=0x...your_private_key
   EAS_FROM_ACCOUNT=0x...your_account_address

2. Install dependencies:
   pip install eas-sdk

3. Run the example:
   python examples/quick_start.py
"""

import os
import sys
from pathlib import Path

# Add src to path for development
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src" / "main"))

from EAS import EAS


def main():
    """Quick start example showing common EAS operations."""
    
    print("🚀 EAS SDK Quick Start Example")
    print("=" * 40)
    
    # Example 1: Initialize EAS from environment
    print("\n1. Initialize EAS from environment variables")
    try:
        eas = EAS.from_environment()
        print("   ✅ EAS instance created successfully")
    except Exception as e:
        print(f"   ❌ Failed to create EAS instance: {e}")
        print("\n💡 Make sure you have set up your .env file with:")
        print("   EAS_CHAIN=sepolia")
        print("   EAS_PRIVATE_KEY=0x...")
        print("   EAS_FROM_ACCOUNT=0x...")
        return

    # Example 2: List supported chains
    print("\n2. List available chains")
    from EAS.config import list_supported_chains, get_mainnet_chains, get_testnet_chains
    
    all_chains = list_supported_chains()
    mainnet_chains = get_mainnet_chains()
    testnet_chains = get_testnet_chains()
    
    print(f"   📊 Total supported chains: {len(all_chains)}")
    print(f"   🏦 Mainnet chains: {', '.join(mainnet_chains[:3])}...")
    print(f"   🧪 Testnet chains: {', '.join(testnet_chains[:3])}...")

    # Example 3: Register a simple schema (testnet only)
    print("\n3. Register a sample schema")
    try:
        # Simple identity schema
        schema = "string name,uint256 age,bool verified"
        result = eas.register_schema(schema, network_name="sepolia")  # Use testnet
        
        if result.success:
            print(f"   ✅ Schema registered with UID: {result.data.get('schema_uid', 'N/A')}")
            schema_uid = result.data.get('schema_uid')
        else:
            print(f"   ❌ Schema registration failed: {result.error}")
            schema_uid = None
            
    except Exception as e:
        print(f"   ⚠️  Schema registration skipped: {e}")
        schema_uid = None

    # Example 4: Create an attestation (using known schema)
    print("\n4. Create a sample attestation")
    try:
        # Use a known schema or the one we just created
        if not schema_uid:
            # Fallback to a common test schema (adjust as needed)
            schema_uid = "0x83c23d3c24c90bc5d1b8b44a7c2cc50e4d9efca2e80d78a3ce5f8e4d10e5d4e5"
        
        # Note: In a real application, you'd encode data properly
        # This is just for demonstration
        print(f"   📝 Using schema UID: {schema_uid}")
        print("   ⚠️  Attestation creation requires proper data encoding")
        print("   📚 See full_example.py for complete attestation workflow")
        
    except Exception as e:
        print(f"   ⚠️  Attestation example skipped: {e}")

    # Example 5: Show CLI usage
    print("\n5. CLI Tools Available")
    print("   🔍 Query schemas: eas-tools show-schema <schema_uid>")
    print("   📋 Query attestations: eas-tools show-attestation <attestation_uid>")
    print("   🔧 Generate code: eas-tools generate-schema <schema_uid>")

    print("\n✨ Quick start complete!")
    print("\n📖 Next steps:")
    print("   • Check out examples/full_example.py for complete workflows")
    print("   • Read examples/multi_chain_examples.py for multi-chain usage")
    print("   • Visit the documentation for detailed API reference")


if __name__ == "__main__":
    main()