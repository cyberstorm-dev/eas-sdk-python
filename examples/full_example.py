#!/usr/bin/env python3
"""
EAS SDK Complete Example

This example demonstrates a complete workflow using the EAS SDK,
including schema creation, attestations, revocations, and queries.

This example shows best practices and proper error handling.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

# Add src to path for development
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src" / "main"))

from EAS import EAS
from EAS.config import get_network_config
from eth_abi import encode


class EASWorkflowExample:
    """Complete EAS workflow example."""

    def __init__(self):
        """Initialize the example."""
        self.eas = None
        self.schema_uid = None
        self.attestation_uid = None

    def setup_eas(self) -> bool:
        """Set up EAS instance."""
        print("🔧 Setting up EAS instance...")
        
        try:
            # Method 1: From environment (recommended)
            self.eas = EAS.from_environment()
            print("   ✅ EAS created from environment variables")
            return True
            
        except Exception as env_error:
            print(f"   ⚠️  Environment setup failed: {env_error}")
            
            # Method 2: Direct configuration (fallback)
            try:
                print("   🔄 Trying direct configuration...")
                
                # Get configuration for testnet
                config = get_network_config("sepolia")
                
                # You would need to provide these values
                private_key = os.getenv("PRIVATE_KEY")
                from_account = os.getenv("FROM_ACCOUNT") 
                
                if not private_key or not from_account:
                    print("   ❌ PRIVATE_KEY and FROM_ACCOUNT environment variables required")
                    return False
                
                self.eas = EAS.from_chain(
                    chain_name="sepolia",
                    private_key=private_key,
                    from_account=from_account
                )
                print("   ✅ EAS created with direct configuration")
                return True
                
            except Exception as direct_error:
                print(f"   ❌ Direct configuration failed: {direct_error}")
                return False

    def register_schema(self) -> bool:
        """Register a schema for our attestations."""
        print("\n📝 Registering schema...")
        
        try:
            # Define a useful schema for user profiles
            schema = "string name,string email,uint256 reputation,bool verified,bytes32 profileHash"
            
            print(f"   Schema: {schema}")
            
            result = self.eas.register_schema(
                schema=schema,
                network_name="sepolia",  # Use testnet for safety
                revocable=True  # Allow revocations
            )
            
            if result.success:
                # Extract schema UID from transaction logs or response
                schema_uid = result.data.get('schema_uid')
                if schema_uid:
                    self.schema_uid = schema_uid
                    print(f"   ✅ Schema registered: {schema_uid}")
                    print(f"   🔗 Transaction: {result.tx_hash}")
                    return True
                else:
                    print("   ⚠️  Schema registered but UID not found in response")
                    return False
            else:
                print(f"   ❌ Schema registration failed: {result.error}")
                return False
                
        except Exception as e:
            print(f"   ❌ Schema registration error: {e}")
            return False

    def create_attestation(self) -> bool:
        """Create an attestation using our schema."""
        print("\n🏅 Creating attestation...")
        
        if not self.schema_uid:
            print("   ❌ No schema UID available")
            return False
        
        try:
            # Prepare attestation data
            recipient = "0x742d35Cc6634C0532925a3b8D16c30B9b2C4e40B"  # Example recipient
            
            # Encode data according to our schema
            # Schema: "string name,string email,uint256 reputation,bool verified,bytes32 profileHash"
            attestation_data = encode(
                ["string", "string", "uint256", "bool", "bytes32"],
                [
                    "Alice Johnson",
                    "alice@example.com", 
                    1000,  # reputation score
                    True,  # verified
                    bytes.fromhex("a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890")
                ]
            )
            
            print(f"   👤 Recipient: {recipient}")
            print(f"   📦 Data length: {len(attestation_data)} bytes")
            
            result = self.eas.create_attestation(
                schema_uid=self.schema_uid,
                recipient=recipient,
                encoded_data=attestation_data,
                expiration=0,  # No expiration
                revocable=True,
                value=0  # No ETH value
            )
            
            if result.success:
                # Extract attestation UID from transaction logs
                attestation_uid = result.data.get('attestation_uid')
                if attestation_uid:
                    self.attestation_uid = attestation_uid
                    print(f"   ✅ Attestation created: {attestation_uid}")
                    print(f"   🔗 Transaction: {result.tx_hash}")
                    return True
                else:
                    print("   ⚠️  Attestation created but UID not found in response")
                    print(f"   🔗 Transaction: {result.tx_hash}")
                    return True  # Still a success
            else:
                print(f"   ❌ Attestation creation failed: {result.error}")
                return False
                
        except Exception as e:
            print(f"   ❌ Attestation creation error: {e}")
            return False

    def query_attestation(self) -> bool:
        """Query the attestation we just created."""
        print("\n🔍 Querying attestation...")
        
        if not self.attestation_uid:
            print("   ⚠️  No attestation UID to query")
            return False
            
        try:
            attestation = self.eas.get_attestation(self.attestation_uid)
            
            if attestation:
                print(f"   ✅ Attestation found:")
                print(f"      Schema: {attestation[1]}")  # schema UID
                print(f"      Recipient: {attestation[2]}")  # recipient
                print(f"      Attester: {attestation[3]}")  # attester
                print(f"      Time: {attestation[4]}")  # time
                print(f"      Expiration: {attestation[5]}")  # expiration
                print(f"      Revocable: {attestation[6]}")  # revocable
                print(f"      Ref UID: {attestation[7]}")  # ref UID
                print(f"      Data length: {len(attestation[8])} bytes")  # data
                print(f"      Revoked: {attestation[9]}")  # revoked
                print(f"      Revocation time: {attestation[10]}")  # revocation time
                return True
            else:
                print("   ❌ Attestation not found")
                return False
                
        except Exception as e:
            print(f"   ❌ Query error: {e}")
            return False

    def demonstrate_offchain_attestation(self) -> bool:
        """Demonstrate off-chain attestation."""
        print("\n🌐 Creating off-chain attestation...")
        
        try:
            # Create off-chain attestation message
            message = {
                "version": 1,
                "schema": self.schema_uid or "0x" + "0" * 64,
                "recipient": "0x742d35Cc6634C0532925a3b8D16c30B9b2C4e40B",
                "time": int(time.time()),
                "expirationTime": 0,
                "revocable": True,
                "refUID": None,
                "data": json.dumps({
                    "name": "Bob Smith",
                    "email": "bob@example.com",
                    "reputation": 750,
                    "verified": False,
                    "note": "Off-chain attestation example"
                }).encode()
            }
            
            offchain_attestation = self.eas.attest_offchain(message)
            
            print(f"   ✅ Off-chain attestation created")
            print(f"   🆔 UID: {offchain_attestation['message']['uid']}")
            print(f"   ✍️  Signature: {offchain_attestation['signature']['r'][:10]}...")
            
            return True
            
        except Exception as e:
            print(f"   ❌ Off-chain attestation error: {e}")
            return False

    def demonstrate_revocation(self) -> bool:
        """Demonstrate attestation revocation."""
        print("\n❌ Revoking attestation...")
        
        if not self.attestation_uid:
            print("   ⚠️  No attestation UID to revoke")
            return False
            
        try:
            result = self.eas.revoke_attestation(self.attestation_uid)
            
            if result.success:
                print(f"   ✅ Attestation revoked")
                print(f"   🔗 Transaction: {result.tx_hash}")
                return True
            else:
                print(f"   ❌ Revocation failed: {result.error}")
                return False
                
        except Exception as e:
            print(f"   ❌ Revocation error: {e}")
            return False

    def run_complete_workflow(self):
        """Run the complete EAS workflow."""
        print("🚀 EAS SDK Complete Workflow Example")
        print("=" * 50)
        
        # Step 1: Setup
        if not self.setup_eas():
            print("\n❌ Setup failed. Cannot continue.")
            return
        
        # Step 2: Register schema
        if not self.register_schema():
            print("\n⚠️  Using fallback schema for remaining examples...")
            # Use a known schema for testnets
            self.schema_uid = "0x83c23d3c24c90bc5d1b8b44a7c2cc50e4d9efca2e80d78a3ce5f8e4d10e5d4e5"
        
        # Step 3: Create attestation
        if self.create_attestation():
            # Step 4: Query attestation
            self.query_attestation()
            
            # Step 5: Demonstrate revocation
            print("\n⏱️  Waiting 5 seconds before revocation...")
            time.sleep(5)
            self.demonstrate_revocation()
        
        # Step 6: Off-chain attestation (always works)
        self.demonstrate_offchain_attestation()
        
        print("\n✨ Complete workflow finished!")
        print("\n📚 What you've learned:")
        print("   • How to initialize EAS from environment variables")
        print("   • How to register schemas on-chain")
        print("   • How to create and query attestations")
        print("   • How to create off-chain attestations")
        print("   • How to revoke attestations")
        
        print("\n🛠️  Development Tips:")
        print("   • Use testnet (sepolia) for development")
        print("   • Check transaction status before proceeding")
        print("   • Handle errors gracefully in production")
        print("   • Use off-chain attestations for privacy/cost savings")


def main():
    """Run the complete workflow example."""
    example = EASWorkflowExample()
    example.run_complete_workflow()


if __name__ == "__main__":
    main()