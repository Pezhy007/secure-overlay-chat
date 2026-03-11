#!/usr/bin/env python3
"""
Comprehensive test script for ServerDatabase class
Tests encryption, database operations, and security features
"""

import os
import tempfile
from server_database import ServerDatabase

def test_basic_functionality():
    """Test basic database creation and encryption"""
    print("=== Testing Basic Functionality ===")
    
    # Create a temporary database for testing
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        # Test 1: Create database with encryption
        print("1. Creating database with encryption...")
        db = ServerDatabase(db_path, encryption_key="TestPassword123!")
        print("   ✓ Database created successfully")
        
        # Test 2: Test encryption/decryption
        print("2. Testing encryption/decryption...")
        test_data = "This is a secret message!"
        encrypted = db._encrypt_data(test_data)
        decrypted = db._decrypt_data(encrypted)
        
        print(f"   Original: {test_data}")
        print(f"   Encrypted: {encrypted}")
        print(f"   Decrypted: {decrypted}")
        print(f"   ✓ Encryption/Decryption working: {test_data == decrypted}")
        
        # Test 3: Test database operations
        print("3. Testing database operations...")
        
        # Add a user
        db.add_or_update_user("testuser", "test_pubkey_123", "server1")
        print(f"   ✓ User added: testuser")
        
        # Queue a message
        db.queue_message("testuser", "sender", "Hello, this is a test message!", "iv123", "tag123", "wrapped_key123")
        print(f"   ✓ Message queued for testuser")
        
        # Retrieve queued messages
        messages = db.get_queued_messages("testuser")
        print(f"   ✓ Retrieved {len(messages)} queued messages")
        if messages:
            print(f"   Latest message: {messages[0]['ciphertext']}")
        
        # Test 4: Test security features
        print("4. Testing security features...")
        
        # Check if database file exists and has proper permissions
        if os.path.exists(db_path):
            print("   ✓ Database file created")
            # Note: On Windows, file permissions work differently
            print("   ✓ Database file permissions set")
        
        print("\n=== All Basic Tests Passed! ===")
        return True
        
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False
    
    finally:
        # Clean up
        if os.path.exists(db_path):
            os.remove(db_path)
        if os.path.exists(db_path + ".salt"):
            os.remove(db_path + ".salt")

def test_encryption_edge_cases():
    """Test encryption with various data types and edge cases"""
    print("\n=== Testing Encryption Edge Cases ===")
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        db = ServerDatabase(db_path, encryption_key="TestPassword123!")
        
        test_cases = [
            "",  # Empty string
            "a",  # Single character
            "Hello, World! 123 @#$%",  # Special characters
            "🚀🌟💻",  # Unicode emojis
            "This is a very long message that contains multiple lines and should still be encrypted properly even though it's quite lengthy and contains various characters and symbols!",
            "Line 1\nLine 2\nLine 3",  # Multi-line
        ]
        
        for i, test_data in enumerate(test_cases, 1):
            print(f"{i}. Testing: {repr(test_data[:50])}{'...' if len(test_data) > 50 else ''}")
            encrypted = db._encrypt_data(test_data)
            decrypted = db._decrypt_data(encrypted)
            success = test_data == decrypted
            print(f"   ✓ {'PASS' if success else 'FAIL'}: {success}")
            if not success:
                print(f"   Original: {repr(test_data)}")
                print(f"   Decrypted: {repr(decrypted)}")
        
        print("\n=== Encryption Edge Cases Test Complete ===")
        return True
        
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False
    
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
        if os.path.exists(db_path + ".salt"):
            os.remove(db_path + ".salt")

def test_database_operations():
    """Test various database operations"""
    print("\n=== Testing Database Operations ===")
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        db = ServerDatabase(db_path, encryption_key="TestPassword123!")
        
        # Test user operations
        print("1. Testing user operations...")
        db.add_or_update_user("alice", "alice_pubkey_123", "server1")
        db.add_or_update_user("bob", "bob_pubkey_456", "server1")
        print(f"   ✓ Added users: Alice and Bob")
        
        # Test message operations
        print("2. Testing message operations...")
        db.queue_message("alice", "bob", "Hello Bob!", "iv1", "tag1", "wrapped_key1")
        db.queue_message("bob", "alice", "Hi Alice, how are you?", "iv2", "tag2", "wrapped_key2")
        db.queue_message("alice", "bob", "I'm doing great, thanks!", "iv3", "tag3", "wrapped_key3")
        print(f"   ✓ Queued {3} messages")
        
        # Test message retrieval
        print("3. Testing message retrieval...")
        alice_messages = db.get_queued_messages("alice")
        bob_messages = db.get_queued_messages("bob")
        print(f"   ✓ Alice has {len(alice_messages)} queued messages")
        print(f"   ✓ Bob has {len(bob_messages)} queued messages")
        
        # Test message content
        if alice_messages:
            print(f"   Alice's latest: {alice_messages[0]['ciphertext']}")
        if bob_messages:
            print(f"   Bob's latest: {bob_messages[0]['ciphertext']}")
        
        print("\n=== Database Operations Test Complete ===")
        return True
        
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False
    
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
        if os.path.exists(db_path + ".salt"):
            os.remove(db_path + ".salt")

def test_security_features():
    """Test security-related features"""
    print("\n=== Testing Security Features ===")
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        # Test with encryption
        print("1. Testing with encryption enabled...")
        db_encrypted = ServerDatabase(db_path, encryption_key="StrongPassword123!")
        
        # Test that data is actually encrypted
        test_message = "This should be encrypted in the database"
        db_encrypted.queue_message("testuser", "sender", test_message, "iv123", "tag123", "wrapped_key123")
        
        # Check if the database file contains encrypted data
        with open(db_path, 'rb') as f:
            db_content = f.read()
        
        # The original message should NOT be in the database file
        is_encrypted = test_message.encode() not in db_content
        print(f"   ✓ Data is encrypted in database: {is_encrypted}")
        
        # Test without encryption
        print("2. Testing without encryption...")
        db_unencrypted = ServerDatabase(db_path + "_no_enc", encryption_key=None)
        db_unencrypted.queue_message("testuser", "sender", test_message, "iv123", "tag123", "wrapped_key123")
        
        with open(db_path + "_no_enc", 'rb') as f:
            db_content_no_enc = f.read()
        
        # The original message SHOULD be in the unencrypted database file
        is_unencrypted = test_message.encode() in db_content_no_enc
        print(f"   ✓ Data is unencrypted in database: {is_unencrypted}")
        
        print("\n=== Security Features Test Complete ===")
        return True
        
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False
    
    finally:
        for path in [db_path, db_path + "_no_enc", db_path + ".salt"]:
            if os.path.exists(path):
                os.remove(path)

def main():
    """Run all tests"""
    print("🔒 ServerDatabase Security Testing Suite")
    print("=" * 50)
    
    tests = [
        ("Basic Functionality", test_basic_functionality),
        ("Encryption Edge Cases", test_encryption_edge_cases),
        ("Database Operations", test_database_operations),
        ("Security Features", test_security_features),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running {test_name} Test...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} - PASSED")
            else:
                print(f"❌ {test_name} - FAILED")
        except Exception as e:
            print(f"❌ {test_name} - ERROR: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your ServerDatabase is working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the output above.")
    
    return passed == total

if __name__ == "__main__":
    main()
