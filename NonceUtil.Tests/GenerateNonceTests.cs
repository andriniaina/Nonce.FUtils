﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NonceUtil;

namespace NonceUtil.Tests
{
    [TestClass]
    public class GenerateNonceTests
    {
        [TestMethod]
        public void GenerateNonce_DefaultTimeout()
        {
            // Setup

            // Execution
            var nonce = NonceUtil.GenerateNonce("noncesecret", 180);

            // Assertion
            Assert.IsFalse(String.IsNullOrEmpty(nonce));
        }

        [TestMethod]
        public void GenerateNonce_SpecificTimeout()
        {
            // Setup

            // Execution
            var nonce = NonceUtil.GenerateNonce("noncesecret", 900); // Timeout of 15 minutes

            // Assertion
            Assert.IsFalse(String.IsNullOrEmpty(nonce));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateNonce_SpecificTimeout_GreaterThanZero_ThrowsException()
        {
            NonceUtil.GenerateNonce("noncesecret", 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateNonce_EmptySecret_ThrowsException()
        {
            NonceUtil.GenerateNonce(String.Empty, 180);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateNonce_SecretLessThanTenChars_ThrowsException()
        {
            NonceUtil.GenerateNonce("secret", 180); // Secret less than 10 chars
        }
    }
}
