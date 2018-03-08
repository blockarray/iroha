/**
 * Copyright Soramitsu Co., Ltd. 2018 All Rights Reserved.
 * http://soramitsu.co.jp
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "backend/protobuf/from_old_model.hpp"
#include "crypto_provider/impl/crypto_provider_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "model/generators/query_generator.hpp"
#include "model/generators/transaction_generator.hpp"
#include "model/sha3_hash.hpp"

namespace iroha {
  class CryptoProviderTest : public ::testing::Test {
   public:
    CryptoProviderTest() : keypair(create_keypair()), provider(keypair) {
      wrong_key.fill(0x1);
    }

    keypair_t keypair;
    CryptoProviderImpl provider;
    pubkey_t wrong_key;
  };

  /**
   * @given properly signed block
   * @when verify block
   * @then block is verified
   */
  TEST_F(CryptoProviderTest, SignAndVerifyBlock) {
    // make old model block
    model::Block old_block;
    old_block.height = 2;
    old_block.created_ts = 12345;
    old_block.hash = hash(old_block);
    provider.sign(old_block);

    // verify old block
    ASSERT_TRUE(provider.verify(old_block));

    // verify shared model block
    auto block = shared_model::proto::from_old(old_block);
    ASSERT_TRUE(provider.verify(block));
  }

  /**
   * @given block with inctorrect sign
   * @when verify block
   * @then block is not verified
   */
  TEST_F(CryptoProviderTest, SignAndVerifyBlockWithWrongKey) {
    // make old model block
    model::Block old_block;
    old_block.height = 2;
    old_block.created_ts = 12345;
    old_block.hash = hash(old_block);

    // sign with wrong key
    auto signature = iroha::sign(
        iroha::hash(old_block).to_string(), keypair.pubkey, keypair.privkey);
    old_block.sigs.emplace_back(signature, wrong_key);

    ASSERT_FALSE(provider.verify(old_block));

    auto block = shared_model::proto::from_old(old_block);
    ASSERT_FALSE(provider.verify(block));
  }

  /**
   * @given properly signed query
   * @when verify query
   * @then query is verified
   */
  TEST_F(CryptoProviderTest, SignAndVerifyQuery) {
    auto old_query = model::generators::QueryGenerator().generateGetAccount(
        0, "test", 0, "test");

    provider.sign(*old_query);
    ASSERT_TRUE(provider.verify(*old_query));

//    auto query = shared_model::proto::from_old(*(std::static_pointer_cast<iroha::model::Query>(old_query)));
    auto query = shared_model::proto::from_old(*old_query);

    ASSERT_TRUE(provider.verify(query));

    // modify account id, verification should fail
    old_query->account_id = "kappa";
    ASSERT_FALSE(provider.verify(*old_query));

//    auto block2 = shared_model::proto::from_old(*(std::static_pointer_cast<iroha::model::Query>(old_query)));
//    ASSERT_FALSE(provider.verify(block2));
  }

  TEST_F(CryptoProviderTest, SameQueryHashAfterSign) {
    auto query = model::generators::QueryGenerator().generateGetAccount(
        0, "test", 0, "test");

    auto hash = iroha::hash(*query);
    provider.sign(*query);

    auto hash_signed = iroha::hash(*query);
    ASSERT_EQ(hash_signed, hash);
  }

  TEST_F(CryptoProviderTest, SignAndVerifyTransaction) {
    auto model_tx =
        model::generators::TransactionGenerator().generateTransaction(
            "test", 0, {});

    provider.sign(model_tx);
    ASSERT_TRUE(provider.verify(model_tx));

    // now modify transaction's meta, so verify should fail
    model_tx.creator_account_id = "test1";
    ASSERT_FALSE(provider.verify(model_tx));
  }
}  // namespace iroha
