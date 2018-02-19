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

#ifndef IROHA_PROTO_DOMAIN_BUILDER_HPP
#define IROHA_PROTO_DOMAIN_BUILDER_HPP

#include "backend/protobuf/common_objects/domain.hpp"
#include "responses.pb.h"
#include "utils/polymorphic_wrapper.hpp"

namespace shared_model {
  namespace proto {
    class DomainBuilder {
     public:
      shared_model::proto::Domain build() {
        return shared_model::proto::Domain(std::move(domain_));
      }

      DomainBuilder &defaultRole(
          const interface::types::RoleIdType &default_role) {
        domain_.set_default_role(default_role);
        return *this;
      }

      DomainBuilder &domainId(const interface::types::DomainIdType &domain_id) {
        domain_.set_domain_id(domain_id);
        return *this;
      }

     private:
      iroha::protocol::Domain domain_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_DOMAIN_BUILDER_HPP