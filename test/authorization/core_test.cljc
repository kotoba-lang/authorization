(ns authorization.core-test
  (:require [clojure.test :refer [deftest testing is]]
            [authorization.core :as authz]))

(deftest action-matches?-test
  (testing "exact match"
    (is (authz/action-matches? "repo:read" "repo:read"))
    (is (not (authz/action-matches? "repo:read" "repo:write")))
    (is (not (authz/action-matches? "repo:read" "repo")))
    (is (not (authz/action-matches? "repo:read" "repo:read:sub"))))
  (testing "namespaced wildcard"
    (is (authz/action-matches? "repo:*" "repo:read"))
    (is (authz/action-matches? "repo:*" "repo:write"))
    (is (not (authz/action-matches? "repo:*" "org:read"))))
  (testing "global wildcard"
    (is (authz/action-matches? "*" "repo:read"))
    (is (authz/action-matches? "*" "anything:at:all"))))

(def store
  (authz/mock-policy-store
   {:admin #{"alice"} :viewer #{"bob"}}
   {:admin [(authz/permission "*")]
    :viewer [(authz/permission "repo:read")]}))

(deftest authorized?-test
  (testing "admin allowed everything"
    (is (authz/authorized? store {:subject "alice" :action "repo:write"}))
    (is (authz/authorized? store {:subject "alice" :action "org:delete"})))
  (testing "viewer allowed only repo:read"
    (is (authz/authorized? store {:subject "bob" :action "repo:read"}))
    (is (not (authz/authorized? store {:subject "bob" :action "repo:write"}))))
  (testing "unknown subject has no roles, always denied"
    (is (not (authz/authorized? store {:subject "carol" :action "repo:read"})))))

(deftest explain-test
  (testing "allow explains the matched role/permission"
    (let [result (authz/explain store {:subject "bob" :action "repo:read"})]
      (is (:allowed? result))
      (is (= :viewer (:matched-role result)))
      (is (= (authz/permission "repo:read") (:matched-permission result)))))
  (testing "deny explains with nils"
    (is (= {:allowed? false :matched-role nil :matched-permission nil}
           (authz/explain store {:subject "bob" :action "repo:write"})))))
