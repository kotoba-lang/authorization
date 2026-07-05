(ns authorization.core
  "Access-control decisions as pure data — roles→permissions lookup and
  wildcard action matching. Storage of who-has-which-role is an injected
  host capability (`IPolicyStore`), the same seam `godaddy-dns`'s `IDns`
  uses for its zone data — `mock-policy-store` here is the deterministic
  in-memory analogue of `mock-dns`, so tests and demos run with no
  external store.

  This is **allow-only** RBAC: there is no explicit-deny rule, no
  precedence between rules, and no ABAC context conditions (time of day,
  IP range, …). A subject is authorized iff at least one of their roles
  carries a permission whose `:action`/`:resource` patterns match the
  request. That is a deliberately small v1, not a policy-language engine."
  (:require [clojure.string :as str]))

(defn action-matches?
  "Wildcard matcher over colon-namespaced strings. Splits `pattern` and
  `action` on `:` and compares segment-by-segment; a `*` segment in
  `pattern` matches the rest of `action` regardless of how many segments
  remain (including none). Segments before the first `*` must match
  exactly, and a pattern with no `*` must match `action` exactly
  (matching lengths, not just a shared prefix)."
  [pattern action]
  (let [p (str/split pattern #":")
        a (str/split action #":")
        plen (count p)
        alen (count a)]
    (loop [i 0]
      (cond
        (and (< i plen) (= "*" (nth p i))) true
        (>= i plen) (= i alen)
        (>= i alen) false
        (= (nth p i) (nth a i)) (recur (inc i))
        :else false))))

(defn permission
  "One permission map: `{:action action :resource resource-pattern}`.
  `resource-pattern` defaults to `\"*\"` (any resource)."
  [action & [resource-pattern]]
  {:action action :resource (or resource-pattern "*")})

(defprotocol IPolicyStore
  "Role/permission host capability."
  (-roles-for [this subject]
    "Returns a set of role keywords held by `subject`.")
  (-permissions-for [this role]
    "Returns a seq of permission maps (see `permission`) granted to `role`."))

(deftype MockPolicyStore [subject->roles role->permissions]
  IPolicyStore
  (-roles-for [_ subject]
    (get subject->roles subject #{}))
  (-permissions-for [_ role]
    (get role->permissions role [])))

(defn mock-policy-store
  "An in-memory `IPolicyStore`. `role->subjects` is `{role #{subject …}}`
  (inverted internally into a subject→roles lookup); `role->permissions`
  is `{role [permission-map …]}`. Deterministic, no external store.

    (mock-policy-store {:admin #{\"alice\"} :viewer #{\"bob\"}}
                        {:admin [(permission \"*\")]
                         :viewer [(permission \"repo:read\")]})"
  [role->subjects role->permissions]
  (let [subject->roles (reduce-kv
                         (fn [acc role subjects]
                           (reduce (fn [acc subject]
                                     (update acc subject (fn [rs] (conj (or rs #{}) role))))
                                   acc subjects))
                         {} role->subjects)]
    (->MockPolicyStore subject->roles role->permissions)))

(defn- matching-permission
  "First permission (across all of `subject`'s roles) whose `:action` and
  `:resource` patterns match the request, as `[role permission]`, or nil."
  [policy-store {:keys [subject action resource]}]
  (let [resource (or resource "*")]
    (->> (-roles-for policy-store subject)
         (some (fn [role]
                 (->> (-permissions-for policy-store role)
                      (some (fn [perm]
                              (when (and (action-matches? (:action perm) action)
                                         (action-matches? (:resource perm) resource))
                                [role perm])))))))))

(defn authorized?
  "true iff any role held by `(:subject request)` carries a permission
  whose `:action`/`:resource` patterns match `(:action request)` /
  `(:resource request)` (resource defaults to `\"*\"`)."
  [policy-store request]
  (boolean (matching-permission policy-store request)))

(defn explain
  "Same decision as `authorized?`, but returns
  `{:allowed? bool :matched-role role-or-nil :matched-permission perm-or-nil}`
  — useful for audit logging or debugging a deny."
  [policy-store request]
  (if-let [[role perm] (matching-permission policy-store request)]
    {:allowed? true :matched-role role :matched-permission perm}
    {:allowed? false :matched-role nil :matched-permission nil}))
