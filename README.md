# kotoba-lang/authorization

[![CI](https://github.com/kotoba-lang/authorization/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/authorization/actions/workflows/ci.yml)

Access-control decisions as pure data — roles→permissions lookup and wildcard
action matching, every namespace `.cljc`, zero third-party runtime deps.
Storage of who-has-which-role is an injected `IPolicyStore` host capability,
the same seam `kotoba-lang/godaddy-dns`'s `IDns` uses for DNS zone data.

This is the **"what can you do"** layer — a distinct concern from
`kotoba-lang/authentication` ("who are you"). The two compose: a `:subject`
passed to `authorized?`/`explain` here is typically an identity reference
produced by that layer (or by `kotoba-lang/identity`), but this repo has no
code dependency on either — it only needs a subject key and an
`IPolicyStore`.

## Scope: allow-only RBAC (v1)

There is no explicit-deny rule, no rule precedence, and no ABAC context
conditions (time of day, IP range, …). A subject is authorized iff at least
one of their roles carries a permission whose `:action`/`:resource` patterns
match the request. This is a deliberately small v1, not a policy-language
engine — if you need explicit deny or attribute conditions, this library
isn't it yet.

## Usage

```clojure
(require '[authorization.core :as authz])

(def store
  (authz/mock-policy-store
   {:admin #{"alice"} :viewer #{"bob"}}
   {:admin  [(authz/permission "*")]
    :viewer [(authz/permission "repo:read")]}))

(authz/authorized? store {:subject "bob" :action "repo:read"})
;; => true

(authz/authorized? store {:subject "bob" :action "repo:write"})
;; => false

(authz/explain store {:subject "bob" :action "repo:write"})
;; => {:allowed? false :matched-role nil :matched-permission nil}
```

`action-matches?` is the wildcard primitive underneath: colon-namespaced
strings, `*` matches the rest of the string (`"repo:*"` matches
`"repo:read"`/`"repo:write"` but not `"org:read"`; `"*"` matches everything;
a pattern with no `*` must match exactly, not just share a prefix).

## Test

```bash
clojure -M:test
```
