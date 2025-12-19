(ns altcha-clj.verify
  (:require
   [altcha-clj.core :refer [create-challenge hash-hex hmac-hex]]
   [altcha-clj.encoding :as enc]
   [clojure.string :as str]))

(defn- past?
  "Checks if the expiration time is not in the past relative to the reference time"
  [expire-time reference-time]
  (let [expiration (if (empty? expire-time)
                     0
                     (parse-long expire-time))]
    (< expiration (quot reference-time 1000))))

(defn assoc-if-some
  "Conditionally adds a key `k` to value `v` pairs 
  to map `m`. If no args are present or `v` is nil, returns `m`.
  If passed a variadic argument of arbitrary number of `kvs` 
  key-value pairs, adds each of them that is not nil to `m`"
  ([m] m)
  ([m k v]
   (if (some? v)
     (assoc m k v)
     m))
  ([m k v & kvs]
   (let [ret (assoc-if-some m k v)]
     (if kvs
       (recur ret (first kvs) (second kvs) (nnext kvs))
       ret))))

(defn check-solution
  "Verifies the solution received from the client, returning
  an explicit `true` or a falsy `nil`
  Params:
  - `payload`: the map of the following keys received from the client.
  Note that usually you'll get the solution encoded in base-64
    - `algorithm`
    - `challenge` - the solved challenge value
    - `number` - the random number generated previously
    - `salt`
    - `signature`
  - `hmac-key` - the HMAC key used for verification.
  - `check-expiration?` - whether to check if the challenge has not expired.
  Recommended to be kept as true

  Keys:
  - `max-number` - optional max-number override. If you're facing issues with
  false negatives, try adding your value to this function's args
  - `reference-time` - reference timestamp to compare as the timestamp 
  which must be greater than the challenge's `created-at` value
  - `throw-on-false?` - whether to throw an error if the result is false.
  The result will be an ex-message with `params`, `payload`, `not-expired?` and `expected-challenge`"
  [payload hmac-key ^Boolean check-expiration? & {:keys [max-number reference-time throw-on-false?]
                                                  :or {reference-time (System/currentTimeMillis)}}]
  (let [{:keys [algorithm challenge number salt signature]} payload
        {:keys [salt expires expire ttl] :as params} (enc/extract-params
                                                      (enc/decode-url-component (:salt challenge salt)))
        expected (create-challenge (assoc-if-some {:algorithm algorithm
                                                   :hmac-key hmac-key
                                                   :number number
                                                   :current-time reference-time
                                                   :salt salt}
                                                  :ttl ttl
                                                  :expires expires
                                                  :max-number max-number))
        base-result (and (= (:challenge expected) challenge)
                         (= (:signature expected) signature))
        ;; truth table: if checks disabled will return true regardless of result. nil if [true true]
        not-expired? (some not [check-expiration? (past? (or expires expire) reference-time)])
        result (and base-result not-expired?)]
    (when (and throw-on-false? (not result))
      (throw (ex-info "Challenge validation failed. "
                      {:payload payload
                       :params params
                       :not-expired? not-expired?
                       :reference-time reference-time
                       :expiration-time expires
                       :expected-challenge expected})))
    result))

(defn check-solution-base64
  "Verifies a base64 encoded solution. For parameters documenation, see `check-solution`
  NOTE: must pass number in the tail args map in testing"
  [b64-payload hmac-key ^Boolean check-expiration? & {:keys [max-number reference-time throw-on-false? number]}]
  (->
   b64-payload
   (enc/decode-base64)
   (enc/json->clj)
   (assoc-if-some :number number)
   (check-solution hmac-key check-expiration?
                   (assoc-if-some {}
                                  :max-number max-number :reference-time reference-time :throw-on-false? throw-on-false?))))

(defn signature-not-expired? [verification-data current]
  (or (nil? (:expires verification-data))
      (> (parse-long (:expires verification-data)) current)))

(defn verify-server-signature [{:keys [algorithm verification-data signature verified] :as payload}
                               hmac-key]
  (let [expected-signature (hmac-hex algorithm
                                     (hash-hex algorithm verification-data)
                                     hmac-key)
        extracted-params (enc/extract-params (str "x?" (enc/decode-url-component verification-data)))
        current-time (System/currentTimeMillis)]
    {:verified (and verified
                    (:verified extracted-params)
                    ;; we get :expired key from parsing verification-data
                    (signature-not-expired? extracted-params current-time)
                    (= signature expected-signature))
     :verification-data (update-in extracted-params [:verified] #(if (string? %)
                                                                   (true? (parse-boolean %))
                                                                   (true? %)))}))

(defn verify-server-signature-base64 [base64-payload hmac-key]
  (-> base64-payload
      (enc/decode-base64)
      (enc/json->clj)
      (verify-server-signature hmac-key)))

(defn verify-fields-hash
  "Verify the hashes of field values in the input map.
  Useful for scraper protection"
  [form-data fields fields-hash algorithm]
  (let [joined-data (str/join "\n" (map #(get form-data % "") fields))
        computed-hash (hash-hex algorithm (str/trim joined-data))]
    (= computed-hash fields-hash)))

