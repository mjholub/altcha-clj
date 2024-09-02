(ns altcha-clj.verify 
  (:require
   [altcha-clj.core :refer [create-challenge hash-hex hmac-hex]]
   [altcha-clj.encoding :as encoding]
   [altcha-clj.polyfill :refer [now parse-int]]
   [clojure.string :as str]))

(defn- is-not-past?
  "Checks if the expiration time is not in the past relative to the reference time"
  [expire-time reference-time]
(let [expiration (if (empty? expire-time) 
                     0
                     (parse-int expire-time))]
    (> expiration (quot reference-time 1000))))

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
  (
   [m k v & kvs]
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
  The result will be an ex-message with `params`, `payload`, `not-expired?` and `expected-challenge`
  "
[payload hmac-key check-expiration? & {:keys [max-number reference-time throw-on-false?]}]
(let [{:keys [algorithm challenge number salt signature]} payload
      params (encoding/extract-params 
               (encoding/decode-url-component (get challenge :salt salt)))
      expire-time (:expires params)
      expected-challenge (create-challenge (assoc-if-some {:algorithm algorithm
                                                  :hmac-key hmac-key
                                                  :number number
                                                  :current-time reference-time
                                                  :salt salt}
                                                  :ttl (:ttl params)
                                                  :expires (:expires params)
                                                  :max-number max-number
                                                  )) 
        base-result (and (= (:challenge expected-challenge) (or (:challenge challenge) challenge))
             (= (:signature expected-challenge) signature))
        not-expired? (if check-expiration? (is-not-past? expire-time reference-time) true)
        result (and base-result not-expired?)]
  (when (and throw-on-false? (not result))
    (throw (ex-info "Challenge validation failed. "
           {:payload payload
            :params params
            :not-expired? not-expired?
            :expected-challenge expected-challenge
            })
           )
    )
  result
))
  


(defn check-solution-base64 
  "Verifies a base64 encoded solution. For parameters documenation, see `check-solution`"
  [b64-payload hmac-key check-expiration? & {:keys [max-number reference-time throw-on-false?]}]
  (->
    b64-payload
    (encoding/decode-base64)
    (encoding/json->clj)
    (check-solution hmac-key check-expiration? 
                    :max-number max-number
                    :reference-time reference-time
                    :throw-on-false throw-on-false?
                    )  
  ))

(defn signature-not-expired? [verification-data current]
  (or (nil? (:expires verification-data))
                        (> (parse-int (:expires verification-data)) current))
  )

(defn verify-server-signature [{:keys [algorithm verification-data signature verified] :as payload}
                               hmac-key]
  (let [expected-signature (hmac-hex algorithm 
                                     (hash-hex algorithm verification-data) 
                                     hmac-key)
        extracted-params (encoding/extract-params verification-data)
        current-time (now)
        ]
    {:verified (and verified
                    (:verified extracted-params)
                    ;; we get :expired key from parsing verification-data
                    (signature-not-expired? extracted-params current-time) 
                    (= signature expected-signature))
     :verification-data (update-in extracted-params [:verified] #(parse-boolean %))
     }
    )
  )

(defn verify-server-signature-base64 [base64-payload hmac-key]
  (-> base64-payload
      (encoding/decode-base64)
      (encoding/json->clj)
      (verify-server-signature hmac-key)
      ) 
  )

(defn verify-fields-hash 
  "Verify the hashes of field values in the input map.
  Useful for scraper protection"
  [form-data fields fields-hash algorithm]
  (let [joined-data (str/join "\n" (map #(get form-data % "") fields))
        computed-hash (hash-hex algorithm (str/trim joined-data))]
    (= computed-hash fields-hash)))
  
